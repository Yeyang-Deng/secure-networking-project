# node.py
import asyncio, json, os, base64, uuid, time, sys, signal, hashlib
from collections import deque
from typing import Dict, Any, Optional, Set, Tuple, Union

import websockets
from websockets.server import WebSocketServerProtocol
from websockets.client import WebSocketClientProtocol

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ------------------------------
# Utilities: time, id, b64
# ------------------------------
def now_ms() -> int:
    return int(time.time() * 1000)

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def new_msg_id() -> str:
    return str(uuid.uuid4())

# ---- immutable fields for signing (do NOT include ttl/route) ----
SIGNED_FIELDS = ("v", "type", "id", "from", "to", "ts", "seq", "body")

def signed_bytes(msg: Dict[str, Any]) -> bytes:
    base = {k: msg.get(k) for k in SIGNED_FIELDS}
    return json.dumps(base, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

# at top-level (near other helpers)
FORWARD_VIA_FIELD = "_via"

# ------------------------------
# RSA identity & helpers
# ------------------------------
def ensure_keys(keydir: str) -> Tuple[rsa.RSAPrivateKey, bytes]:
    os.makedirs(keydir, exist_ok=True)
    pem_priv = os.path.join(keydir, "node_private.pem")
    if os.path.exists(pem_priv):
        with open(pem_priv, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
    else:
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(pem_priv, "wb") as f:
            f.write(
                priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
    pub = priv.public_key()
    pub_der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fp = hashlib.sha256(pub_der).hexdigest()[:16]  # short fingerprint
    return priv, fp.encode("ascii")

def pubkey_pem(priv: rsa.RSAPrivateKey) -> str:
    pub = priv.public_key()
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

def rsa_oaep_encrypt(pubkey_pem_str: str, data: bytes) -> bytes:
    pub = serialization.load_pem_public_key(pubkey_pem_str.encode("utf-8"))
    return pub.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )

def rsa_oaep_decrypt(priv: rsa.RSAPrivateKey, ct: bytes) -> bytes:
    return priv.decrypt(
        ct,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    )

def rsa_pss_sign(priv: rsa.RSAPrivateKey, data: bytes) -> bytes:
    return priv.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )

def rsa_pss_verify(pub_pem: str, sig: bytes, data: bytes) -> bool:
    try:
        pub = serialization.load_pem_public_key(pub_pem.encode("utf-8"))
        pub.verify(
            sig,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

# ------------------------------
# AES-GCM helpers
# ------------------------------
def aes_encrypt(aes_key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    aes = AESGCM(aes_key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ct

def aes_decrypt(aes_key: bytes, nonce: bytes, ct: bytes) -> bytes:
    aes = AESGCM(aes_key)
    return aes.decrypt(nonce, ct, associated_data=None)

# ------------------------------
# Message building
# ------------------------------
def envelope(v: str, typ: str, from_id: str, to: str, ttl: int, seq: int, body: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "v": v, "type": typ, "id": new_msg_id(), "from": from_id, "to": to,
        "ts": now_ms(), "ttl": ttl, "seq": seq, "route": [], "body": body, "sig": ""
    }

# ------------------------------
# Node
# ------------------------------
class Node:
    def __init__(self, host: str, port: int, peers: Set[str], keydir: str = "./keys"):
        self.host, self.port = host, port
        self.priv, self.node_id = ensure_keys(keydir)
        self.node_id = self.node_id.decode("ascii")
        self.pub_pem = pubkey_pem(self.priv)

        self.neighbour_urls: Set[str] = set(peers)
        self.ws_set: Set[Union[WebSocketServerProtocol, WebSocketClientProtocol]] = set()

        # sessions: peer_id -> {"tx": bytes, "rx": bytes, "seq": int, "pub": str}
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.seen_ids: deque[str] = deque(maxlen=5000)
        self.seen_set: Set[str] = set()

        # membership view: peer_id -> {"addr": "...", "last_seen": int, "pub": str}
        self.view: Dict[str, Dict[str, Any]] = {}

        # per-run counters
        self.seq_out = 0

        # ---- Backdoor hooks (Week 9 only; keep disabled for clean build) ----
        self.enable_dbg_bypass = False         # B1: signature bypass
        self.enable_nonce_reuse_once = False   # B2: nonce reuse
        self.bypass_peer: Optional[str] = None  # peer_id for which signature checks are skipped

        print(f"[BOOT] Node {self.node_id} listening {host}:{port} | peers: {list(peers)}")

    # -------------- Net loops --------------
    async def start(self):
        # start long-running tasks
        server_t = asyncio.create_task(self._server())
        await asyncio.sleep(0.2)
        for url in self.neighbour_urls:
            asyncio.create_task(self._dial(url))
        asyncio.create_task(self._heartbeat_loop())
        asyncio.create_task(self._stdin_loop())

        # keep the main coroutine alive
        try:
            await asyncio.Event().wait()  # sleep forever until cancelled (Ctrl+C)
        except asyncio.CancelledError:
            pass

    async def _server(self):
        # Compatible with websockets 11 (ws, path) and 12+ (ws)
        async def handler(ws, path=None):
            await self._on_open(ws, is_outgoing=False)
            try:
                async for raw in ws:
                    await self._on_message(ws, raw)
            finally:
                self.ws_set.discard(ws)

        # also be compatible with import paths
        try:
            from websockets.server import serve as ws_serve  # websockets 12+
        except ImportError:
            from websockets import serve as ws_serve  # websockets 11

        self.server = await ws_serve(handler, self.host, self.port)
        await self.server.wait_closed()

    async def _dial(self, url: str):
        while True:
            ws = None
            try:
                ws = await websockets.connect(url)
                self.ws_set.add(ws)
                await self._on_open(ws, is_outgoing=True)
                async for raw in ws:
                    await self._on_message(ws, raw)
            except asyncio.CancelledError:
                # proper shutdown
                raise
            except Exception:
                await asyncio.sleep(2.0)
            finally:
                if ws in self.ws_set:
                    self.ws_set.discard(ws)
                if ws is not None:
                    try:
                        await ws.close()
                    except Exception:
                        pass

    # -------------- Handshake --------------
    async def _on_open(self, ws, is_outgoing: bool):
        # Send HELLO immediately
        msg = envelope("0.1", "HELLO", self.node_id, "*", 6, self.seq_inc(), {
            "pubkey": self.pub_pem,
            "ciphers": ["RSA-OAEP", "RSA-PSS", "AES-256-GCM"],
            "addr": f"ws://{self.host}:{self.port}"
        })
        await self.send_raw(ws, msg)

    # -------------- Send helpers --------------
    def seq_inc(self) -> int:
        self.seq_out += 1
        return self.seq_out

    async def send_raw(self, ws, msg: Dict[str, Any]):
        # Only originator signs; forwarders must not touch the signature
        if msg["type"] != "HELLO":
            if msg.get("from") == self.node_id:
                msg["sig"] = b64e(rsa_pss_sign(self.priv, signed_bytes(msg)))
            # else: forwarding path, keep existing msg["sig"] as-is
        await ws.send(json.dumps(msg, ensure_ascii=False))

    async def flood(self, src_ws, msg: Dict[str, Any]):
        # forward to all sockets except the one we received from
        for w in list(self.ws_set):
            if w is src_ws:
                continue
            m = dict(msg)
            m[FORWARD_VIA_FIELD] = self.node_id  # mark who forwarded
            await self.send_raw(w, m)

    # -------------- Message processing --------------
    async def _on_message(self, ws, raw: str):
        try:
            msg = json.loads(raw)
        except Exception:
            return
        if msg.get("from") == self.node_id:
            return
        mid = msg.get("id")
        if not mid or self._seen(mid):
            return

        if msg["type"] != "HELLO":
            if msg.get("from") == self.node_id:
                return
            if not self._verify_message_signature(msg):
                print("[DROP] bad signature")
                return

        ttl = int(msg.get("ttl", 0))
        if ttl <= 0:
            return
        msg["ttl"] = ttl - 1
        msg["route"] = list(msg.get("route", [])) + [self.node_id]

        self._touch_view(msg)

        # Deliver?
        deliver = (msg.get("to") in (self.node_id, "*"))
        if deliver:
            await self._deliver(msg, ws)

        if msg["ttl"] > 0:
            await self.flood(ws, msg)

    def _verify_message_signature(self, msg: Dict[str, Any]) -> bool:
        """
        Verify RSA-PSS signature for the message.
        If enable_dbg_bypass is True and bypass_peer equals the message 'from',
        skip verification (backdoor).
        """
        from_id = msg.get("from")

        # B1: backdoor - skip signature verification for the configured peer
        if self.enable_dbg_bypass and self.bypass_peer and self.bypass_peer == from_id:
            print(f"[BACKDOOR] Skipping signature check for {from_id}")
            return True

        if from_id == self.node_id:
            from_pub = self.pub_pem
        else:
            from_pub = self.view.get(from_id, {}).get("pub")

        if not from_pub:
            from_pub = msg.get("body", {}).get("pubkey")
            if not from_pub:
                return False

        sig_b64 = msg.get("sig")
        if not sig_b64:
            return False

        return rsa_pss_verify(from_pub, b64d(sig_b64), signed_bytes(msg))

    def _touch_view(self, msg: Dict[str, Any]):
        frm = msg.get("from")
        if not frm:
            return
        entry = self.view.get(frm) or {}
        if msg["type"] == "HELLO":
            entry["pub"] = msg["body"].get("pubkey")
            entry["addr"] = msg["body"].get("addr")
        entry["last_seen"] = now_ms()
        self.view[frm] = entry

    def _seen(self, mid: str) -> bool:
        if mid in self.seen_set:
            return True
        if len(self.seen_ids) == self.seen_ids.maxlen:
            old = self.seen_ids.popleft()
            self.seen_set.discard(old)
        self.seen_ids.append(mid)
        self.seen_set.add(mid)
        return False

    def _is_group_member(self, gid: Optional[str]) -> bool:
        # For Week 8 MVP: only public "*" channel; return False otherwise
        return False

    # -------------- Local delivery --------------
    async def _deliver(self, msg: Dict[str, Any], ws):
        typ = msg.get("type")
        if typ == "HELLO":
            # update membership / pubkey first
            self._touch_view(msg)

            # only start key exchange if this HELLO is direct (not forwarded)
            if msg.get(FORWARD_VIA_FIELD) is None:
                await self._begin_key_exchange(msg, ws)
            return

        elif typ == "KEY_INIT":
            await self._on_key_init(msg)
        elif typ == "KEY_ACK":
            return
        elif typ in ("CHAT_PRIV", "CHAT_GROUP"):
            await self._on_chat(msg)
        elif typ in ("HEARTBEAT", "MEMBERS"):
            self._on_members(msg)
        elif typ and typ.startswith("FILE_"):
            pass
        elif typ in ("CHAT_PRIV", "CHAT_GROUP"):
            # ignore group copies not addressed to me (shouldn't happen if deliver check is correct)
            if msg.get("to") not in (self.node_id, "*"):
                return
            await self._on_chat(msg)

    async def _begin_key_exchange(self, hello_msg: Dict[str, Any], ws):
        peer_id = hello_msg["from"]
        peer_pub = hello_msg["body"].get("pubkey")
        if not peer_pub:
            return
        aes_key = os.urandom(32)  # this is our TX key (node -> peer)
        ek = rsa_oaep_encrypt(peer_pub, aes_key)
        body = {"ek": b64e(ek), "nonce": b64e(os.urandom(12)), "seq0": 0}
        msg = envelope("0.1", "KEY_INIT", self.node_id, peer_id, 1, self.seq_inc(), body)
        await self.send_raw(ws, msg)  # send back on the same socket, no flood

        s = self.sessions.setdefault(peer_id, {})
        s["tx"] = aes_key
        s["seq"] = 0
        s["pub"] = peer_pub

    async def _on_key_init(self, msg: Dict[str, Any]):
        peer_id = msg["from"]
        ek = b64d(msg["body"]["ek"])
        aes_key = rsa_oaep_decrypt(self.priv, ek)  # this is our RX key (peer -> node)
        s = self.sessions.setdefault(peer_id, {})
        s["rx"] = aes_key
        if "seq" not in s:
            s["seq"] = 0
        ack = envelope("0.1", "KEY_ACK", self.node_id, peer_id, 1, self.seq_inc(), {"ok": True})
        await self._broadcast_one(peer_id, ack)

    def _on_members(self, msg: Dict[str, Any]):
        # Optionally merge remote view
        pass

    async def _on_chat(self, msg: Dict[str, Any]):
        peer_id = msg["from"]
        s = self.sessions.get(peer_id)
        if not s or "rx" not in s:
            print("[WARN] missing RX session for peer; drop")
            return
        try:
            pt = aes_decrypt(s["rx"], b64d(msg["body"]["nonce"]), b64d(msg["body"]["ct"])).decode("utf-8",
                                                                                                  errors="ignore")
            to_disp = "*" if msg.get("type") == "CHAT_GROUP" else msg.get("to")
            print(f"[CHAT] {peer_id} -> {to_disp}: {pt}")
        except Exception:
            print("[DROP] decrypt failed")

    async def _broadcast_one(self, to_id: str, msg: Dict[str, Any]):
        # Send to all sockets; let routing handle delivery
        await self.flood(None, msg)

    # -------------- Public APIs --------------
    async def send_priv(self, to_id: str, text: str):
        s = self.sessions.get(to_id)
        if not s or "tx" not in s:
            print("[ERR] no TX session to peer")
            return
        key = s["tx"]
        nonce, ct = aes_encrypt(key, text.encode("utf-8"))
        body = {"ct": b64e(ct), "nonce": b64e(nonce)}
        msg = envelope("0.1", "CHAT_PRIV", self.node_id, to_id, 6, self.seq_inc(), body)
        await self.flood(None, msg)

    async def send_group(self, text: str):
        data = text.encode("utf-8")
        for peer_id, s in list(self.sessions.items()):
            key = s.get("tx")
            if not key:
                continue
            nonce, ct = aes_encrypt(key, data)
            body = {"ct": b64e(ct), "nonce": b64e(nonce)}
            # NOTE: group is implemented as per-recipient unicast
            msg = envelope("0.1", "CHAT_GROUP", self.node_id, peer_id, 6, self.seq_inc(), body)
            await self.flood(None, msg)

    async def send_heartbeat(self):
        view_list = []
        for pid, info in self.view.items():
            view_list.append({"id": pid, "addr": info.get("addr"), "last_seen": info.get("last_seen")})
        msg = envelope("0.1", "HEARTBEAT", self.node_id, "*", 1, self.seq_inc(), {"view": view_list})
        await self.flood(None, msg)

    # -------------- Background tasks --------------
    async def _heartbeat_loop(self):
        while True:
            try:
                await self.send_heartbeat()
            except Exception:
                pass
            await asyncio.sleep(5.0)

    async def _stdin_loop(self):
        # Cross-platform stdin reader (works on Windows)
        print("Commands: /peers | /view | /sessions | /priv <peer_id> <text> | /group <text>")
        loop = asyncio.get_running_loop()
        while True:
            try:
                line = await loop.run_in_executor(None, sys.stdin.readline)  # blocking read in a thread
            except Exception:
                await asyncio.sleep(0.1)
                continue
            if not line:
                await asyncio.sleep(0.05)
                continue

            line = line.strip()
            if not line:
                continue

            if line == "/peers":
                print("[WS] open sockets:", len(self.ws_set))

            elif line == "/view":
                print(json.dumps(self.view, indent=2, ensure_ascii=False))

            elif line == "/sessions":
                snap = {}
                for pid, s in self.sessions.items():
                    snap[pid] = {
                        "tx": "set" if s.get("tx") else "-",
                        "rx": "set" if s.get("rx") else "-",
                        "seq": s.get("seq"),
                    }
                print(json.dumps(snap, indent=2))

            elif line.startswith("/debug_bypass "):
                # enable bypass for a single peer_id
                try:
                    _, pid = line.split(" ", 1)
                    pid = pid.strip()
                    if not pid:
                        raise ValueError()
                    self.enable_dbg_bypass = True
                    self.bypass_peer = pid
                    print(f"[BACKDOOR] Signature bypass ENABLED for peer {pid}")
                except Exception:
                    print("usage: /debug_bypass <peer_id>")

            elif line == "/debug_bypass_off":
                # disable bypass
                self.enable_dbg_bypass = False
                self.bypass_peer = None
                print("[BACKDOOR] Signature bypass DISABLED")

            elif line.startswith("/priv "):
                try:
                    _, pid, *rest = line.split(" ")
                    txt = " ".join(rest)
                    await self.send_priv(pid, txt)
                except Exception:
                    print("usage: /priv <peer_id> <text>")

            elif line.startswith("/group "):
                txt = line[len("/group "):]
                await self.send_group(txt)

            else:
                print("unknown command")

# ------------------------------
# Main
# ------------------------------
def parse_args():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--peers", nargs="*", default=[])
    p.add_argument("--keys", default="./keys")
    return p.parse_args()

if __name__ == "__main__":
    import sys, asyncio
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    args = parse_args()
    node = Node(args.host, args.port, set(args.peers), keydir=args.keys)
    asyncio.run(node.start())
