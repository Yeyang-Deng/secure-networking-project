# Secure P2P Messaging System

A distributed peer-to-peer messaging system built with Python, WebSockets and modern cryptographic techniques.

The project was developed as part of a university Secure Programming course. It explores secure communication between multiple peer nodes, including identity management, key exchange, encrypted messaging, message authentication and distributed routing.

The project also contains an intentionally implemented security bypass for controlled security testing and peer review.

---

## Project Overview

The application creates a decentralised messaging network where multiple nodes communicate directly with each other without relying on a central messaging server.

Each node can:

- Discover other peers
- Establish cryptographic session keys
- Send encrypted private messages
- Send encrypted group messages
- Forward messages through the network
- Verify message signatures
- Inspect active peer and session information

A typical three-node network looks like:

```text
        Node 7001
       /         \
      /           \
Node 7002 ------- Node 7003
```

Each node runs its own WebSocket server and can also connect to other nodes as a client.

---

## Technologies

- Python
- AsyncIO
- WebSockets
- RSA-2048
- RSA-OAEP
- RSA-PSS
- AES-256-GCM
- SHA-256
- JSON
- Git / GitHub

---

## Security Design

### Node Identity

Each node generates its own RSA-2048 key pair when it is first started.

The public key is used to derive a short peer identifier using SHA-256.

```text
RSA Public Key
      │
      ▼
   SHA-256
      │
      ▼
   Peer ID
```

Private keys are generated locally and are not included in this repository.

---

### Peer Discovery

Nodes exchange `HELLO` messages containing:

- Public key
- Peer address
- Supported cryptographic algorithms

HELLO messages can propagate through the overlay network so that nodes can learn about peers that are not directly connected.

---

### Session Key Exchange

Private communication uses symmetric AES keys.

RSA-OAEP is used during the key exchange process to securely transfer session key material.

Each peer maintains directional session keys:

```text
Node A                        Node B

tx ───────────────────────► rx
rx ◄─────────────────────── tx
```

Keeping separate transmit and receive keys avoids session-key overwrite problems when both peers initiate communication at the same time.

---

### Message Encryption

Private and group messages are encrypted using:

**AES-256-GCM**

AES-GCM provides both:

- Confidentiality
- Integrity protection

A new nonce is normally generated for each encrypted message.

---

### Message Authentication

Messages are signed using:

**RSA-PSS with SHA-256**

Only immutable message fields are included in the signature.

These include:

```text
version
message type
message ID
sender
recipient
timestamp
sequence
body
```

Routing fields such as TTL and route history are not signed because forwarding nodes need to modify them.

The receiving node verifies the signature before processing the message.

---

## Distributed Message Routing

Messages can be forwarded between nodes using a simple flooding mechanism.

Each message contains:

- A unique message ID
- TTL
- Routing information
- Sender and recipient
- Sequence number

Nodes maintain a cache of previously seen message IDs to prevent repeated processing.

The routing process is approximately:

```text
Sender
  │
  ▼
Neighbour Node
  │
  ├── Verify signature
  ├── Check duplicate message ID
  ├── Reduce TTL
  ├── Update route
  │
  ▼
Forward to other peers
  │
  ▼
Recipient
```

---

## Private Messaging

A private message can be sent to a specific peer using:

```text
/priv <peer_id> <message>
```

For example:

```text
/priv a83bd82fa392de21 Hello from Node 7001
```

The message is encrypted using the session key associated with that peer.

Intermediate nodes may forward the encrypted packet but cannot decrypt the message.

---

## Group Messaging

Group messages can be sent using:

```text
/group <message>
```

Instead of encrypting one message with a shared group key, the implementation sends an individually encrypted message to each recipient.

This allows every recipient to receive a message encrypted with its own established session key.

---

## Command-Line Interface

The running application provides several commands.

### View connected WebSockets

```text
/peers
```

Displays the current number of open WebSocket connections.

### View discovered peers

```text
/view
```

Displays information such as:

- Peer ID
- Address
- Last-seen timestamp
- Public key

### View session state

```text
/sessions
```

Displays whether transmit and receive keys have been established for each peer.

Example:

```json
{
  "a83bd82fa392de21": {
    "tx": "set",
    "rx": "set",
    "seq": 4
  }
}
```

### Send a private message

```text
/priv <peer_id> <message>
```

### Send a group message

```text
/group <message>
```

---

## Intentional Security Backdoor

This project also contains an intentional signature-verification bypass.

It was implemented for controlled security testing as part of the Secure Programming assessment and is **disabled by default**.

Normally, every signed message must pass RSA-PSS signature verification.

The testing feature allows signature verification to be deliberately disabled for one selected peer:

```text
/debug_bypass <peer_id>
```

When enabled, messages originating from that peer bypass the normal signature check.

The bypass can be disabled again using:

```text
/debug_bypass_off
```

The relevant behaviour is deliberately visible in the program output:

```text
[BACKDOOR] Signature bypass ENABLED
[BACKDOOR] Skipping signature check
```

### Why this exists

The purpose of this feature was to demonstrate how a seemingly small change to authentication logic can undermine an otherwise secure communication protocol.

It was used to explore:

- Authentication bypass vulnerabilities
- Trust assumptions in distributed systems
- The impact of weakened signature verification
- Security code review
- Adversarial testing
- The difference between secure cryptographic primitives and secure system design

The cryptographic algorithms themselves remain secure; the vulnerability is introduced at the application logic layer by deliberately choosing not to enforce signature verification.

> **Important:** The backdoor is included only as an educational security-testing feature. It should remain disabled during normal operation and this project should not be treated as production-ready security software.

---

## Running the Project

### Requirements

The project was developed using Python 3.9 and has been tested with Python 3.9.10.

Install the required dependencies:

```bash
pip install -r requirements.txt
```

Main dependencies include:

```text
websockets
cryptography
uvloop (Linux only)
```

---

## Running Three Local Nodes

Open three terminals from the project root.

### Node 1

```bash
python src/node.py --port 7001 --keys keys-7001 --peers ws://127.0.0.1:7002 ws://127.0.0.1:7003
```

### Node 2

```bash
python src/node.py --port 7002 --keys keys-7002 --peers ws://127.0.0.1:7001 ws://127.0.0.1:7003
```

### Node 3

```bash
python src/node.py --port 7003 --keys keys-7003 --peers ws://127.0.0.1:7001 ws://127.0.0.1:7002
```

Each node must use a different key directory.

For example:

```text
keys-7001/
keys-7002/
keys-7003/
```

These directories are generated automatically during execution and are excluded from Git.

---

## Key Implementation Challenges

Several issues were identified and resolved during development.

### WebSocket Version Compatibility

The WebSocket server implementation was updated to support differences between WebSockets library versions.

### Cross-Platform AsyncIO

Windows required a different event-loop configuration from Linux and macOS.

The project includes Windows-specific AsyncIO handling to allow the application to run consistently across platforms.

### Distributed Key Exchange

Initially, forwarding handshake messages could cause incorrect session-key behaviour.

The protocol was changed so that key exchange is initiated only for directly connected peers.

### Directional Session Keys

Separate transmit and receive session keys were introduced to avoid key-overwrite race conditions.

### Signature Verification and Forwarding

Forwarding nodes modify TTL and routing information.

To prevent these changes from invalidating signatures, only immutable fields are signed and signatures are verified before routing fields are modified.

### Group Messaging

Group messaging was implemented as multiple encrypted unicasts instead of using a single ciphertext broadcast.

This ensures that each recipient receives data encrypted specifically for its session.

---

## My Contribution

My work on the project included:

- Developing and debugging the Python peer node
- Implementing peer-to-peer WebSocket communication
- Working with RSA and AES-based cryptographic operations
- Developing private and group messaging functionality
- Working on session and peer management
- Debugging distributed message forwarding and signature verification
- Improving compatibility between WebSockets library versions
- Developing command-line functionality for inspecting peers and sessions
- Testing security weaknesses and intentional vulnerable behaviour
- Participating in security review and adversarial testing

---

## Repository Structure

```text
secure-networking-project/
│
├── src/
│   └── node.py
│
├── screenshots/
│   └── Demo screenshots
│
├── requirements.txt
├── .gitignore
└── README.md
```

Generated private keys are intentionally excluded:

```text
keys-*/
*.pem
```

---

## What I Learned

This project gave me practical experience with both secure software development and distributed systems.

In particular, I developed a stronger understanding of:

- Asynchronous networking
- Peer-to-peer architectures
- Public-key cryptography
- Symmetric encryption
- Digital signatures
- Secure key exchange
- Message routing
- Session management
- Authentication vulnerabilities
- Security testing
- Debugging distributed applications

One of the most important lessons from the project was that using strong cryptographic algorithms alone does not guarantee a secure system. Application logic, trust decisions and verification behaviour are equally important.

---

## Project Note

This project originated from a university team assessment in Secure Programming.

This repository is a portfolio version containing the Python implementation related to my work. Private keys, virtual environments and unnecessary team files are not included.

The intentional security bypass is retained for educational demonstration and security analysis purposes and is disabled by default.
