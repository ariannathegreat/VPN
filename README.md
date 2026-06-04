# VPN Secure Tunnel — Arianna's Implementation

Python implementation of the VPN project (programming role).  
All code maps directly to the week-by-week roadmap.

---

## Project Structure

```
vpn_project/
├── core/
│   ├── crypto.py       ← Week 4: ECDH key exchange, AES-GCM / ChaCha20-Poly1305
│   ├── handshake.py    ← Week 4: 4-message handshake state machine (client + server)
│   ├── packet.py       ← Week 5 & 6: encapsulation, replay window, timestamp check
│   ├── tun.py          ← Week 3: TUN interface, routing, DNS leak prevention
│   └── session.py      ← Week 6: session lifecycle, re-key, idle timeout
├── client/
│   └── client.py       ← Full VPN client (Weeks 3–7)
├── server/
│   └── server.py       ← Multi-client VPN server (Weeks 3–7)
├── utils/
│   └── logger.py       ← Week 7: structured logging + JSON audit trail
├── tests/
│   └── test_vpn.py     ← 44 unit & integration tests
├── logs/               ← Runtime log output (auto-created)
└── requirements.txt
```

---

## Setup (VS Code)

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Open in VS Code
Open the `vpn_project/` folder as your workspace.  
The recommended Python extension will auto-detect the project.

### 3. Run tests
```bash
python -m pytest tests/test_vpn.py -v
```

---

## Running the VPN (requires Linux + root for TUN)

### Start the server
```bash
sudo python server/server.py --psk "your-secret-key" --port 5194
```

### Connect a client (separate terminal / machine)
```bash
sudo python client/client.py \
  --host 127.0.0.1 \
  --port 5194 \
  --psk "your-secret-key"
```

### Optional flags
| Flag | Default | Description |
|------|---------|-------------|
| `--host` | `0.0.0.0` (server) / `127.0.0.1` (client) | Server IP |
| `--port` | `5194` | UDP port |
| `--psk` | *(required)* | Pre-shared key |
| `--tun` | `vpn0` / `vpns0` | TUN interface name |
| `--cipher` | `ChaCha20-Poly1305` | `AES-GCM` or `ChaCha20-Poly1305` |
| `--full-tunnel` | off | Route all traffic through VPN |
| `--debug` | off | Verbose logging |

---

## What each module implements

### `core/crypto.py`
- `ECDHKeyPair` — X25519 ephemeral key pair generation
- `derive_session_keys()` — HKDF-SHA256 key derivation from ECDH shared secret
- `CipherSuite` — AEAD encrypt/decrypt with random nonce, supports AES-GCM and ChaCha20-Poly1305
- `hash_psk()` — SHA-256 pre-shared key derivation

### `core/handshake.py`
- `ClientHandshake` — builds CLIENT_HELLO, CLIENT_FINISH; processes SERVER_HELLO, SERVER_ACK
- `ServerHandshake` — processes CLIENT_HELLO, CLIENT_FINISH; builds SERVER_HELLO, SERVER_ACK
- `SessionKeys` — holds send/recv cipher pair + metadata

### `core/packet.py`
- `VPNPacket` — wire-format serialise/deserialise with 26-byte header
- `PacketEncapsulator` — wraps raw IP frames, increments sequence counter
- `ReplayWindow` — 64-bit sliding bitmask, rejects replayed or too-old sequences
- `validate_timestamp()` — rejects packets > 60 s outside current time

### `core/tun.py`
- `TUNInterface` — opens `/dev/net/tun`, configures IP address and routes via `ip` commands
- `DNSProtection` — overwrites `/etc/resolv.conf` with VPN DNS on connect, restores on close

### `core/session.py`
- `Session` — per-client state: keys, replay window, rx/tx stats, idle timer
- `SessionManager` — thread-safe dict of sessions with background reaper thread

### `client/client.py`
- Full client: TUN setup → handshake → select() loop → disconnect
- Keepalive thread every 20 s
- Re-key detection triggers clean reconnect

### `server/server.py`
- Listens on UDP, dispatches CLIENT_HELLO to new handshake, routes FINISH to pending state
- `select()` + background TUN→client forwarding thread
- Handles KEEPALIVE, DISCONNECT, re-key signals

### `utils/logger.py`
- Rotating file logs (`logs/vpn.log`)
- `AuditLogger` — JSON event lines to `logs/audit.log` for CONNECT, AUTH_FAIL, REPLAY, REKEY, etc.

---

## Security Properties

| Property | Implementation |
|----------|---------------|
| Confidentiality | AES-256-GCM or ChaCha20-Poly1305 |
| Integrity | AEAD authentication tag |
| Key Exchange | X25519 ECDH + HKDF-SHA256 |
| Authentication | HMAC-SHA256 PSK proof in handshake |
| Replay protection | Sliding-window seq + timestamp check |
| DNS leak prevention | `/etc/resolv.conf` override |
| Forward secrecy | Ephemeral ECDH keys per session |
| Session expiry | 5 min idle / 1 hr hard timeout + re-key |

---

## Roadmap alignment

| Week | Arianna task | File |
|------|-------------|------|
| 3 | TUN/TAP interface, UDP socket, skeleton server/client | `tun.py`, `client.py`, `server.py` |
| 4 | Handshake, crypto library, session state machine | `crypto.py`, `handshake.py` |
| 5 | Packet encapsulation/decapsulation, routing, DNS | `packet.py`, `tun.py` |
| 6 | Replay protection, session timeout, re-key | `packet.py`, `session.py` |
| 7 | Logging, audit trail, error handling, graceful disconnect | `logger.py`, `client.py`, `server.py` |
