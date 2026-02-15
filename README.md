# Orbit

**Self-hosted, end-to-end encrypted content sharing over IPFS.**

Orbit lets you run a personal **station** on a Raspberry Pi (or any Linux box) that publishes encrypted content to IPFS and grants access to followers via cryptographic envelopes. No centralized servers, no platform lock-in — you own your data and your identity.

## How It Works

```
You (Station)                         Followers
     |                                     |
     |  1. Encrypt content                 |
     |  2. Upload to IPFS                  |
     |  3. Create per-follower envelopes   |
     |  4. Publish manifest                |
     |  5. Update IPNS pointer             |
     |                                     |
     |          IPFS Network               |
     |  <------------------------------>   |
     |                                     |
     |     6. Resolve your Peer ID (IPNS)  |
     |     7. Fetch manifest               |
     |     8. Open their envelope          |
     |     9. Decrypt content              |
```

Each post gets its own random symmetric key. That key is wrapped in a **SealedBox envelope** for each authorized follower, sealed to their public key. Only they can open it. Your station's IPFS **Peer ID** acts as a permanent address — followers can always find you via IPNS, even if your IP or tunnel URL changes.

## Features

- **End-to-end encryption** — Content is encrypted before it leaves your device. IPFS peers only see ciphertext.
- **Per-post access control** — Each post has its own key. Grant access to everyone, specific followers, or just yourself.
- **Permanent discovery via IPNS** — Your IPFS Peer ID is your stable address. No DNS, no static IP required.
- **Zero-config public access** — Optional Cloudflare Quick Tunnel gives you a public HTTPS URL with no port forwarding.
- **Multi-client architecture** — One identity, many apps. Photo sharing (orbitstagram), file storage (orbitdrive), and more — all sharing the same encryption and social graph.
- **Device pairing** — Pair your phone or laptop as a delegate device via 6-digit PIN. Access your content from anywhere.
- **Encrypted social graph** — Your follower and following lists are encrypted before being published to IPFS.
- **One-click install** — Single script sets up everything on a Raspberry Pi: IPFS, Python, systemd services, firewall, identity.

## Quick Start

### Raspberry Pi (Recommended)

```bash
git clone https://github.com/your-username/orbit.git
cd orbit
chmod +x install.sh
./install.sh
```

The installer handles everything:
1. Installs Python 3.11+, IPFS (Kubo), and cloudflared
2. Creates a Python virtual environment with all dependencies
3. Bootstraps your cryptographic identity (Curve25519 keypair + UUID)
4. Configures and starts systemd services (IPFS, Orbit, Cloudflare tunnel)
5. Opens the firewall and prints your Peer ID

After install, your station is live. Share your **Peer ID** with followers — they can always find you at:

```
https://ipfs.io/ipns/<your-peer-id>
```

### Manual Setup (Dev / Non-Pi)

```bash
# Prerequisites: Python 3.11+, IPFS daemon running on localhost:5001

git clone https://github.com/your-username/orbit.git
cd orbit

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env as needed

python run.py
```

## Configuration

Copy `.env.example` to `.env` and customize:

| Variable | Default | Description |
|----------|---------|-------------|
| `ORBIT_PORT` | `8443` | HTTPS port |
| `ORBIT_PASSWORD` | _(empty)_ | Encrypt your private key at rest |
| `CLOUDFLARE_TUNNEL_ENABLED` | `false` | Enable zero-config public access |
| `IPFS_API_URL` | `http://127.0.0.1:5001` | Local IPFS daemon |
| `MAX_UPLOAD_SIZE` | `104857600` | Max upload size (100 MB) |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

See [PROTOCOL.md](PROTOCOL.md) Appendix B for the full configuration reference.

## Architecture

```
 +-------------------------------------------+
 |  Client Layer (orbitstagram, orbitdrive)   |  App-specific metadata
 +-------------------------------------------+
 |  Manifest Layer                            |  Post index, envelope pointers
 +-------------------------------------------+
 |  Social Graph Layer                        |  Encrypted followers/following
 +-------------------------------------------+
 |  Content Encryption Layer                  |  Per-post symmetric + envelopes
 +-------------------------------------------+
 |  Identity Layer                            |  Curve25519 keypairs, UIDs
 +-------------------------------------------+
 |  Discovery Layer (IPNS)                    |  Permanent station addresses
 +-------------------------------------------+
 |  Cryptographic Primitives                  |  NaCl, BLAKE2b, HMAC-SHA256
 +-------------------------------------------+
 |  Transport (IPFS + HTTPS API)              |  Content storage, station API
 +-------------------------------------------+
```

### Cryptography

| Purpose | Algorithm |
|---------|-----------|
| Post encryption | XSalsa20-Poly1305 (NaCl SecretBox) |
| Envelope sealing | Curve25519 SealedBox |
| Key agreement | X25519 |
| Auth key derivation | BLAKE2b (domain-separated) |
| Request signing | HMAC-SHA256 |
| PIN hashing | scrypt |
| Key-at-rest encryption | Argon2i |

## API

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /profile` | None | Public identity document (uid, public key, peer ID, manifest pointer) |
| `GET /health` | None | Station health check |
| `POST /inbox` | None* | Receive follow requests |
| `POST /post` | HMAC | Create an encrypted post |
| `POST /rewrap` | HMAC | Get a device-specific envelope |
| `POST /follow` | HMAC | Follow another user |
| `POST /unfollow` | HMAC | Unfollow a user |
| `POST /delegate/start` | None | Initiate device pairing |
| `POST /delegate/confirm` | None | Confirm pairing with PIN |

\* Follow requests are unauthenticated; other inbox message types require HMAC.

## IPNS Discovery

Every Orbit station publishes its `public.json` to IPNS under its IPFS Peer ID. This creates a **permanent, location-independent address** for your station:

```
Peer ID (never changes)  -->  IPNS  -->  /ipfs/<CID>  -->  public.json
```

Clients discover stations in priority order:
1. **Direct endpoint** — fastest, uses the HTTP URL from the social graph
2. **IPNS resolution** — if the endpoint is down, resolve the Peer ID via DHT
3. **Public gateway** — last resort: `https://ipfs.io/ipns/<peer-id>`

This means you can move your Pi to a new network, get a new tunnel URL, or change ISPs — followers will still find you.

## Multi-Client Design

Orbit is a protocol, not a single app. Multiple clients share the same identity, encryption, and follower graph:

```json
{
  "clients": {
    "orbitstagram": {
      "posts": [{ "post_cid": "Qm...", "audience_mode": "all", "envelopes_cid": "Qm..." }]
    },
    "orbitdrive": {
      "posts": [{ "post_cid": "Qm...", "audience_mode": "self", "envelopes_cid": "Qm..." }]
    }
  }
}
```

Building a new client? Pick a name, define your metadata schema, and post to your namespace. See [PROTOCOL.md](PROTOCOL.md) Section 16.

## Project Structure

```
orbit/
├── install.sh              # One-click Raspberry Pi installer
├── run.py                  # Entry point (uvicorn + TLS)
├── requirements.txt        # Python dependencies
├── .env.example            # Configuration template
├── PROTOCOL.md             # Full protocol specification
├── orbit_node/
│   ├── main.py             # FastAPI app and routes
│   ├── identity.py         # Keypair generation and loading
│   ├── posts.py            # Post creation and encryption
│   ├── envelopes.py        # Envelope creation/decryption
│   ├── manifest.py         # Manifest serialization
│   ├── rewrap.py           # Delegate envelope rewrap
│   ├── auth.py             # HMAC authentication
│   ├── inbox.py            # Follow request handling
│   ├── pairing.py          # Device pairing (PIN)
│   ├── graph.py            # Social graph encryption
│   ├── followers.py        # Follower database ops
│   ├── following.py        # Following database ops
│   ├── ipfs_client.py      # IPFS/IPNS API wrapper
│   ├── tunnel.py           # Cloudflare tunnel monitor
│   ├── profile.py          # /profile endpoint
│   ├── config.py           # Configuration loading
│   └── database.py         # SQLite schema
├── orbit_data/             # Runtime data (created on first run)
│   ├── keys/private.bin    # Station keypair
│   ├── public.json         # Public identity
│   ├── orbit.db            # SQLite database
│   └── ssl/                # TLS certificates
└── tests/                  # Test suite
```

## Managing Your Station

```bash
# Check status
sudo systemctl status orbit

# View logs
sudo journalctl -u orbit -f

# Restart
sudo systemctl restart orbit

# View IPFS peer ID
ipfs id -f='<id>'

# Check tunnel URL
sudo journalctl -u cloudflared-tunnel -f
```

## Running Tests

```bash
source .venv/bin/activate
pytest
```

## Protocol Specification

The full protocol is documented in [PROTOCOL.md](PROTOCOL.md) — covering identity, cryptography, envelopes, manifests, IPNS discovery, device pairing, authentication, the social graph, and the installation process.

## License

TBD
