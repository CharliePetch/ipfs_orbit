# Cipher Station

**Self-hosted, post-quantum, end-to-end encrypted content sharing over IPFS.**

Cipher Station lets you run a personal **station** on a Raspberry Pi (or any Linux box) that publishes encrypted content to IPFS and grants access to followers via cryptographic envelopes. No centralized servers, no platform lock-in — you own your data and your identity.

Content access control and device authentication use **NIST post-quantum algorithms** — ML-KEM-768 (FIPS 203) and ML-DSA-65 (FIPS 204) — so traffic captured today cannot be decrypted by a future quantum computer ("harvest now, decrypt later"). You can also publish **public, unencrypted** content for anyone to read.

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

Each post gets its own random symmetric key. That key is wrapped in a **post-quantum envelope** (ML-KEM-768) for each authorized follower, encapsulated to their public key. Only they can open it. Your station's IPFS **Peer ID** acts as a permanent address — followers can always find you via IPNS, even if your IP or tunnel URL changes.

## Features

- **Post-quantum cryptography** — Content envelopes use ML-KEM-768 (FIPS 203) and device authentication uses ML-DSA-65 (FIPS 204). No classical X25519 anywhere — safe against "harvest now, decrypt later".
- **End-to-end encryption** — Content is encrypted before it leaves your device. IPFS peers only see ciphertext.
- **Per-post access control** — Each post has its own key. Grant access to everyone, specific followers, just yourself, or **publicly** (unencrypted).
- **Optional public hosting** — Publish a file unencrypted to IPFS for anyone to fetch via a public gateway — useful for a profile picture, a public document, or a static site asset.
- **Permanent discovery via IPNS** — Your IPFS Peer ID is your stable address. No DNS, no static IP required.
- **Zero-config public access** — Optional Cloudflare Quick Tunnel gives you a public HTTPS URL with no port forwarding.
- **Multi-client architecture** — One identity, many apps. Photo sharing (cipherframe), file storage (ciphervault), and more — all sharing the same encryption and social graph.
- **Device pairing** — Pair your phone or laptop as a delegate device via 6-digit PIN. Access your content from anywhere.
- **Command-line client** — `./cipher` pairs as a delegate and can post, list, fetch and delete from any shell. See [Command-Line Client](#command-line-client).
- **Station-side fetch** — Paired devices can ask the station to retrieve any CID over its own IPFS connection instead of leaning on rate-limited public gateways.
- **Encrypted social graph** — Your follower and following lists are encrypted before being published to IPFS.
- **One-click install** — Single script sets up everything on a Raspberry Pi: IPFS, Python, systemd services, firewall, identity.

## Quick Start

### Raspberry Pi / Linux (Recommended)

```bash
git clone https://github.com/CharliePetch/cipher-station.git
cd cipher-station
chmod +x install.sh
./install.sh
```

The installer handles everything:
1. Installs Python 3.11+, IPFS (Kubo), and cloudflared
2. Creates a Python virtual environment with all dependencies
3. Bootstraps your post-quantum identity (ML-KEM-768 + ML-DSA-65 keypairs + UUID)
4. Configures and starts systemd services (IPFS, Cipher Station, Cloudflare tunnel, daily USB backup)
5. Opens the firewall (SSH, the station port, and the IPFS swarm port — pre-existing LAN services are preserved) and prints your Peer ID

Optional flags: `--restore` to rebuild from a USB backup (see [Backup & Restore](#backup--restore)), and `CIPHER_AUTO_UPDATE=true ./install.sh` to opt a self-hosted station into the health-gated auto-updater.

### macOS

Double-click `install-macos.command` in Finder. It installs IPFS and cloudflared under `~/.cipherstation`, registers `launchd` services, and adds a menu-bar app showing pairing PINs, the tunnel URL and storage. See [MACOS.md](MACOS.md).

After install, your station is live. Share your **Peer ID** with followers — they can always find you at:

```
https://ipfs.io/ipns/<your-peer-id>
```

### Manual Setup (Dev / Non-Pi)

```bash
# Prerequisites: Python 3.11+, IPFS daemon running on localhost:5001

git clone https://github.com/CharliePetch/cipher-station.git
cd cipher-station

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Optional: create a .env with any of the settings below
python run.py
```

`run.py` generates a self-signed TLS certificate on first start and listens on `https://0.0.0.0:8443`.

## Configuration

Settings are read from the environment or a `.env` file in the project root (the installer writes one). Everything has a working default:

| Variable | Default | Description |
|----------|---------|-------------|
| `CIPHER_PORT` | `8443` | HTTPS port |
| `CIPHER_HOST` | `0.0.0.0` | Bind address |
| `CIPHER_PANEL_PORT` | `8444` | Admin panel port (always bound to 127.0.0.1; see [Admin panel](#admin-panel)) |
| `CIPHER_BASE_DIR` | `./cipher_station_data` | Where keys, DB, manifests and TLS certs live |
| `CIPHER_PASSWORD` | _(empty)_ | Encrypt the station's private keys at rest (Argon2i) |
| `CIPHER_PQC_BACKEND` | `auto` | `auto` / `liboqs` / `python` — see [constant-time backend](#optional-constant-time-backend-liboqs) |
| `CLOUDFLARE_TUNNEL_ENABLED` | `false` | Enable zero-config public access |
| `IPFS_API_URL` | `http://127.0.0.1:5001` | Local IPFS daemon RPC |
| `IPFS_GATEWAY_URL` | `http://127.0.0.1:8080` | Local IPFS gateway (used to stream content) |
| `MAX_UPLOAD_SIZE` | `104857600` | Max upload size (100 MB) |
| `CIPHER_FETCH_ENABLED` | `true` | Serve `GET /fetch/{cid}` to paired devices |
| `CIPHER_FETCH_MAX_BYTES` | `536870912` | Refuse fetches larger than this (512 MB) |
| `CIPHER_FETCH_MAX_CONCURRENT` | `4` | In-flight fetches before the station answers 503 |
| `CIPHER_FETCH_PIN` | `false` | Pin fetched content instead of leaving it as GC-able cache |
| `CIPHER_BACKUP_DEST` | _(auto-detect USB)_ | Fixed destination for the daily backup |
| `CIPHER_PUBLIC_URL_MODE` | `quick` | Public URL mode: `quick` / `domain` / `grant` — see [Public URL modes](#public-url-modes) |
| `VERCEL_API_TOKEN` | _(unset)_ | Vercel DNS driver credential (own-domain mode / registry zones) |
| `CLOUDFLARE_API_TOKEN` | _(unset)_ | Cloudflare DNS driver credential (own-domain mode / registry zones) |
| `REGISTRY_ENABLED` | `false` | Serve the subdomain registry API on :8443 — see [Subdomain registry](#subdomain-registry) |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

See [PROTOCOL.md](PROTOCOL.md) Appendix B for the full configuration reference.

## Architecture

```
 +-------------------------------------------+
 |  Client Layer (cipherframe, ciphervault)   |  App-specific metadata
 +-------------------------------------------+
 |  Manifest Layer                            |  Post index, envelope pointers
 +-------------------------------------------+
 |  Social Graph Layer                        |  Encrypted followers/following
 +-------------------------------------------+
 |  Content Encryption Layer                  |  Per-post symmetric + envelopes
 +-------------------------------------------+
 |  Identity Layer                            |  ML-KEM-768 + ML-DSA-65 keypairs, UIDs
 +-------------------------------------------+
 |  Discovery Layer (IPNS)                    |  Permanent station addresses
 +-------------------------------------------+
 |  Cryptographic Primitives                  |  ML-KEM-768, ML-DSA-65, NaCl, BLAKE2b
 +-------------------------------------------+
 |  Transport (IPFS + HTTPS API)              |  Content storage, station API
 +-------------------------------------------+
```

### Cryptography

| Purpose | Algorithm |
|---------|-----------|
| Post encryption | XSalsa20-Poly1305 (NaCl SecretBox) — 256-bit, already PQ-resistant |
| Envelope key wrapping | **ML-KEM-768** (FIPS 203) KEM-DEM + SecretBox |
| Envelope KDF | BLAKE2b (domain-separated, `person="orbit-kem"`) |
| Device request signing | **ML-DSA-65** (FIPS 204) signatures |
| PIN hashing | scrypt |
| Key-at-rest encryption | Argon2i |

ML-KEM is a Key Encapsulation Mechanism, so a post's symmetric key is wrapped using the standard **KEM-DEM** construction: encapsulate to the recipient's ML-KEM key, derive a wrapping key from the shared secret with BLAKE2b, and SecretBox-wrap the post key. Device authentication signs the canonical request string with ML-DSA instead of deriving an HMAC key from an (X25519) ECDH.

> **Caveats.** By default the post-quantum primitives use the pure-Python [`kyber-py`](https://pypi.org/project/kyber-py/) and [`dilithium-py`](https://pypi.org/project/dilithium-py/) libraries — chosen because they install with no native build on a Raspberry Pi. They are **not constant-time** and are self-described as educational; in Cipher Station's model decapsulation and signing happen client-side (never as a server oracle), so timing side-channels are low-risk, but this is not a hardened production crypto stack. For a **constant-time** implementation, install the optional [Open Quantum Safe](https://openquantumsafe.org/) `liboqs` backend (see below). This release is also a **hard breaking change** — there is no migration from older X25519 stations, and every client must implement ML-KEM envelope opening and ML-DSA request signing.

#### Optional: constant-time backend (liboqs)

The ML-KEM / ML-DSA math is provided by a pluggable backend, selected with `CIPHER_PQC_BACKEND`:

| Value | Backend | Notes |
|-------|---------|-------|
| `auto` (default) | liboqs if available, else pure-Python | Self-tests liboqs at startup and falls back safely |
| `liboqs` | Open Quantum Safe (C) | **Constant-time / hardened.** Requires the `oqs` binding (native build) |
| `python` | kyber-py + dilithium-py | Pure-Python, no native build |

Both backends implement the same FIPS standards, so keys, envelopes, and signatures are fully interoperable — you can switch backends without re-bootstrapping. To enable the hardened backend:

```bash
pip install oqs            # builds/links liboqs; needs cmake + a C compiler
# then restart with CIPHER_PQC_BACKEND=auto (default) or =liboqs to require it
```

## API

| Endpoint | Auth | Description |
|----------|------|-------------|
| `GET /profile` | None | Public identity document (uid, ML-KEM + ML-DSA public keys, peer ID, manifest pointer) |
| `GET /health` | None | Station health check |
| `GET /storage` | None | IPFS repo, disk and per-client usage |
| `POST /inbox` | None* | Receive follow requests |
| `POST /delegate/start` | None | Initiate device pairing |
| `POST /delegate/confirm` | None | Confirm pairing with PIN |
| `POST /post` | Owner | Create a post (`audience_mode`: `self` / `specific` / `all` / `public`) |
| `POST /post/delete` | Owner | Remove a post from the manifest and unpin it |
| `POST /post/share` | Owner | Re-share an existing post to a new audience |
| `POST /rewrap` | Owner | Get a post's key re-sealed to this device's ML-KEM key |
| `GET /content/{cid}` | Owner | Stream bytes this station published (local-only, supports `Range`) |
| `GET /fetch/{cid}` | Owner | Retrieve **any** CID over the station's own IPFS connection (size-capped, rate-limited) |
| `POST /profile/update`, `POST /profile/avatar` | Owner | Edit the public profile |
| `POST /privacy/flip` | Owner | Switch the account between private and public |
| `GET /followers`, `GET /followers/pending` | Owner | List followers / pending requests |
| `POST /followers/approve`, `POST /followers/remove` | Owner | Manage followers |
| `GET /following`, `POST /follow`, `POST /unfollow` | Owner | Manage who you follow |

\* Follow requests are unauthenticated; other inbox message types require a signature.

**Owner** routes require a signed request from one of the station owner's paired delegate devices; a follower's device is rejected with 403. Full request/response shapes are in [PROTOCOL.md](PROTOCOL.md) Section 14.

**Authenticated requests** are signed with the device's **ML-DSA-65** key. The client sends `x-cipher-uid`, `x-cipher-device`, `x-cipher-ts`, `x-cipher-nonce`, `x-cipher-body-sha256`, and `x-cipher-sig` (base64 ML-DSA signature over the canonical string `METHOD\nPATH\nUID\nDEVICE_UID\nTS\nNONCE\nBODY_SHA256`). The station verifies the signature against the device's stored public key; a ±60 s timestamp window and a one-time nonce store prevent replay.

### Audience modes

Every post declares an `audience_mode`:

| Mode | Who can read | Encrypted? |
|------|--------------|------------|
| `self` | only you | yes |
| `specific` | you + listed follower UIDs | yes |
| `all` | you + all allowed followers | yes |
| `public` | **anyone** | **no** |

A `public` post is uploaded to IPFS **unencrypted** with no envelopes; its manifest entry is flagged `"encrypted": false` and any metadata is stored in the clear. Read it directly from any IPFS gateway:

```
https://ipfs.io/ipfs/<post_cid>
```

⚠️ Public content is **permanent and world-readable** once published — anyone who learns the CID (including via your public IPNS manifest) can fetch it, and IPFS has no delete. Only publish what you intend to share with the world.

## IPNS Discovery

Every Cipher Station publishes its `public.json` to IPNS under its IPFS Peer ID. This creates a **permanent, location-independent address** for your station:

```
Peer ID (never changes)  -->  IPNS  -->  /ipfs/<CID>  -->  public.json
```

Clients discover stations in priority order:
1. **Direct endpoint** — fastest, uses the HTTP URL from the social graph
2. **IPNS resolution** — if the endpoint is down, resolve the Peer ID via DHT
3. **Public gateway** — last resort: `https://ipfs.io/ipns/<peer-id>`

This means you can move your Pi to a new network, get a new tunnel URL, or change ISPs — followers will still find you.

## Command-Line Client

`./cipher` is a small stdlib client that speaks the full delegate protocol from any shell: it pairs as one of your devices, encrypts on your machine, and never hands the station plaintext or a key outside a post-quantum envelope.

```bash
# Pair once. The 6-digit PIN appears in the station's log (or the macOS menu bar).
./cipher pair --station https://<station>:8443
./cipher pair --station https://<station>:8443 --insecure   # self-signed cert: pins it (TOFU)

# Publish, browse, fetch, remove
./cipher post ~/Photos/trip.jpg --folder Trips --audience self
./cipher post notes.md --audience public
./cipher post file.bin --client drive              # land it in the CipherVault bucket
./cipher list
./cipher get <cid>                                 # writes the original filename in the cwd
./cipher get <cid> -o /tmp/out.bin
./cipher delete <cid>
```

- Keys and the station address live in `~/.config/cipher-cli/config.json` (mode 0600; override the directory with `CIPHER_CLI_HOME`).
- `--insecure` does not mean "trust anything": the station's certificate fingerprint is pinned at pairing and later commands refuse a station whose certificate changed. Re-pair with `--force` if you replaced the certificate on purpose.
- `--folder` becomes a `tags` entry inside the encrypted metadata, matching the drive client's folder convention. The real filename never appears on the wire.
- `list` and `get` recover each post's key through `POST /rewrap`, so the CLI can read posts made by your other devices too.

## Multi-Client Design

Cipher Station is a protocol, not a single app. Multiple clients share the same identity, encryption, and follower graph:

```json
{
  "clients": {
    "cipherframe": {
      "posts": [
        { "post_cid": "Qm...", "audience_mode": "all", "envelopes_cid": "Qm..." },
        { "post_cid": "Qm...", "audience_mode": "public", "encrypted": false, "envelopes_cid": null }
      ]
    },
    "ciphervault": {
      "posts": [{ "post_cid": "Qm...", "audience_mode": "self", "envelopes_cid": "Qm..." }]
    }
  }
}
```

Building a new client? Pick a name, define your metadata schema, and post to your namespace. See [PROTOCOL.md](PROTOCOL.md) Section 16.

## Project Structure

```
cipher-station/
├── install.sh              # One-click Raspberry Pi / Linux installer
├── install-macos.command   # macOS installer (launchd services + menu bar app)
├── run.py                  # Entry point (uvicorn + TLS)
├── cipher                  # Command-line client entry script
├── requirements.txt        # Python dependencies
├── README.md, PROTOCOL.md, CLIENT_FAQ.md, MACOS.md
├── brand/                  # Logo, icons and BRAND.md
├── scripts/
│   └── cipher-updater.sh   # Health-gated auto-updater (systemd timer)
├── cipher_station/
│   ├── main.py             # FastAPI app and routes
│   ├── pqcrypto.py         # Post-quantum primitives (ML-KEM-768, ML-DSA-65)
│   ├── crypto.py           # Key-at-rest encryption (Argon2i + SecretBox)
│   ├── identity.py         # PQC keypair generation and loading
│   ├── posts.py            # Post creation and encryption
│   ├── envelopes.py        # ML-KEM envelope create/open
│   ├── manifest.py         # Manifest serialization and publishing
│   ├── ipns_publisher.py   # Background IPNS publishing (off the request path)
│   ├── rewrap.py           # Delegate envelope rewrap
│   ├── rewrap_envelopes.py # Re-issue every envelope after a follower change
│   ├── auth.py             # ML-DSA signature authentication
│   ├── inbox.py            # Follow request handling
│   ├── pairing.py          # Device pairing (PIN)
│   ├── graph.py            # Social graph encryption
│   ├── followers.py        # Follower database ops
│   ├── following.py        # Following database ops
│   ├── privacy.py          # Private <-> public account flips
│   ├── ipfs_client.py      # IPFS/IPNS API wrapper (local + network streaming)
│   ├── tunnel.py           # Cloudflare tunnel monitor
│   ├── profile.py          # /profile endpoint
│   ├── storage.py          # Atomic, locked JSON state writes
│   ├── config.py           # Configuration loading
│   ├── backup.py           # USB backup & restore (create/restore CLI)
│   ├── tray.py             # macOS menu bar app
│   └── database.py         # SQLite schema
├── cipher_cli/
│   └── cli.py              # Command-line client (pair / post / list / get / delete)
├── cipher_station_data/    # Runtime data (created on first run; CIPHER_BASE_DIR)
│   ├── keys/mlkem.bin      # Station ML-KEM-768 keypair (content)
│   ├── keys/mldsa.bin      # Station ML-DSA-65 keypair (auth)
│   ├── public.json         # Public identity (uid, mlkem/mldsa public keys)
│   ├── manifests/          # Client manifests
│   ├── cipherstation.db    # SQLite database
│   └── ssl/                # TLS certificates
└── tests/                  # Test suite
```

## Admin panel

The station serves a web admin panel on its **own loopback-only listener**:
**http://localhost:8444/admin** (`CIPHER_PANEL_PORT`, always bound to
127.0.0.1, plain HTTP, no proxy-header trust). It is a separate server from
the public :8443 API, so the Cloudflare tunnel and any reverse proxy of :8443
can never reach it.

Access requires the **per-boot panel token**: on every station start a random
token is written (mode 0600) to `<data_dir>/panel_token`. Read it on the
station:

```bash
cat cipher_station_data/panel_token
```

The panel prompts for the token and keeps it in sessionStorage; every
`/admin/api` request must carry `Authorization: Bearer <token>` (constant-time
compared). As defense in depth the panel also refuses non-loopback socket
peers and rejects state-changing requests with a foreign `Origin` header.

The panel shows live station status (public URL, peer ID, IPNS name, IPFS
storage), lets you edit the station name/profile, tunnel & permanent-URL
settings, and the IPFS storage cap, and includes a full drive client (browse,
preview, upload, download, delete) compatible with the CipherVault drive
format. Pairing PINs are intentionally **not** shown in the panel — read them
from the station log on the box.

From another machine, use an SSH tunnel:

```bash
ssh -L 8444:localhost:8444 user@station
# then open http://localhost:8444/admin locally
```

## Public URL modes

The panel's Configuration tab offers three ways to give the station a public
URL (radio selection under **Public URL**). All modes are keys-optional:
missing or invalid credentials degrade to the quick tunnel with a banner —
never an unreachable station.

1. **Quick tunnel** (default) — the existing Cloudflare quick tunnel. Zero
   setup, ephemeral `https://<words>.trycloudflare.com` URL that rotates every
   restart.
2. **Own domain** — a permanent hostname on a domain you control. The panel
   keeps DNS **A/AAAA records pointed at the station's current public IPs**
   (discovered via ipify/icanhazip; v4-only and v6-only networks both work)
   and re-checks every 5 minutes (DDNS). Two DNS drivers behind one
   `DnsProvider` interface:
   - **Vercel** — set `VERCEL_API_TOKEN` in `.env`.
   - **Cloudflare** — set `CLOUDFLARE_API_TOKEN` in `.env` (zone must be
     CF-hosted; named-tunnel provisioning is not part of this mode — records
     only).

   This mode requires a **router port-forward** (WAN TCP 8443 or 443 → the
   station's LAN IP:8443); the panel shows the exact LAN IP and port. TLS
   note: the station serves its own (self-signed) certificate on :8443; a
   trusted-certificate (ACME) flow is future work. `CIPHER_PUBLIC_URL` is set
   from the chosen hostname while the mode is active.
3. **Subdomain grant** — claim a name (e.g. `charlie.cipherstation.io`) from
   a remote **subdomain registry** run by another operator (see below). The
   claim, heartbeats, and release are signed with this station's ML-DSA
   identity key; the panel shows availability/claim status and keeps the
   registry pointed at the station's current target.

## Subdomain registry

Any station can also *run* a registry that hands out subdomains on DNS zones
its operator controls. It ships in the repo and is **off by default** — set
`REGISTRY_ENABLED=true` in `.env` to mount the public API on :8443
(`/registry/*`). Zone configuration lives in `<data_dir>/registry.json`:

```json
{
  "zones": {
    "cipherstation.io": {
      "driver": "cloudflare",
      "token_env": "CLOUDFLARE_API_TOKEN",
      "claim_mode": "public",
      "reserved": ["extra-blocked-name"]
    }
  }
}
```

- **Claim modes:** `own` (admin-only via the panel), `invite` (claims need an
  admin-issued invite code), `public` (open claims).
- **Reserved names:** a built-in list (`www`, `mail`, `api`, `admin`,
  `panel`, `station`, `ns*`, plus an impersonation list — `login`, `secure`,
  `support`, `official`, `bank`, …) is always enforced; per-zone extras can
  be edited in the panel's Registry tab.
- **API** (rate-limited per client IP; all mutations ML-DSA-signed over a
  canonical payload with timestamp + nonce replay protection):
  - `GET /registry/check?name=x&zone=y` → `{available, reason?}`
  - `POST /registry/claim` → 201 (creates the DNS record + claim row),
    409 if taken (`taken_since`), 403 reserved/denied, 400 invalid. Names are
    single DNS labels: 1–63 chars of `[a-z0-9-]`, no edge hyphens.
  - `POST /registry/heartbeat` — refreshes the claim; accepts an updated
    target (re-upserts DNS on change).
  - `POST /registry/release` — owner-signed release (deletes DNS + row).
- **Expiry:** claims lapse **90 days** after the last heartbeat; expired
  names revert to available and their DNS records are deleted (lazily, on
  the next check/claim of the name).
- **Administration:** the panel gains a **Registry** tab (only when
  `REGISTRY_ENABLED=true`) with a claims table (revoke), invite-code
  issuance, per-zone driver/token status, and the reserved-name editor.

## Managing Your Station

```bash
# Check status
sudo systemctl status cipherstation

# View logs (pairing PINs appear here)
sudo journalctl -u cipherstation -f

# Restart
sudo systemctl restart cipherstation

# View IPFS peer ID
ipfs id -f='<id>'

# Current tunnel URL (also shown by the installer and in public.json "endpoint")
sudo journalctl -u cipherstation -f | grep 'Tunnel endpoint'
```

Hosted stations, and self-hosted ones installed with `CIPHER_AUTO_UPDATE=true`, run `cipherstation-updater.timer`: it checks out the pinned commit, re-runs the installer, and rolls back automatically if `/health` does not come back.

## Backup & Restore

microSD cards fail. A backup captures **everything that makes the station yours** —
your Cipher Station keys, the database, the manifest, **and** the IPFS peer identity (your
permanent peer ID / IPNS address) plus the pinned post content — into a single
portable archive on a USB drive, so you can rebuild on a fresh card or box and
come back at the **same address with the same posts**.

### Create a backup

Plug in a USB drive, then:

```bash
# Auto-detects a mounted USB drive (or set CIPHER_BACKUP_DEST / pass --dest)
.venv/bin/python -m cipher_station.backup create

# Explicit destination, or encrypt the archive with a passphrase:
.venv/bin/python -m cipher_station.backup create --dest /media/$USER/MYDRIVE
.venv/bin/python -m cipher_station.backup create --passphrase 'correct horse battery staple'

# List backups found on the drive
.venv/bin/python -m cipher_station.backup list
```

A **daily backup also runs automatically** whenever a USB drive is mounted, via
the `cipherstation-backup.timer` systemd unit the installer sets up (it cleanly no-ops
when no drive is present). Set a fixed destination with `CIPHER_BACKUP_DEST` in
`.env`.

> ⚠️ **Unencrypted backups contain your private keys** (Cipher Station + the IPFS node
> key + your `.env`). Keep the drive physically secure, or use `--passphrase`.

### Restore onto a fresh station

During install, point `install.sh` at a backup:

```bash
./install.sh --restore                                   # auto-detect a backup on a mounted USB
./install.sh --restore=/media/<user>/<drive>/cipherstation-backup-<id>-<ts>.tar.gz
```

Restore reinstates `cipher_station_data/`, the IPFS peer identity, and the pinned content
**before** a fresh identity would be generated — so `ipfs id` returns your
original peer ID and followers can still find you. (If you used a passphrase, it
will be prompted for.) The archive format is documented in
[PROTOCOL.md](PROTOCOL.md).

## Running Tests

```bash
source .venv/bin/activate
pytest
```

No IPFS daemon is needed; the suite stubs IPFS and runs every station path inside a temp directory. Three liboqs interop tests skip unless the `oqs` binding is installed.

## Protocol Specification

The full protocol is documented in [PROTOCOL.md](PROTOCOL.md) — covering identity, cryptography, envelopes, manifests, IPNS discovery, device pairing, authentication, the social graph, and the installation process.

## License

TBD
