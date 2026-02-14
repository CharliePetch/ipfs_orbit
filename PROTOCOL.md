# Orbit Protocol Specification

**Version:** 1.0-draft
**Date:** 2026-02-14
**Status:** Draft

---

## Abstract

Orbit is a self-hosted, end-to-end encrypted content sharing protocol built on IPFS. A user runs a **station** (e.g., on a Raspberry Pi at home), publishes encrypted content to IPFS, and provisions access to friends, family, or followers via cryptographic **envelopes** containing per-post decryption keys. The station owner's content is replicated and made available through IPFS's content-addressed storage, removing dependence on centralized platforms.

The protocol is designed to be **extensible**: different application-layer **clients** (photo sharing, file storage, document collaboration, etc.) share the same identity, encryption, and access-control infrastructure while defining their own metadata schemas within a unified manifest.

---

## 1. Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

All integers are unsigned unless otherwise noted. All strings are UTF-8. Hexadecimal encodings use lowercase characters. JSON serialization for IPFS upload MUST use compact encoding (no whitespace separators: `(",", ":")`).

---

## 2. Glossary

| Term | Definition |
|------|------------|
| **Station** | The user's self-hosted Orbit node. Holds the root private key. Runs the API server and local IPFS daemon. Typically a Raspberry Pi or similar always-on device. |
| **Delegate** | A secondary device (phone, laptop) paired with the station. Has its own Curve25519 keypair but relies on the station for envelope rewrapping. |
| **UID** | A UUID v4 string that uniquely identifies a user across the Orbit network. |
| **Device UID** | A UUID v4 string that uniquely identifies a single device belonging to a user. For a station, `device_uid` equals `uid`. |
| **Envelope** | A NaCl SealedBox containing a 32-byte symmetric key, encrypted to a specific recipient's Curve25519 public key. |
| **Manifest** | A JSON document listing all posts across all clients, with pointers to encrypted content and envelope files on IPFS. Published to IPFS; its CID is stored in `public.json` as `manifest_pointer`. |
| **Client** | An application-layer module that uses the Orbit protocol for a specific use case (e.g., `orbitstagram` for photos, `orbitdrive` for files). Each client occupies a namespace within the manifest. |
| **CID** | Content Identifier. An IPFS content-addressed hash (typically CIDv0/Base58). |
| **Post** | A single encrypted content blob stored on IPFS, along with its associated envelopes and metadata. |
| **Audience** | The set of UIDs permitted to decrypt a given post. Controlled by `audience_mode`. |

---

## 3. Architecture Overview

### 3.1 System Topology

```
                          IPFS Network
                         /            \
                        /              \
    [Station]  <-- IPFS Daemon -->  [IPFS Peers]
    (FastAPI)      (port 5001)
        |
        |  HTTPS / LAN
        |
    [Delegate Device]
    (iOS / Android / Web)
```

A station consists of:
- An **Orbit server** (HTTP API)
- A **local IPFS daemon** (Kubo, port 5001)
- A **SQLite database** for follower/device state
- A **local filesystem** for key material and manifests

Delegate devices communicate with the station over HTTP (ideally HTTPS in production) and access IPFS content either through the station's IPFS gateway or their own IPFS node.

### 3.2 Trust Model

The **station** is the root of trust:
- It holds the only copy of the user's root private key.
- It generates all envelopes (encrypts symmetric keys for recipients).
- It approves or denies follow requests.
- It performs envelope rewrapping for delegate devices.

**Delegates** are trusted devices that have been paired via a PIN-based ceremony. They can create posts and request envelope rewraps, but cannot access the root private key directly.

**Followers** are external users who have been granted access. They receive envelopes sealed to their public key, allowing them to decrypt posts they are authorized to see.

### 3.3 Protocol Layers

```
 +-------------------------------------------+
 |  Client Layer (orbitstagram, orbitdrive)   |  Application-specific metadata
 +-------------------------------------------+
 |  Manifest Layer                            |  Post index, envelope pointers
 +-------------------------------------------+
 |  Social Graph Layer                        |  Followers, following, graph encryption
 +-------------------------------------------+
 |  Content Encryption Layer                  |  Per-post symmetric encryption + envelopes
 +-------------------------------------------+
 |  Identity Layer                            |  Keypairs, UIDs, public identity
 +-------------------------------------------+
 |  Cryptographic Primitives                  |  NaCl, Argon2i, BLAKE2b, HMAC
 +-------------------------------------------+
 |  Transport (IPFS + HTTP API)               |  Content storage, station API
 +-------------------------------------------+
```

---

## 4. Cryptographic Primitives

### 4.1 Key Types

| Key Type | Algorithm | Size | Usage |
|----------|-----------|------|-------|
| Identity keypair | Curve25519 | 32 bytes (private), 32 bytes (public) | User/device identity, envelope creation |
| Symmetric key | XSalsa20-Poly1305 (NaCl SecretBox) | 32 bytes | Post encryption, graph encryption, metadata encryption |
| Auth key | BLAKE2b derived | 32 bytes | HMAC-based request authentication |

### 4.2 Symmetric Encryption (SecretBox)

Used for encrypting post content, metadata, and social graphs.

- **Algorithm:** XSalsa20-Poly1305 (NaCl SecretBox)
- **Key size:** 32 bytes
- **Nonce:** 24 bytes, randomly generated per encryption

**Output format:**

```
+----------+------------------+--------+
| nonce    | ciphertext       | tag    |
| 24 bytes | len(plaintext)   | 16 B   |
+----------+------------------+--------+
```

Total output size: `24 + len(plaintext) + 16` bytes.

The nonce is prepended to the ciphertext by NaCl's `SecretBox.encrypt()`. Implementations MUST generate a fresh random nonce for every encryption operation.

### 4.3 Asymmetric Encryption (SealedBox)

Used for creating envelopes (encrypting symmetric keys for specific recipients).

- **Algorithm:** NaCl SealedBox (X25519 key agreement + XSalsa20-Poly1305)
- **Input:** plaintext (typically 32 bytes), recipient Curve25519 public key
- **Ephemeral keypair:** Generated internally per encryption

**Output format:**

```
+-----------------+------------------+--------+
| ephemeral_pk    | ciphertext       | tag    |
| 32 bytes        | len(plaintext)   | 16 B   |
+-----------------+------------------+--------+
```

For a 32-byte symmetric key input, the output is `32 + 32 + 16 = 80` bytes, which encodes to **160 hex characters**.

SealedBox provides anonymous encryption: the recipient can decrypt without knowing the sender's identity, using only their own private key.

### 4.4 Password-Based Key Encryption (Argon2i)

Used for encrypting the station's private key at rest.

- **KDF:** Argon2i (via PyNaCl defaults)
- **Salt:** 16 bytes, randomly generated
- **Output key:** 32 bytes
- **Encryption:** The derived key encrypts the private key material using SecretBox

**Stored format:**

```
+--------+----------------------------------+
| salt   | SecretBox(sk_32 + pk_32)         |
| 16 B   | 24 (nonce) + 64 (ct) + 16 (tag) |
+--------+----------------------------------+
```

Total: `16 + 24 + 64 + 16 = 120` bytes.

### 4.5 PIN Hashing (scrypt)

Used for hashing device-pairing PINs.

- **Algorithm:** scrypt
- **Parameters:** n=16384 (2^14), r=8, p=1, dklen=32
- **Salt:** 16 bytes, randomly generated per session

### 4.6 Auth Key Derivation

Used for deriving HMAC keys for delegate authentication.

1. **Key agreement:** `shared_secret = X25519(station_sk, device_pk)` (32 bytes)
2. **Domain separation:** `auth_key = BLAKE2b(shared_secret, digest_size=32, person=b"orbit-auth")`

The `person` parameter MUST be exactly the 8-byte ASCII string `orbit-auth` zero-padded to 16 bytes (per BLAKE2b spec).

### 4.7 Request Signing (HMAC-SHA256)

- **Algorithm:** HMAC-SHA256
- **Key:** auth_key (32 bytes, derived per Section 4.6)
- **Message:** canonical request string (see Section 12)

---

## 5. Identity Layer

### 5.1 Identity Structure

Each Orbit identity consists of:

| Field | Type | Description |
|-------|------|-------------|
| `uid` | UUID v4 string | Globally unique user identifier |
| `device_uid` | UUID v4 string | Per-device identifier. For the station, `device_uid == uid`. |
| `public_key` | 64 hex chars | Curve25519 public key (32 bytes) |

### 5.2 Key Storage

The station stores its private key in a binary file:

**File:** `orbit_data/keys/private.bin`

**Format (unencrypted, dev mode):**

```
+---------------+---------------+
| private_key   | public_key    |
| 32 bytes      | 32 bytes      |
+---------------+---------------+
```

Total: 64 bytes.

For production deployments, the key file SHOULD be encrypted using the Argon2i scheme described in Section 4.4.

### 5.3 Public Identity Document

**File:** `orbit_data/public.json`

Every station MUST publish a public identity document:

```json
{
  "uid": "<uuid-v4>",
  "alias": "<human-readable-name> | null",
  "public_key": "<64-hex-chars>",
  "endpoint": "<https://station-url> | null",
  "manifest_pointer": "<ipfs-cid> | null",
  "followers_cid": "<ipfs-cid> | null",
  "following_cid": "<ipfs-cid> | null",
  "follow_decoder_envelopes_cid": "<ipfs-cid> | null"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `uid` | MUST | User's UUID v4 |
| `alias` | MAY | Human-readable display name |
| `public_key` | MUST | Hex-encoded Curve25519 public key. MUST match the station's actual keypair. |
| `endpoint` | SHOULD | HTTPS URL where the station API is reachable |
| `manifest_pointer` | MUST (after first post) | IPFS CID of the current manifest |
| `followers_cid` | MAY | IPFS CID of the encrypted followers graph |
| `following_cid` | MAY | IPFS CID of the encrypted following graph |
| `follow_decoder_envelopes_cid` | MAY | IPFS CID of the graph decoder envelopes |

### 5.4 Bootstrap Flow

When a station starts for the first time:

1. Generate a Curve25519 keypair.
2. Generate a UUID v4 for `uid`.
3. Write `private.bin` (sk + pk, 64 bytes).
4. Write `public.json` with the generated uid and public key.
5. Register the station as its own follower (uid, device_uid=uid, station public key, allowed="Allowed").

---

## 6. Envelope System

### 6.1 Concept

An **envelope** wraps a per-post symmetric key for a specific recipient. The symmetric key is encrypted using the recipient's Curve25519 public key via NaCl SealedBox. Only the holder of the corresponding private key can open the envelope and recover the symmetric key.

### 6.2 Envelope Creation

```
Input:  sym_key (32 bytes), recipient_public_key (32 bytes)
Output: SealedBox(sym_key, recipient_public_key) -> 80 bytes -> 160 hex chars
```

Implementations MUST:
- Validate that the recipient public key is exactly 32 bytes (64 hex characters).
- Skip envelope creation for invalid keys (log and continue).
- Hex-encode the SealedBox output using lowercase characters.

### 6.3 Envelope Opening

```
Input:  envelope_hex (160 hex chars), recipient_private_key (32 bytes)
Output: sym_key (32 bytes)
```

The recipient decodes the hex envelope to 80 bytes, then decrypts using `SealedBox(private_key).decrypt()`.

### 6.4 User-Level Keying

Post envelopes are keyed by **UID** (not device_uid). This means:
- Each post has **one envelope per user**, regardless of how many devices that user has.
- The envelope is sealed to the **root device's public key** for that user.
- For the station owner, the envelope is always sealed to the station's own public key.

This design prevents envelope explosion (N posts * M followers * D devices) and keeps the envelopes JSON compact.

### 6.5 Self-Envelope

Every post MUST include a "self" envelope — an envelope sealed to the station's own public key, keyed by the station's uid. This ensures the station can always decrypt its own content.

When constructing the envelope list:
1. Remove any existing entry for the station's uid.
2. Insert a self-entry at position 0, using the station's public key (not any delegate device key).

### 6.6 Delegate Access via Rewrap

Delegate devices cannot directly open user-level envelopes (they have different keypairs). Instead, they request an **envelope rewrap** from the station:

1. Delegate sends authenticated request: "I am device D of user U, give me access to post P."
2. Station opens the root envelope with station sk -> recovers sym_key.
3. Station re-encrypts sym_key with the delegate device's public key -> new envelope.
4. Station returns the device-specific envelope.

See Section 11 for the full rewrap protocol.

---

## 7. Content Encryption

### 7.1 Post Encryption Flow

When creating a new post, the station executes the following steps:

**Step 1: Generate symmetric key**
```
sym_key = random(32)  # NaCl SecretBox.KEY_SIZE
```

**Step 2: Encrypt content**
```
box = SecretBox(sym_key)
encrypted_blob = box.encrypt(plaintext_bytes)
# Output: nonce(24) + ciphertext + tag(16)
```

**Step 3: Upload to IPFS**
```
post_cid = ipfs_add_bytes(encrypted_blob)
```

**Step 4: Determine recipients**

The recipient list depends on the `audience_mode`:

| Mode | Recipients |
|------|------------|
| `self` | Station only (self-envelope) |
| `specific` | Station + explicitly listed UIDs |
| `all` | Station + all approved followers |

Followers are deduplicated to one entry per uid. When multiple devices exist for a uid, preference is given to the entry where `device_uid == uid` (the root device).

**Step 5: Create envelopes**
```
envelopes = {}
for each recipient:
    envelopes[recipient.uid] = SealedBox(sym_key, recipient.public_key).hex()
```

The station's self-envelope is always included, sealed to the station's own public key.

**Step 6: Publish envelopes to IPFS**
```json
{
  "v": 1,
  "post_cid": "<ipfs-cid>",
  "envelopes": {
    "<uid-1>": "<160-hex-sealed-box>",
    "<uid-2>": "<160-hex-sealed-box>"
  }
}
```
```
envelopes_cid = ipfs_add_bytes(compact_json(envelopes_doc))
```

**Step 7: Encrypt metadata (optional)**

If the post has associated metadata (caption, filename, etc.), it is encrypted with the same symmetric key:

```
metadata_json = compact_json(metadata_dict)
encrypted_metadata = SecretBox(sym_key).encrypt(metadata_json)
metadata_hex = encrypted_metadata.hex()
```

**Step 8: Append to manifest**

See Section 8.

**Step 9: Publish manifest to IPFS and update pointer**
```
manifest_cid = ipfs_add_bytes(compact_json(manifest))
public.json["manifest_pointer"] = manifest_cid
```

### 7.2 Content Decryption Flow

**For the station (root device):**
1. Load manifest, find post entry by `post_cid`.
2. Fetch envelopes JSON from IPFS using `envelopes_cid`.
3. Look up envelope for own uid.
4. Decrypt envelope with station private key -> recover `sym_key`.
5. Fetch encrypted blob from IPFS using `post_cid`.
6. Decrypt blob with `SecretBox(sym_key)` -> plaintext.

**For a delegate device:**
1. Load manifest from station (via `/profile` -> `manifest_pointer` -> IPFS).
2. Send authenticated `/rewrap` request for the desired `post_cid`.
3. Receive device-specific envelope from station.
4. Decrypt envelope with device private key -> recover `sym_key`.
5. Fetch encrypted blob from IPFS using `post_cid`.
6. Decrypt blob with `SecretBox(sym_key)` -> plaintext.

**For an external follower:**
1. Fetch the station's `public.json` (via their endpoint or IPFS).
2. Fetch manifest from IPFS using `manifest_pointer`.
3. For each post, fetch envelopes JSON using `envelopes_cid`.
4. Look up envelope for own uid.
5. Decrypt envelope with own private key -> recover `sym_key`.
6. Fetch and decrypt the post blob.

---

## 8. Manifest System

### 8.1 Manifest Schema

The manifest is the central index of all published content. It supports multiple application-layer clients within a single document.

```json
{
  "clients": {
    "<client-name>": {
      "posts": [
        {
          "post_cid": "<ipfs-cid>",
          "audience_mode": "self | specific | all",
          "envelopes_cid": "<ipfs-cid>",
          "envelopes_count": 5,
          "metadata": "<hex-encrypted-json>",
          "audience_uids": ["<uid>", "..."]
        }
      ]
    }
  }
}
```

### 8.2 Post Entry Fields

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `post_cid` | MUST | string | IPFS CID of the encrypted content blob |
| `audience_mode` | MUST | string | One of: `"self"`, `"specific"`, `"all"` |
| `envelopes_cid` | MUST | string | IPFS CID of the envelopes JSON document |
| `envelopes_count` | SHOULD | integer | Number of envelopes (informational) |
| `metadata` | MAY | string | Hex-encoded SecretBox ciphertext of client-specific metadata JSON |
| `audience_uids` | MUST if `specific` | string[] | Sorted list of UIDs when `audience_mode` is `"specific"` |

### 8.3 Envelopes JSON Document

Published separately to IPFS. One per post.

```json
{
  "v": 1,
  "post_cid": "<ipfs-cid>",
  "envelopes": {
    "<uid>": "<hex-encoded-sealed-box>"
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `v` | MUST | Schema version. Currently `1`. |
| `post_cid` | MUST | The post this envelope set belongs to |
| `envelopes` | MUST | Map of uid -> hex-encoded SealedBox (160 hex chars for 32-byte key) |

### 8.4 Audience Modes

| Mode | Behavior |
|------|----------|
| `self` | Only the station can decrypt. No follower envelopes are created. The self-envelope is always present. |
| `specific` | The station plus an explicit list of approved follower UIDs. `audience_uids` MUST be present and sorted. |
| `all` | The station plus all followers with `allowed == "Allowed"`. |

### 8.5 Manifest Publishing

When the manifest changes (new post, updated envelopes):

1. Serialize the manifest to compact JSON (`separators=(",", ":")`, `ensure_ascii=False`).
2. Upload to IPFS -> `manifest_cid`.
3. Update `public.json["manifest_pointer"]` to the new CID.

Since IPFS is content-addressed, every manifest change produces a new CID. Previous versions remain available on IPFS as long as they are pinned or cached by peers.

### 8.6 Legacy Manifest Migration

Implementations SHOULD support loading the legacy flat manifest format and normalizing it to the multi-client schema:

**Legacy format:**
```json
{
  "client": "orbitstagram",
  "posts": [...]
}
```

**Normalized to:**
```json
{
  "clients": {
    "orbitstagram": {
      "posts": [...]
    }
  }
}
```

The legacy `audience_mode` value `"all_followers"` MUST be normalized to `"all"`.

---

## 9. Social Graph

### 9.1 Followers (Inbound)

Followers are tracked at the **device level** in the station's local database.

**Schema:**

| Column | Type | Description |
|--------|------|-------------|
| `uid` | TEXT, NOT NULL | Follower's user ID |
| `device_uid` | TEXT, NOT NULL | Follower's device ID |
| `public_key` | TEXT, NOT NULL | Curve25519 public key (64 hex chars) |
| `alias` | TEXT, NULL | Human-readable name |
| `allowed` | TEXT, NOT NULL, DEFAULT "Allowed" | Access status: `"Allowed"` or `"Denied"` |
| `endpoint` | TEXT, NULL | Follower's station URL |

**Primary key:** `(uid, public_key)`

### 9.2 Following (Outbound)

Users the station owner follows.

| Column | Type | Description |
|--------|------|-------------|
| `uid` | TEXT, NOT NULL | Target user's ID |
| `public_key` | TEXT, NOT NULL | Target user's public key |
| `endpoint` | TEXT, NOT NULL | Target user's station URL |
| `alias` | TEXT, NULL | Human-readable name |

**Primary key:** `(uid, public_key)`

### 9.3 Graph Encryption

The follower and following lists are encrypted and published to IPFS for distribution to authorized followers. This uses the same SecretBox scheme as post encryption, with an ephemeral key shared via per-follower envelopes.

**Encrypted followers graph:**
```json
{
  "version": 1,
  "updated_at": "<uuid-hex>",
  "followers": [
    {
      "uid": "<uuid>",
      "public_key": "<64-hex>",
      "device_uid": "<uuid>",
      "alias": "<string | null>",
      "allowed": "Allowed",
      "endpoint": "<url | null>"
    }
  ]
}
```

**Encrypted following graph:**
```json
{
  "version": 1,
  "updated_at": "<uuid-hex>",
  "following": [
    {
      "uid": "<uuid>",
      "public_key": "<64-hex>",
      "endpoint": "<url>"
    }
  ]
}
```

Both are encrypted with a fresh ephemeral SecretBox key, uploaded to IPFS, and their CIDs stored in `public.json`.

### 9.4 Graph Decoder Envelopes

To allow followers to decrypt the social graph, the station creates decoder envelopes. Unlike post envelopes (which are user-level), graph decoder envelopes are **device-level**: each device of each follower gets its own envelope.

```json
{
  "version": 1,
  "envelopes": {
    "<follower-uid>": [
      {
        "device_uid": "<device-uuid>",
        "envelope": "<hex-sealed-box>"
      }
    ]
  }
}
```

This document is published to IPFS (unencrypted JSON, since the envelopes themselves are cryptographically sealed). Its CID is stored in `public.json["follow_decoder_envelopes_cid"]`.

### 9.5 Graph Rebuild

The social graph is rebuilt and re-published whenever the follower or following list changes (follow, unfollow, new device). The rebuild process:

1. Generate a new ephemeral symmetric key.
2. Encrypt the following graph -> upload to IPFS -> `following_cid`.
3. Filter followers to `allowed == "Allowed"` only.
4. Encrypt the followers graph -> upload to IPFS -> `followers_cid`.
5. Create device-level decoder envelopes for all allowed followers -> upload to IPFS -> `follow_decoder_envelopes_cid`.
6. Update `public.json` with all three CIDs.

---

## 10. Device Pairing

### 10.1 Overview

Device pairing allows a delegate device (e.g., a phone) to authenticate with the station and gain access to content via envelope rewrapping. The pairing uses a 6-digit PIN displayed on the station and entered on the delegate device.

### 10.2 Pairing Session

| Field | Type | Description |
|-------|------|-------------|
| `pairing_id` | string | URL-safe random token (18 bytes, base64url) |
| `created_at` | integer | Unix timestamp |
| `expires_at` | integer | Unix timestamp (`created_at + 300`) |
| `device_uid` | string | The delegate device's UUID |
| `device_public_key` | string | The delegate device's Curve25519 public key (64 hex) |
| `salt_hex` | string | 16-byte random salt (32 hex chars) |
| `pin_hash_hex` | string | scrypt hash of PIN (64 hex chars) |
| `attempts` | integer | Failed PIN attempts (max 5) |
| `status` | string | `"pending"` -> `"confirmed"` or `"expired"` or `"locked"` |

### 10.3 PIN Format

- 6 decimal digits, zero-padded: `000000` through `999999`
- Generated using `secrets.randbelow(10^6)`

### 10.4 Pairing Flow

**Step 1: Delegate initiates pairing**

```
POST /delegate/start
Content-Type: application/json

{
  "device_uid": "<uuid>",
  "public_key": "<64-hex-chars>"
}
```

Response:
```json
{
  "status": "ok",
  "pairing_id": "<url-safe-token>",
  "expires_in_seconds": 300
}
```

The station generates a 6-digit PIN, hashes it with scrypt, and displays the PIN to the station operator (e.g., via console, display, or notification).

**Step 2: User communicates PIN to delegate out-of-band**

The station operator reads the PIN and enters it on the delegate device (or tells it to the person holding the device). This is the trust bridge.

**Step 3: Delegate confirms pairing**

```
POST /delegate/confirm
Content-Type: application/json

{
  "pairing_id": "<url-safe-token>",
  "pin": "123456"
}
```

The station:
1. Validates `pairing_id` exists and status is `"pending"`.
2. Checks expiration (MUST be within 300 seconds of creation).
3. Checks attempt count (MUST be < 5).
4. Hashes the submitted PIN with the stored salt using scrypt.
5. Compares against stored hash using constant-time comparison.
6. On success: sets status to `"confirmed"`, registers the device as a follower with `allowed="Allowed"`.
7. On failure: increments attempt count; locks session if attempts >= 5.

Response (success):
```json
{
  "status": "ok",
  "action": "delegate_added",
  "uid": "<station-uid>",
  "device_uid": "<device-uid>"
}
```

---

## 11. Envelope Rewrap Protocol

### 11.1 Purpose

Delegate devices need access to post content, but post envelopes are sealed to the station's public key (user-level keying). The rewrap protocol allows a delegate to request a device-specific envelope from the station.

### 11.2 Request

```
POST /rewrap
Content-Type: application/json
[HMAC Authentication Headers - see Section 12]

{
  "uid": "<user-uuid>",
  "device_uid": "<device-uuid>",
  "post_cid": "<ipfs-cid>",
  "envelopes_cid": "<ipfs-cid>"    // OPTIONAL override
}
```

The `uid` and `device_uid` in the body MUST match the values in the authentication headers.

### 11.3 Server-Side Processing

1. Verify HMAC authentication (see Section 12).
2. Verify header/body uid and device_uid match.
3. Load the manifest and find the post entry matching `post_cid`.
4. Determine `envelopes_cid` (from body override or post entry).
5. Fetch the envelopes JSON from IPFS.
6. Extract the root envelope for the station's uid.
7. Decrypt the root envelope with the station's private key -> recover `sym_key`.
8. Look up the delegate device's public key from the followers database.
9. Re-encrypt `sym_key` with the device's public key -> new SealedBox envelope.
10. Return the device-specific envelope.

### 11.4 Response

**Success:**
```json
{
  "status": "ok",
  "result": {
    "status": "rewrap_ok",
    "uid": "<user-uuid>",
    "device_uid": "<device-uuid>",
    "post_cid": "<ipfs-cid>",
    "envelope": "<160-hex-sealed-box>"
  }
}
```

**Error:**
```json
{
  "status": "ok",
  "result": {
    "error": "<error-description>"
  }
}
```

### 11.5 Security Requirements

- The delegate device MUST be registered in the followers table with `allowed == "Allowed"`.
- The request MUST pass HMAC authentication.
- The station MUST NOT return envelopes for devices that are not authorized.

---

## 12. Authentication Scheme

### 12.1 Overview

Authenticated endpoints use HMAC-SHA256 signatures derived from a shared secret between the station and the delegate device. This provides mutual authentication (only paired devices can compute valid signatures) and request integrity.

### 12.2 Key Derivation

```
shared_secret = X25519(station_private_key, device_public_key)    # 32 bytes
auth_key = BLAKE2b(shared_secret, digest_size=32, person=b"orbit-auth")  # 32 bytes
```

Both station and delegate can independently compute the same `auth_key`.

### 12.3 Canonical String

The signed message is constructed by joining the following fields with newline (`\n`) separators:

```
METHOD\nPATH\nUID\nDEVICE_UID\nTIMESTAMP\nNONCE\nBODY_SHA256
```

| Component | Format | Example |
|-----------|--------|---------|
| METHOD | Uppercase HTTP method | `POST` |
| PATH | Request path (no query string) | `/rewrap` |
| UID | User UUID string | `52dd6e1a-...` |
| DEVICE_UID | Device UUID string | `a1b2c3d4-...` |
| TIMESTAMP | Unix epoch seconds (decimal string) | `1704067200` |
| NONCE | Random hex string (SHOULD be >= 16 bytes / 32 hex chars) | `a3f2...` |
| BODY_SHA256 | Lowercase hex SHA-256 of the raw request body | `e3b0c442...` |

The canonical string is UTF-8 encoded before HMAC computation.

### 12.4 HMAC Computation

```
signature = HMAC-SHA256(auth_key, canonical_string_bytes)
```

The signature is hex-encoded (lowercase) for transmission.

### 12.5 HTTP Headers

Authenticated requests MUST include the following headers:

| Header | Value |
|--------|-------|
| `x-orbit-uid` | User UUID |
| `x-orbit-device` | Device UUID |
| `x-orbit-ts` | Unix timestamp (seconds) |
| `x-orbit-nonce` | Random hex string |
| `x-orbit-body-sha256` | Lowercase hex SHA-256 of request body |
| `x-orbit-hmac` | Lowercase hex HMAC-SHA256 signature |

### 12.6 Server Verification

The station verifies authenticated requests in this order:

1. **Time window:** `|now - timestamp| <= 60` seconds. Reject if stale.
2. **Device authorization:** Look up device in followers table. MUST have `allowed == "Allowed"`.
3. **Replay protection:** Check nonce against the nonce table. Reject if seen before.
4. **Body integrity:** If the middleware captured a body SHA-256, compare against the header value (constant-time).
5. **HMAC verification:** Derive auth_key, compute expected HMAC, compare against header value (constant-time).
6. **Record nonce:** Store the nonce in the database to prevent replay.

**Error responses:**

| Condition | HTTP Status | Detail |
|-----------|-------------|--------|
| Bad timestamp format | 401 | `"bad timestamp"` |
| Stale request | 401 | `"stale request"` |
| Device not found/allowed | 403 | `"device not authorized"` |
| Nonce replay | 401 | `"replay"` |
| Body hash mismatch | 401 | `"bad body hash"` |
| HMAC mismatch | 401 | `"bad auth"` |

### 12.7 Nonce Management

- Nonces are stored per (uid, device_uid, nonce) triple.
- Nonce TTL: 24 hours. Expired nonces are periodically cleaned up.
- Nonces MUST be unique per device per time window.

---

## 13. Inbox & Follow Requests

### 13.1 Follow Request (Multi-Device)

External users send follow requests to a station's inbox to request access to content.

```
POST /inbox
Content-Type: application/json

{
  "type": "follow_request",
  "uid": "<follower-uuid>",
  "devices": [
    {
      "device_uid": "<device-uuid>",
      "public_key": "<64-hex-chars>"
    }
  ]
}
```

**Processing:**
1. Validate that the follower uid is not the station's own uid (prevents self-injection).
2. Validate each device entry has a valid `device_uid` and 64-hex-char `public_key`.
3. Check device cap: max 20 devices per follower (configurable via `ORBIT_MAX_DEVICES_PER_FOLLOWER`).
4. Register each device in the followers table.
5. If any new devices were added or keys rotated, optionally trigger envelope rewrap for all existing posts.

**Response:**
```json
{
  "status": "ok",
  "result": {
    "status": "follow_accepted_multi_device",
    "rewrap_triggered": true
  }
}
```

### 13.2 Follow Request (Legacy Single-Device)

```json
{
  "type": "follow_request",
  "uid": "<follower-uuid>",
  "public_key": "<64-hex-chars>"
}
```

The uid is used as both uid and device_uid. Behaves the same as multi-device with a single entry.

### 13.3 Auto-Rewrap on Follow Change

When a new follower is accepted (or an existing follower's key changes), the station MAY automatically rewrap all post envelopes to include the new follower. This is controlled by the `ORBIT_AUTO_REWRAP_ON_FOLLOW_CHANGE` environment variable (default: enabled).

The rewrap process:
1. For each post in the manifest:
   a. Decrypt the root envelope -> recover `sym_key`.
   b. Rebuild the envelope map including the new follower.
   c. Publish updated envelopes JSON to IPFS -> new `envelopes_cid`.
   d. Update the post entry in the manifest.
2. Publish the updated manifest to IPFS.
3. Update `public.json["manifest_pointer"]`.

### 13.4 Follow Request Authentication

The `POST /inbox` endpoint does NOT require HMAC authentication for `follow_request` messages. This allows external users to send follow requests without prior key exchange. All other inbox message types MUST be authenticated.

### 13.5 Future Inbox Message Types

The following message types are reserved for future use:
- `post_key_update` — notification that post envelopes have been updated
- `manifest_update` — notification that the manifest has changed

---

## 14. API Reference

### 14.1 Public Endpoints

#### `GET /profile`

Returns the station's public identity document.

**Authentication:** None

**Response:** `public.json` contents (see Section 5.3)

### 14.2 Unauthenticated Endpoints

#### `POST /inbox`

Receives inbox messages. Unauthenticated for `follow_request` type; authenticated for all others.

**Request body:** `InboxMessage` (see Section 13)

### 14.3 Authenticated Endpoints

All authenticated endpoints require HMAC headers (Section 12.5).

#### `POST /post`

Create a new encrypted post.

**Content-Type:** `multipart/form-data`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file` | binary | MUST | Raw file content to encrypt |
| `metadata` | string (JSON) | MAY | Client-specific metadata JSON string |

**Response:**
```json
{
  "status": "post_ok",
  "cid": "<post-ipfs-cid>",
  "envelopes_cid": "<envelopes-ipfs-cid>",
  "audience_mode": "all",
  "audience_uids": null,
  "followers_raw": 5,
  "followers_used": 5,
  "manifest_posts": 4
}
```

#### `POST /rewrap`

Request an envelope rewrap for a delegate device. See Section 11.

#### `POST /follow`

Add an outbound follow (the station owner starts following another user).

**Request body:**
```json
{
  "uid": "<target-uuid>",
  "endpoint": "<target-station-url>",
  "public_key": "<target-64-hex>"
}
```

Triggers a social graph rebuild (Section 9.5).

#### `POST /unfollow`

Remove an outbound follow.

**Request body:**
```json
{
  "uid": "<target-uuid>",
  "public_key": "<target-64-hex>"
}
```

Triggers a social graph rebuild.

### 14.4 Pairing Endpoints

#### `POST /delegate/start`

Initiate device pairing. See Section 10.4, Step 1.

**Authentication:** None

#### `POST /delegate/confirm`

Confirm device pairing with PIN. See Section 10.4, Step 3.

**Authentication:** None

---

## 15. Message Flows

### 15.1 Post Creation (Station)

```
Station                         IPFS
  |                               |
  |  1. Generate sym_key (32B)    |
  |  2. Encrypt content           |
  |  3. Upload encrypted blob --->|---> post_cid
  |  4. Build per-uid envelopes   |
  |  5. Upload envelopes JSON --->|---> envelopes_cid
  |  6. Update manifest           |
  |  7. Upload manifest --------->|---> manifest_cid
  |  8. Update public.json        |
  |                               |
```

### 15.2 Content Retrieval (Delegate)

```
Delegate                    Station                     IPFS
  |                           |                           |
  |  1. GET /profile -------->|                           |
  |  <-- public.json ---------|                           |
  |                           |                           |
  |  2. Fetch manifest ---------------------------------->|
  |  <-- manifest JSON -----------------------------------|
  |                           |                           |
  |  3. POST /rewrap -------->|                           |
  |     (authenticated)       |  4. Fetch envelopes ----->|
  |                           |  <-- envelopes JSON ------|
  |                           |  5. Decrypt root envelope |
  |                           |  6. Re-encrypt for device |
  |  <-- device envelope -----|                           |
  |                           |                           |
  |  7. Decrypt envelope      |                           |
  |     -> sym_key            |                           |
  |  8. Fetch post blob --------------------------------->|
  |  <-- encrypted blob ----------------------------------|
  |  9. Decrypt with sym_key  |                           |
  |     -> plaintext          |                           |
```

### 15.3 Follower Enrollment

```
Follower                    Station
  |                           |
  |  1. POST /inbox           |
  |     {type: follow_request |
  |      uid, devices}        |
  |  ----------------------->|
  |                           |  2. Validate uid != self
  |                           |  3. Check device cap
  |                           |  4. Register devices
  |                           |  5. Rewrap all posts (optional)
  |                           |  6. Rebuild social graph
  |  <-- follow_accepted -----|
  |                           |
```

### 15.4 Device Pairing

```
Delegate                    Station                     Operator
  |                           |                           |
  |  1. POST /delegate/start  |                           |
  |     {device_uid, pk}      |                           |
  |  ----------------------->|                            |
  |                           |  2. Generate PIN           |
  |                           |  3. Hash PIN (scrypt)      |
  |                           |  4. Store session          |
  |  <-- {pairing_id} --------|  5. Display PIN ---------->|
  |                           |                           |
  |                           |        6. Out-of-band     |
  |  <------- PIN communicated via voice/display ---------|
  |                           |                           |
  |  7. POST /delegate/confirm|                           |
  |     {pairing_id, pin}     |                           |
  |  ----------------------->|                            |
  |                           |  8. Verify PIN             |
  |                           |  9. Register device        |
  |  <-- {delegate_added} ----|                           |
```

### 15.5 External Follower Content Retrieval

```
Follower                                            IPFS
  |                                                   |
  |  1. Fetch station's public.json (via endpoint) -->|
  |  <-- public.json ----------------------------------|
  |                                                   |
  |  2. Fetch manifest (manifest_pointer) ----------->|
  |  <-- manifest JSON --------------------------------|
  |                                                   |
  |  3. For each post of interest:                    |
  |     a. Fetch envelopes (envelopes_cid) ---------->|
  |     <-- envelopes JSON ----------------------------|
  |     b. Find envelope for own uid                  |
  |     c. Decrypt envelope -> sym_key                |
  |     d. Fetch post blob (post_cid) --------------->|
  |     <-- encrypted blob ----------------------------|
  |     e. Decrypt blob -> plaintext                  |
  |     f. If metadata present: decrypt metadata      |
```

---

## 16. Client Extension Model

### 16.1 Overview

The Orbit protocol is designed to support multiple application-layer clients sharing the same identity, encryption, and access-control infrastructure. Each client defines its own namespace within the manifest and its own metadata schema.

### 16.2 Adding a New Client

To add a new client type:

1. Choose a unique client name (lowercase, alphanumeric + hyphens recommended).
2. Define a metadata schema for your client's post type.
3. When creating posts, specify your client name so entries are placed under `manifest["clients"]["<your-client>"]`.
4. Encrypt metadata using the same per-post symmetric key.

### 16.3 Required vs. Client-Specific Fields

**Required fields** (all clients MUST include these in each post entry):

| Field | Description |
|-------|-------------|
| `post_cid` | IPFS CID of encrypted content |
| `audience_mode` | Access control mode |
| `envelopes_cid` | IPFS CID of envelopes document |

**Client-specific fields** (carried in the encrypted `metadata` blob):

Each client defines its own JSON schema for metadata. The metadata is encrypted with the same symmetric key as the post content, so only authorized recipients can read it.

### 16.4 Example Client Schemas

**orbitstagram** (photo/video sharing):
```json
{
  "caption": "Sunset at the beach",
  "timestamp": 1704067200,
  "location": {"lat": 37.7749, "lon": -122.4194},
  "content_type": "image/jpeg",
  "width": 1920,
  "height": 1080
}
```

**orbitdrive** (file storage):
```json
{
  "filename": "report.pdf",
  "mime_type": "application/pdf",
  "size_bytes": 1048576,
  "created_at": 1704067200,
  "modified_at": 1704070800,
  "path": "/documents/work/"
}
```

**orbitdocs** (document collaboration):
```json
{
  "title": "Project Proposal",
  "version": 3,
  "authors": ["alice", "bob"],
  "format": "markdown",
  "word_count": 2450
}
```

### 16.5 Client Naming Conventions

- Client names SHOULD be lowercase and use only `[a-z0-9-]`.
- To avoid collisions, third-party clients SHOULD use a namespaced format: `orgname-clienttype` (e.g., `acme-photos`).
- The names `default`, `orbit`, and `system` are RESERVED.

### 16.6 Client Versioning

Clients MAY add a `version` field to their namespace object:

```json
{
  "clients": {
    "orbitdrive": {
      "version": 2,
      "posts": [...]
    }
  }
}
```

Clients SHOULD handle older versions gracefully by migrating data in-memory when reading.

---

## 17. Security Considerations

### 17.1 Threat Model

The Orbit protocol is designed to protect against:

- **Passive network observers:** All content is encrypted before leaving the station. IPFS peers see only encrypted blobs.
- **Compromised IPFS nodes:** Content is encrypted at rest. CIDs reveal content existence but not content.
- **Unauthorized followers:** Only approved followers with valid envelopes can decrypt content.

The protocol does NOT protect against:

- **Compromised station:** If the station's private key is compromised, all past and future content is exposed.
- **Compromised recipient:** A follower who has decrypted content can redistribute it.
- **Traffic analysis:** Post timing, frequency, and blob sizes are visible to IPFS peers.

### 17.2 Forward Secrecy

Each post uses a fresh random 32-byte symmetric key. Compromising one post's key does not reveal other posts' content. However, the station's root private key can decrypt all post envelopes (since the self-envelope is always present), so forward secrecy is bounded by the root key's integrity.

### 17.3 Metadata Privacy

- **Encrypted metadata:** Post metadata (captions, filenames, etc.) is encrypted with the same key as the post content. Only authorized recipients can read it.
- **Manifest visibility:** The manifest itself is published to IPFS unencrypted. This reveals: number of posts, audience modes, number of envelopes per post, and post CIDs. Implementations concerned about this SHOULD consider encrypting the manifest.
- **Social graph encryption:** Follower and following lists are encrypted before IPFS publication.

### 17.4 Device Revocation

To revoke a delegate device's access:

1. Set the device's `allowed` status to `"Denied"` in the followers table.
2. Rebuild all post envelopes excluding the revoked device's user-level envelope (if this was their only device).
3. Republish the manifest.
4. Rebuild and republish the social graph.

Note: The revoked device may still have cached decryption keys for previously-accessed posts. Revocation only prevents access to future posts and future rewrap requests.

### 17.5 Rate Limiting

- **PIN attempts:** Device pairing is limited to 5 PIN attempts per session.
- **Device cap:** Each follower is limited to 20 devices (configurable).
- **Time window:** Authentication requests must be within 60 seconds of current time.

### 17.6 Self-UID Injection Prevention

Follow requests targeting the station's own uid MUST be rejected. This prevents an attacker from registering a device under the station owner's uid, which could grant unintended access to the self-envelope.

---

## 18. IPFS Integration

### 18.1 IPFS Daemon

The station MUST run a local IPFS daemon (e.g., Kubo) with the HTTP API enabled on port 5001 (default).

### 18.2 API Operations

**Upload content:**
```
POST http://127.0.0.1:5001/api/v0/add
Content-Type: multipart/form-data

file=<binary-data>
```

Response includes `"Hash"` field containing the CID.

**Fetch content:**
```
POST http://127.0.0.1:5001/api/v0/cat?arg=<CID>
```

Response body contains the raw bytes.

### 18.3 Pinning

The station SHOULD pin all CIDs it publishes to ensure content remains available. This includes:
- Post blobs (`post_cid`)
- Envelopes documents (`envelopes_cid`)
- Manifest versions (`manifest_pointer`)
- Encrypted social graphs (`followers_cid`, `following_cid`, `follow_decoder_envelopes_cid`)

Old manifest versions and superseded envelope documents MAY be unpinned to reclaim storage.

### 18.4 Content Addressing

IPFS uses content-based addressing: the CID is a cryptographic hash of the content. This provides:
- **Integrity:** Content at a CID always matches the expected hash.
- **Deduplication:** Identical content produces the same CID.
- **Immutability:** Published content cannot be altered without changing the CID.

---

## 19. Backward Compatibility

### 19.1 Manifest Format

Implementations MUST accept both the legacy flat format and the current multi-client format, normalizing to multi-client on read (see Section 8.6).

### 19.2 Audience Mode

The legacy value `"all_followers"` MUST be normalized to `"all"` on read.

### 19.3 Envelope Encoding

The current format uses hex encoding. Legacy implementations that produced base64-encoded envelopes SHOULD be supported for reading. New envelopes MUST be hex-encoded.

### 19.4 Post CID Field

Legacy manifests used `"cid"` instead of `"post_cid"`. Implementations MUST check both field names.

---

## 20. Future Work

- **Content deletion/expiry:** Mechanism for removing posts and notifying followers to discard cached keys.
- **Manifest sharding:** For stations with large post counts, split the manifest into paginated segments.
- **Federation/discovery:** DNS-based or relay-based discovery of stations; cross-station search.
- **Key rotation:** Formal protocol for rotating the station's root keypair while maintaining access to historical content.
- **Manifest encryption:** Option to encrypt the manifest itself, hiding post metadata from unauthorized IPFS observers.
- **Streaming/chunked uploads:** Support for large files via IPFS UnixFS chunking with per-chunk encryption.

---

## Appendix A: Database Schema

```sql
CREATE TABLE followers (
    uid TEXT NOT NULL,
    public_key TEXT NOT NULL,
    device_uid TEXT NOT NULL,
    alias TEXT NULL,
    allowed TEXT NOT NULL DEFAULT 'Allowed',
    endpoint TEXT NULL,
    PRIMARY KEY (uid, public_key)
);

CREATE TABLE following (
    uid TEXT NOT NULL,
    public_key TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    alias TEXT NULL,
    PRIMARY KEY (uid, public_key)
);

CREATE TABLE auth_nonces (
    uid TEXT NOT NULL,
    device_uid TEXT NOT NULL,
    nonce TEXT NOT NULL,
    ts INTEGER NOT NULL,
    PRIMARY KEY (uid, device_uid, nonce)
);

CREATE TABLE pairing_sessions (
    pairing_id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    device_uid TEXT NOT NULL,
    device_public_key TEXT NOT NULL,
    salt_hex TEXT NOT NULL,
    pin_hash_hex TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending'
);
```

---

## Appendix B: Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `IPFS_API` | `http://127.0.0.1:5001` | IPFS daemon HTTP API URL |
| `BASE_DIR` | `./orbit_data` | Root directory for station data |
| `ORBIT_MAX_DEVICES_PER_FOLLOWER` | `20` | Maximum devices per follower uid |
| `ORBIT_AUTO_REWRAP_ON_FOLLOW_CHANGE` | `1` | Enable auto-rewrap when followers change (`0` to disable) |
| `MAX_SKEW_SECONDS` | `60` | Maximum clock skew for authenticated requests |
| `NONCE_TTL_SECONDS` | `86400` | How long to retain nonces (24 hours) |
| `PIN_LEN` | `6` | Length of pairing PIN |
| `TTL_SECONDS` (pairing)| `300` | Pairing session timeout (5 minutes) |
| `MAX_ATTEMPTS` (pairing)| `5` | Maximum PIN attempts per session |

---

## Appendix C: References

- **NaCl / libsodium:** https://doc.libsodium.org/
- **PyNaCl:** https://pynacl.readthedocs.io/
- **IPFS:** https://docs.ipfs.tech/
- **Curve25519:** https://cr.yp.to/ecdh.html
- **XSalsa20-Poly1305:** https://doc.libsodium.org/secret-key_cryptography/aead
- **SealedBox:** https://doc.libsodium.org/public-key_cryptography/sealed_boxes
- **Argon2:** RFC 9106
- **BLAKE2:** RFC 7693
- **HMAC:** RFC 2104
- **scrypt:** RFC 7914
- **UUID v4:** RFC 9562
- **RFC 2119 Keywords:** RFC 2119
