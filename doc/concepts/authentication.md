# Authentication

[moq-relay](/rust/moq-relay) supports two authentication methods:
1. **JWT tokens** in the URL for traditional authentication
2. **Privacy Pass** for privacy-preserving authentication ([draft-ietf-moq-privacy-pass-auth](https://datatracker.ietf.org/doc/draft-ietf-moq-privacy-pass-auth/))

Note that this authentication only applies when using the relay.
The application is responsible for authentication when using [moq-lite](/rust/moq-lite) directly.


## Overview

The authentication system supports:
- **JWT-based authentication** with query parameter tokens
- **Privacy Pass authentication** with unlinkable tokens (RFC 9577)
- **Path-based authorization** with hierarchical permissions
- **Symmetric key cryptography** (HMAC-SHA256/384/512)
- **Asymmetric key cryptography** (RSASSA-PKCS1-SHA256/384/512, RSASSA-PSS-SHA256/384/512, ECDSA-SHA256/384, EdDSA)
- **Anonymous access** for public content
- **Cluster authentication** for relay-to-relay communication

## Usage

## Anonymous Access
If you don't care about security, anonymous access is supported.
The relay can be configured with a single public prefix, usually "anon".
This is obviously not recommended in production especially because broadcast paths are not unique and can be hijacked.

**Example URL**: `https://cdn.moq.dev/anon`

**Example Configuration:**
```toml
# relay.toml
[auth]
public = "anon"  # Allow anonymous access to anon/**
key = "root.jwk" # Require a token for all other paths
```

If you really, really just don't care, then you can allow all paths.

**Fully Unauthenticated**
```toml
# relay.toml
[auth]
public = ""  # Allow anonymous access to everything
```

And if you want to require an auth token, you can omit the `public` field entirely.
**Fully Authenticated**
```toml
# relay.toml
[auth]
key = "root.jwk" # Require a token for all paths
```


### Authenticated Tokens
An token can be passed via the `?jwt=` query parameter in the connection URL:

**Example URL**: `https://cdn.moq.dev/demo?jwt=<base64-jwt-token>`

**WARNING**: These tokens are only as secure as the delivery.
Make sure that any secrets are securely transmitted (ex. via HTTPS) and stored (ex. secrets manager).
Avoid logging this query parameter if possible; we'll switch to an `Authentication` header once WebTransport supports it.

The token contains permissions that apply to the session.
It can also be used to prevent publishing (read-only) or subscribing (write-only) on a per-path basis.

**Example Token (unsigned)**
```json
{
  "root": "room/123",  // Root path for all operations
  "pub": "alice",      // Publishing permissions (optional)
  "sub": "",           // Subscription permissions (optional)
  "cluster": false,    // Cluster node flag
  "exp": 1703980800,   // Expiration (unix timestamp)
  "iat": 1703977200    // Issued at (unix timestamp)
}
```

This token allows:
- ✅ Connect to `https://cdn.moq.dev/room/123`
- ❌ Connect to: `https://cdn.moq.dev/secret` (wrong root)
- ✅ Publish to `alice/camera`
- ❌ Publish to: `bob/camera` (only alice)
- ✅ Subscribe to `bob/screen`
- ❌ Subscribe to: `../secret` (scope enforced)

A token may omit either the `pub` or `sub` field to make a read-only or write-only token respectively.
An empty string means no restrictions.

Note that there are implicit `/` delimiters added when joining paths (except for empty strings).
Leading and trailing slashes are ignored within a token.

All subscriptions and announcements are relative to the connection URL.
These would all resolves to the same broadcast:
- `CONNECT https://cdn.moq.dev/room/123` could `SUBSCRIBE alice`.
- `CONNECT https://cdn.moq.dev/room` could `SUBSCRIBE 123/alice`.
- `CONNECT https://cdn.moq.dev` could `SUBSCRIBE room/123/alice`.


The connection URL must contain the root path within the token.
It's possible use a more specific path, potentially losing permissions in the process.

Our example token from above:
- 🔴 Connect to `http://cdn.moq.dev/room` (must contain room/123)
- 🟢 Connect to `http://cdn.moq.dev/room/123`
- 🟡 Connect to `http://cdn.moq.dev/room/123/alice` (can't subscribe to `bob`)
- 🟡 Connect to `http://cdn.moq.dev/room/123/bob` (can't publish to `alice`)


### Generating Tokens

`moq-token` is available as a Rust crate ([docs.rs](https://docs.rs/moq-token)), JS library ([@moq/token](https://www.npmjs.com/package/@moq/token)), and CLI.
This documentation focuses on the CLI but the same concepts apply to all.

**Installation**:
```bash
# Install the `moq-token` binary
cargo install moq-token-cli
```

**Generate a key**:
```bash
moq-token --key "root.jwk" generate
```

**Sign a token**:
```bash
moq-token --key "root.jwk" sign \
  --root "rooms/meeting-123" \
  --subscribe "" \
  --publish "alice" \
  --expires 1703980800 > "alice.jwt"
```


And of course, the relay has to be configured with the same key to verify tokens.
We currently only support symmetric keys.

**Example Configuration:**
```toml
# config.toml
[auth]
key = "root.jwk" # Path to the key we generated.
```


## Privacy Pass Authentication

Privacy Pass provides privacy-preserving authorization using unlinkable tokens per [RFC 9577](https://www.rfc-editor.org/rfc/rfc9577.html).
Unlike JWT, tokens cannot be linked across sessions, providing better privacy for users.

### How It Works

```
Client                     Relay                        Issuer
   |                         |                            |
   |-- SETUP (no token) ---->|                            |
   |<-- 0x2 + TokenChallenge |                            |
   |                         |                            |
   |-- POST /token-request ----------------------->|
   |<-- TokenResponse -----------------------------|
   |                         |                            |
   |-- SETUP + Token ------->|                            |
   |<-- SETUP OK ------------|                            |
```

1. Client connects without a token
2. Relay rejects with `0x2 Unauthorized` + serialized `TokenChallenge`
3. Client extracts issuer name from challenge
4. Client requests token from issuer
5. Client reconnects with token in SETUP `AuthorizationToken` parameter

### Quick Test

Uses Cloudflare's demo issuer (`demo-pat.issuer.cloudflare.com`) which requires no attestation:

```bash
# Terminal 1: Start relay with Privacy Pass
cargo run -p moq-relay -- \
  --pp-enabled \
  --tls-generate=localhost \
  --server-bind=127.0.0.1:4443

# Terminal 2: Run the Privacy Pass client example
cargo run -p moq-native --example pp_client -- \
  https://127.0.0.1:4443/test/room
```

Expected output:
```
INFO  pp_client: Privacy Pass MoQ Client
INFO  pp_client: Step 1: Connect without token (expect rejection)
INFO  pp_client:   Got TokenChallenge from issuer: demo-pat.issuer.cloudflare.com
INFO  pp_client: Step 2: Request token from issuer
INFO  pp_client:   Got token: 357 bytes
INFO  pp_client: Step 3: Reconnect with Privacy Pass token
INFO  pp_client: Connected! Session established with Privacy Pass auth
INFO  pp_client: Session stayed alive for 5 seconds, closing...
```

### Configuration

**CLI flags:**
```bash
--pp-enabled              # Enable Privacy Pass authentication
--pp-issuer <HOST>        # Custom issuer hostname (default: demo-pat.issuer.cloudflare.com)
--pp-issuer-key <PATH>    # Path to issuer's public key (SPKI format, base64)
```

**TOML configuration:**
```toml
[privacypass]
enabled = true
# issuer = "your-issuer.example.com"      # Optional custom issuer
# issuer_key = "path/to/issuer-key.pem"   # Optional: load key from file
```

### Token Types

Currently supports publicly verifiable tokens (type `0x0002`, Blind RSA 2048-bit) per [RFC 9578](https://www.rfc-editor.org/rfc/rfc9578.html).

### Combining with JWT

Privacy Pass and JWT can coexist. The relay checks:
1. JWT in URL query parameter (`?jwt=...`)
2. Privacy Pass token in SETUP `AuthorizationToken` parameter
3. Falls back to public path if configured

```toml
[auth]
key = "root.jwk"      # JWT key for traditional auth
public = "anon"       # Public prefix

[privacypass]
enabled = true        # Also accept Privacy Pass tokens
```
