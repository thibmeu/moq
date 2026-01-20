# moq-relay

**moq-relay** is a server that forwards subscriptions from publishers to subscribers, caching and deduplicating along the way.
It's designed to be run in a datacenter, relaying media across multiple hops to deduplicate and improve QoS.

The only argument is the path to a TOML configuration file.
See [relay.toml](../dev/relay.toml) for an example configuration.

## HTTP
Primarily for debugging, you can also connect to the relay via HTTP.

-  `GET /certificate.sha256`: Returns the fingerprint of the TLS certificate.
-  `GET /announced/*prefix`: Returns all of the announced tracks with the given (optional) prefix.
-  `GET /fetch/*path`: Returns the latest group of the given track.

The HTTP server listens on the same bind address, but TCP instead of UDP.
The default is `http://localhost:4443`.
HTTPS is currently not supported.

## Clustering
In order to scale MoQ, you will eventually need to run multiple moq-relay instances potentially in different regions.
This is called *clustering*, where the goal is that a user connects to the closest relay and they magically form a mesh behind the scenes.

**moq-relay** uses a simple clustering scheme using moq-lite.
This is both dog-fooding and a surprisingly ueeful way to distribute live metadata at scale.

We currently use a single "root" node that is used to discover members of the cluster and what broadcasts they offer.
This is a normal moq-relay instance, potentially serving public traffic, unaware of the fact that it's in charge of other relays.

The other moq-relay instances accept internet traffic and consult the root for routing.
They can then advertise their internal ip/hostname to other instances when publishing a broadcast.

Cluster arguments:

-   `--cluster-root <HOST>`: The hostname/ip of the root node. If missing, this node is a root.
-   `--cluster-node <HOST>`: The hostname/ip of this instance. There needs to be a corresponding valid TLS certificate, potentially self-signed. If missing, published broadcasts will only be available on this specific relay.

## Authentication

The relay supports two authentication methods:

1. **JWT tokens** - Traditional signed tokens via URL query parameters
2. **Privacy Pass** - Privacy-preserving tokens via [draft-ietf-moq-privacy-pass-auth](https://datatracker.ietf.org/doc/draft-ietf-moq-privacy-pass-auth/)

For detailed JWT setup, see: **[Authentication Documentation](../../doc/concepts/authentication.md)**

### JWT Authentication
```toml
[auth]
key = "dev/root.jwk"    # JWT signing key
public = "anon"         # Allow anonymous access to /anon prefix
```

### Privacy Pass Authentication

Privacy Pass provides unlinkable tokens for privacy-preserving authorization.
Clients connect, get rejected with a TokenChallenge, acquire a token from an issuer, then reconnect.

**Quick Test** (uses Cloudflare's demo issuer - no attestation required):

```bash
# Terminal 1: Start relay with Privacy Pass enabled
cargo run -p moq-relay -- \
  --pp-enabled \
  --tls-generate=localhost \
  --server-bind=127.0.0.1:4443

# Terminal 2: Run the example client
cargo run -p moq-native --example pp_client -- \
  https://127.0.0.1:4443/test/room
```

The client will:
1. Connect without token → rejected with `TokenChallenge`
2. Parse challenge to get issuer (`demo-pat.issuer.cloudflare.com`)
3. Request token from issuer
4. Reconnect with token → session established

**Configuration:**
```toml
[privacypass]
enabled = true
# Optional: custom issuer (defaults to Cloudflare demo)
# issuer = "your-issuer.example.com"
# issuer_key = "path/to/issuer-public-key.pem"
```

**CLI flags:**
- `--pp-enabled` - Enable Privacy Pass authentication
- `--pp-issuer <HOST>` - Custom issuer hostname
- `--pp-issuer-key <PATH>` - Path to issuer's public key (SPKI format)
