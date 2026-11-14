# tuic-client

Minimalistic TUIC client implementation as a reference

[![Version](https://img.shields.io/crates/v/tuic-client.svg?style=flat)](https://crates.io/crates/tuic-client)
[![License](https://img.shields.io/crates/l/tuic-client.svg?style=flat)](https://github.com/Itsusinn/tuic/blob/dev/LICENSE)

# Overview

The main goal of this TUIC client implementation is not to provide a full-featured, production-ready TUIC client, but to provide a minimal reference for the TUIC protocol client implementation.

This implementation only contains the most basic requirements of a functional TUIC protocol client. If you are looking for features like HTTP-inbound, load-balancing, etc., try other implementations, or implement them yourself.

## Usage

Download the latest binary from [releases](https://github.com/Itsusinn/tuic/releases).

Run the TUIC client with configuration file:

```bash
tuic-client -c PATH/TO/CONFIG
```

## Configuration

The client supports both JSON5 and TOML configuration formats:
- **TOML format**: Use `.toml` file extension (recommended for new configurations)
- **JSON5 format**: Use `.json` or `.json5` file extension (legacy format, still supported)
- **Yaml format**: Use `.yaml` or `.yml` file extension

The format is automatically detected based on the file extension. You can also force TOML parsing by setting the `TUIC_FORCE_TOML` environment variable. Or use `TUIC_CONFIG_FORMAT` environment variable to explicitly specify the format (`toml` or `json5`).

```

### TOML Configuration Example

```toml
# TUIC Client Configuration (TOML format)

log_level = "info"

[relay]
# Server address (hostname:port or IP:port)
server = "example.com:443"

# User UUID
uuid = "00000000-0000-0000-0000-000000000000"

# User password
password = "your_password_here"

# Optional: Bind IP address for outgoing connections
# ip = "192.168.1.100"

# IP stack preference: "v4first" (prefer IPv4), "v6first" (prefer IPv6), 
# "v4only" (IPv4 only), "v6only" (IPv6 only)
# Legacy aliases: "v4", "v6", "v4v6", "v6v4", "prefer_v4", "prefer_v6", "only_v4", "only_v6"
ipstack_prefer = "v4first"

# Optional: Custom certificate paths for server verification
# certificates = ["/path/to/cert.pem"]

# UDP relay mode: "native" or "quic"
udp_relay_mode = "native"

# Congestion control algorithm: "cubic", "new_reno", "bbr", "bbr3"
congestion_control = "cubic"

# ALPN protocols (e.g., ["h3", "h2"])
alpn = []

# Enable 0-RTT handshake
zero_rtt_handshake = false

# Disable SNI (Server Name Indication)
disable_sni = false

# Optional: Override SNI (Server Name Indication) hostname
# Use this to specify a custom SNI that differs from the server hostname
# sni = "custom.example.com"

# Connection timeout
timeout = "8s"

# Startup behavior:
# "eager" -> connect on startup, exit on failure
# "lazy"  -> (default) connect on first incoming SOCKS5/forward request, exit on failure
# "loop"  -> connect on first incoming request, retry forever until success
startup_mode = "lazy"

# Heartbeat interval
heartbeat = "3s"

# Disable native certificate store
disable_native_certs = false

# QUIC send window size (bytes)
send_window = 16777216

# QUIC connection-wide receive window size (bytes).
# A single stream may use at most 4/5 of this window, leaving 1/5 headroom
# for other streams; the total across all streams is capped by this value.
receive_window = 8388608

# Initial MTU
initial_mtu = 1200

# Minimum MTU
min_mtu = 1200

# Enable Generic Segmentation Offload (GSO)
gso = true

# Enable Path MTU Discovery
pmtu = true

# Garbage collection interval
gc_interval = "3s"

# Garbage collection lifetime
gc_lifetime = "15s"

# Skip certificate verification (insecure, use only for testing)
skip_cert_verify = false

[local]
# Local SOCKS5 server address
server = "127.0.0.1:1080"

# Optimistically acknowledge SOCKS5 CONNECT before relay setup (default: true)
optimistic_open = true

# Optional: SOCKS5 authentication username
# username = "socks_user"

# Optional: SOCKS5 authentication password
# password = "socks_pass"

# Enable dual stack (IPv4 and IPv6)
dual_stack = true

# Maximum UDP packet size
max_packet_size = 1500

# TCP port forwarding rules
# [[local.tcp_forward]]
# listen = "127.0.0.1:8080"
# remote = "example.com:80"

# UDP port forwarding rules
# [[local.udp_forward]]
# listen = "127.0.0.1:5353"
# remote = "8.8.8.8:53"
# timeout = "60s"
```

## License

GNU General Public License v3.0

### Optimistic Open (optimistic acknowledgement)

`local.optimistic_open` defaults to `true`. After SOCKS5 authentication and a valid
CONNECT request, the client immediately replies with success, allowing the
application to send its first data while the QUIC relay connection and stream
are being established. Data waits in the bounded TCP receive buffer until the
relay is ready. If setup fails after success was sent, the connection closes
without a second SOCKS5 reply. Existing `relay.startup_mode` failure/retry
behavior still applies.

Set `optimistic_open = false` in `[local]` to restore the previous behavior: wait for
the relay stream and CONNECT command to be ready before replying, and send a
SOCKS5 failure if that setup fails. TUIC has no destination-connect acknowledgement,
so neither setting confirms that the remote destination is reachable. Unlike
Hysteria's Fast Open, this change does not save an additional destination-confirmation
RTT on an already established TUIC connection. It is independent of
`relay.zero_rtt_handshake`; UDP and raw TCP forwarding are unaffected.
