# Katzenpost WASM Client MVP

This crate is the browser-side starting point for the WebTransport client.

Implemented in this MVP:

- Open a WebTransport bidirectional stream and send a framed `ping` proof.
- Request raw signed consensus bytes over the same framed WT control protocol.
- Parse raw Katzenpost PKI certificates from CBOR.
- Verify Ed25519 dirauth signatures against caller-supplied trust anchors.
- Enforce certificate expiration and consensus epoch freshness.
- Extract gateways that advertise `Addresses["webtransport"]`.
- Build a NIKE/X25519 Katzenpost Sphinx packet in Rust/WASM for the reduced
  test geometry and selected gateway -> mix layers -> service path.
- Send the Sphinx packet over the WebTransport control stream and get an
  injection ack from the gateway.
- Generate a SURB in Rust/WASM, embed it in a forward packet, wait for the
  gateway to return the encrypted SURB reply on the same WebTransport stream,
  and decrypt the reply locally in the browser/WASM client.
- Open a long-lived online WebTransport receiver session for a client-generated
  SURB recipient and receive matching SURB replies asynchronously while the
  browser is online.
- Provide a small browser UI that shows `valid`, `invalid`, or `stale`.

Not implemented yet:

- Xwing `pqXX` wire handshake in Rust/WASM.
- KEMSphinx packet construction.
- Browser storage for identity keys, cached consensus, pending SURBs, and
  mailbox state.

The MVP3/MVP4/MVP5 path uses WebTransport only as a transport cable: the
browser/WASM verifies the consensus, builds Sphinx packets, generates SURBs,
and decrypts replies locally, while the gateway only validates packet
length/geometry, enqueues packets into the normal server incoming path, and
pushes matching SURB replies to registered online WT receiver streams.

The MVP control frame is:

```text
magic[4] = "KPWT"
version  = 1
type     = 1 ping | 2 get_consensus | 3 send_packet
         | 4 send_packet_with_reply | 5 register_receiver
         | 0x81 pong | 0x82 consensus | 0x83 packet_ack
         | 0x84 surb_reply | 0x85 receiver_ack
status   = uint16 big endian
length   = uint32 big endian
payload  = length bytes
```

For `get_consensus`, the request payload is `epoch uint64` big endian and the
response payload is the raw signed consensus certificate. The gateway does not
parse, filter, or rewrite the document for the browser client.

For `send_packet`, the request payload is one complete Sphinx packet matching
the gateway's configured Sphinx geometry. The ack payload is `accepted` on
success.

For `send_packet_with_reply`, the request payload is:

```text
recipient[32] || sphinx_packet
```

The gateway registers the recipient for the lifetime of the request, injects
the packet into the normal incoming path, and returns a `surb_reply` frame with
the encrypted SURB payload. The browser/WASM client decrypts that payload using
the locally retained SURB keys.

For `register_receiver`, the request payload is a 32-byte recipient. The
gateway responds with `receiver_ack` and keeps the stream open. Any future
SURB reply for that recipient is delivered as a `surb_reply` frame on the open
stream. If the browser disconnects, the gateway unregisters the online receiver;
offline mailbox/Pigeonhole delivery is deliberately out of scope for this MVP.
