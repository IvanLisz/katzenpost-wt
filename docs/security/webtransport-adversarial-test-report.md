# Katzenpost-over-WebTransport Adversarial Test Report

Date: 2026-05-19

Scope: online-only browser/WASM Katzenpost client path over WebTransport.
Offline storage, mailbox retrieval, and Pigeonhole are out of scope.

## Security Invariants

| Invariant | Status | Evidence |
| --- | --- | --- |
| Browser/WASM verifies consensus locally | Passed | `verify_consensus_bytes` validates certificate version, expiration, epoch freshness, trust-anchor length, Ed25519 signatures, and signature threshold before returning a `VerifiedConsensus`. |
| Browser/WASM rejects invalid, stale, or modified consensus | Passed | Rust tests cover tampered consensus, stale consensus, and packet construction gated on consensus verification. |
| Browser/WASM selects route locally | Passed | `build_sphinx_packet_bytes` and `build_sphinx_packet_with_surb_bytes` parse the verified document and call local route selection before packet construction. The WT gateway API has no route-selection frame. |
| Browser/WASM builds Sphinx/SURB material locally | Passed | WASM creates NIKE Sphinx packets, KEMSphinx/x25519-adapter packets, SURB recipient, SURB ID, SURB keys, and encrypted forward payload before any packet is sent to the gateway. |
| Gateway only forwards opaque packets | Passed with online metadata caveat | WT `send_packet` accepts one already-built packet and enqueues it. `send_packet_with_reply` and `register_receiver` additionally receive a random recipient ID for online SURB delivery, but not plaintext, route, service, or SURB keys. |
| Replies work via SURB without gateway learning plaintext | Passed | Live smoke receives encrypted SURB payload from the gateway and only decrypts in browser/WASM with local SURB keys. Rust tests reject tampered SURB reply ciphertext and wrong keys. |

## Protocol Trace

Captured with:

```sh
cd wasm/katzenpost-wasm-client
npm run smoke:live
```

Reduced topology: 3 dirauths, 3 mixes, 1 gateway, 1 service node, 2 storage replicas.

Live smoke result:

```json
{
  "proofText": "katzenpost-wt-okdummy",
  "epoch": "2357161",
  "expiration": "2357166",
  "signatures": 3,
  "gateways": [
    {
      "name": "gateway1",
      "endpoints": [
        "https://127.0.0.1:30007/.well-known/katzenpost-wt"
      ]
    }
  ],
  "packetLength": 3082,
  "packetAck": "accepted",
  "replyCiphertextLength": 2606,
  "replyPlaintextLength": 2574,
  "replyText": "mvp4-live-smoke",
  "asyncPacketAck": "accepted",
  "asyncReplyCiphertextLength": 2606,
  "asyncReplyPlaintextLength": 2574,
  "asyncReplyText": "mvp5-live-smoke",
  "serviceLog": "Processed Kaetzchen request: 13 (No response)"
}
```

MVP6 KEMSphinx/x25519-adapter live smoke result:

```json
{
  "sphinxMode": "kem-x25519",
  "kemName": "x25519",
  "proofText": "katzenpost-wt-okdummy",
  "epoch": "2357803",
  "expiration": "2357808",
  "signatures": 3,
  "packetLength": 3402,
  "packetAck": "accepted",
  "replyCiphertextLength": 2766,
  "replyPlaintextLength": 2734,
  "replyText": "mvp4-live-smoke",
  "asyncPacketAck": "accepted",
  "asyncReplyCiphertextLength": 2766,
  "asyncReplyPlaintextLength": 2734,
  "asyncReplyText": "mvp5-live-smoke"
}
```

Trace steps:

1. Browser opens WebTransport to the gateway and sends `ping`.
   Gateway replies `pong` with `katzenpost-wt-okdummy`.

2. Browser requests a raw consensus document for epoch `2357161`.
   Gateway serves raw bytes only. Browser/WASM verifies 3 dirauth signatures,
   freshness, and expiration locally, then extracts the WT gateway endpoint.

3. Browser/WASM selects the forward route locally:
   `gateway -> mix layer 0 -> mix layer 1 -> mix layer 2 -> service`.
   It serializes routing commands and builds a 3082-byte Sphinx packet locally.

4. Browser sends `send_packet` with only the Sphinx packet bytes.
   Gateway calls `packet.New` for geometry validation, sets `MustForward`, and
   enqueues the packet into the normal incoming path. The ack is `accepted`.

5. Browser/WASM builds a second packet with an embedded SURB. The SURB contains
   a locally generated random recipient ID, SURB ID, and local decryption keys.
   Browser sends `send_packet_with_reply` with:

   ```text
   recipient[32] || sphinx_packet[3082]
   ```

   The gateway registers the random recipient for the request lifetime, injects
   the packet, and returns only the encrypted SURB reply payload. Browser/WASM
   decrypts it locally to `mvp4-live-smoke`.

6. Browser/WASM builds another packet with a SURB for the online receiver test.
   It opens `register_receiver` with the random recipient ID and keeps the WT
   stream open. It sends the Sphinx packet separately through `send_packet`.
   The reply arrives asynchronously on the receiver stream as `surb_reply`.
   Browser/WASM decrypts locally to `mvp5-live-smoke`.

Relevant service and gateway log evidence:

```text
servicenode1: kaetzchen/echo: Handling request: 15
servicenode1: kaetzchen_worker: Handing off newly generated SURB-Reply: 16 (Src:15)
gateway1: gateway: Delivered SURB-Reply to WebTransport session: 16
```

## Adversarial Tests

Commands:

```sh
cd wasm/katzenpost-wasm-client
cargo test
npm run typecheck

cd /root/katzenpost-wt
docker run --user 0:0 --volume /root/katzenpost-wt:/go/katzenpost \
  --workdir /go/katzenpost -v /root/katzenpost-wt/docker/cache/go:/go/ \
  -e GOCACHE=/go/cache -e GOPATH=/go --rm katzenpost-alpine_base \
  sh -c 'go test ./server/internal/incoming ./server/internal/gateway ./server/config ./server ./core/pki ./cmd/genconfig ./core/genconfig'
```

Test coverage added or confirmed:

- `rejects_tampered_consensus`: modifying signed consensus bytes fails local
  signature/CBOR verification.
- `classifies_stale_consensus`: stale consensus is rejected locally.
- `packet_construction_rejects_tampered_consensus_before_route_selection`:
  packet builders reject modified consensus before any route selection or
  Sphinx construction can proceed.
- `packet_construction_rejects_stale_consensus_before_route_selection`:
  packet builders reject stale consensus before route selection.
- `surb_reply_decryption_is_local_and_authenticated`: local SURB reply decrypt
  succeeds with the retained local keys and rejects tampered ciphertext or wrong
  keys.
- `blake2xb_xof_matches_go_kem_adapter_hash`: Rust/WASM matches the Go
  BLAKE2Xb hash used by Katzenpost's X25519 KEM adapter.
- `kemsphinx_x25519_packet_uses_kem_geometry`: KEMSphinx packet construction
  uses the x25519 KEM-adapter header and packet geometry.
- `kemsphinx_x25519_surb_uses_kem_geometry`: KEMSphinx SURB construction uses
  the KEM geometry and keeps reply decryption material local.
- `kemsphinx_rejects_unsupported_scheme`: the MVP6 KEMSphinx entry point
  refuses unimplemented KEM schemes instead of silently building the wrong
  packet format.
- `TestWebTransportReceiverRejectsInvalidRecipientLength`: WT online receiver
  registration rejects malformed recipient IDs.

## Gateway Trust-Boundary Analysis

Gateway consensus behavior:

- The WT endpoint serves raw consensus bytes via `GetRawConsensus(epoch)`.
- It does not rewrite, filter, or select entries for the browser.
- Any modified or stale document is detected by browser/WASM verification.

Gateway send behavior:

- `send_packet` payload is one complete Sphinx packet.
- The gateway validates packet length/geometry with `packet.New`.
- The gateway does not receive route hops, service capability, plaintext, SURB
  keys, or decrypted reply data.
- It sets forwarding metadata (`MustForward`, `RecvAt`) and hands the packet to
  the existing incoming path.

Gateway reply behavior:

- For online delivery, the gateway maps a random 32-byte recipient ID to a WT
  stream.
- On SURB reply, it copies the encrypted payload and writes a `surb_reply`
  frame to the stream.
- If no online receiver exists, existing spool behavior remains the fallback.
- The gateway never receives SURB decryption keys and cannot validate or read
  the reply plaintext.

## Residual Risks And Non-Claims

- The gateway necessarily observes client IP/TLS/WebTransport session metadata,
  timing, packet sizes, and which random recipient IDs are registered online.
- The gateway can deny service, delay packets, return stale raw consensus, or
  refuse WT connections. The client detects invalid/stale consensus but cannot
  force availability.
- The gateway can correlate an online registered recipient with a later reply on
  that same WT session. That is an online transport metadata leak, not plaintext
  or route delegation.
- This MVP supports the reduced NIKE/X25519 test geometry and the KEMSphinx
  x25519 KEM-adapter geometry. Post-quantum KEMSphinx schemes such as `XWING`
  or `MLKEM768-X25519` remain future work.
- WASM supply-chain integrity, app signing, CSP, reproducible builds, and key
  storage hardening are not proven by these tests.

## Conclusion

The current online-only implementation satisfies the intended trust boundary:
WebTransport is only the cable. The browser/WASM client verifies consensus,
selects routes, builds Sphinx packets, generates SURBs, and decrypts replies.
The gateway forwards opaque packet bytes and delivers encrypted SURB replies to
registered online sessions, but it does not become a trusted bridge for route,
identity, packet construction, or payload confidentiality.
