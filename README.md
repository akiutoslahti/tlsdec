# tlsdec

A small decryptor for TLS 1.3 sessions. Give it a packet capture of one session and the session's key log, and it prints the plaintext. Written to understand the TLS 1.3 record layer and key schedule by building the thing instead of reading about it.

- Reads classic pcap, Ethernet, IPv4, TCP. Reassembles both directions of one flow.
- Splits the streams into TLS records and reads the client random and the cipher suite from the Hellos.
- Takes the handshake and application traffic secrets from an NSS-format key log and derives the write keys and IVs with a hand-written HKDF-Expand-Label.
- Decrypts every record with AES-GCM, nonce from the record sequence number, record header as additional data, and recovers the inner content type.
- Switches from handshake to application keys at Finished, so NewSessionTicket and close_notify show up where they really are.

All code is written by hand. An AI assistant is used for review and as a reference, see CLAUDE.md. The design and the schedule are in PLAN.md. This README was drafted by the assistant from the code and PLAN.md.

## Usage

```
python -m venv .venv && . .venv/bin/activate && pip install -e '.[dev]'
tlsdec --pcap tests/fixtures/fixture-TLS_AES_128_GCM_SHA256.pcap --keylog tests/fixtures/keys-TLS_AES_128_GCM_SHA256.log
```

Output is one block per direction, client to server first. One line per TLS record: index in the stream, outer type and length, which key decrypted it and under which sequence number, the inner type, and for handshake records the message types. Application data follows its line, as text when it is printable ASCII and as hex otherwise.

```
127.0.0.1:4443 -> 127.0.0.1:46430
[index: 0, outer type: HANDSHAKE, outer length: 122, decryption key: -, sequence number: -]
[index: 1, outer type: CHANGE_CIPHER_SPEC, outer length: 1, decryption key: -, sequence number: -]
[index: 2, outer type: APPLICATION_DATA, outer length: 23, decryption key: HANDSHAKE, sequence number: 0, inner type: HANDSHAKE, handshake type(s): ENCRYPTED_EXTENSIONS]
...
[index: 5, outer type: APPLICATION_DATA, outer length: 53, decryption key: HANDSHAKE, sequence number: 3, inner type: HANDSHAKE, handshake type(s): FINISHED]
[index: 6, outer type: APPLICATION_DATA, outer length: 234, decryption key: APPLICATION, sequence number: 0, inner type: HANDSHAKE, handshake type(s): NEW_SESSION_TICKET]
```

Any refusal is printed to stderr with what was expected and what was seen, and the exit code is 1.

## From secret to plaintext

```
key log line (per direction, per phase)
  LABEL  client_random  traffic_secret
              |               |
   matched against the        |       cipher suite from ServerHello
   ClientHello random         |       -> hash (SHA-256 / SHA-384), key length (16 / 32)
                              v
        key = HKDF-Expand-Label(secret, "key", "", key_length)     RFC 8446 7.3
        iv  = HKDF-Expand-Label(secret, "iv",  "", 12)
                              |
   record sequence number --->|  nonce = iv XOR (seqno as 64-bit big-endian, left-padded to 12)   RFC 8446 5.3
   (never on the wire,        |
    counted per direction,    |
    reset at key change)      |
                              v
   record header (5 bytes, as on the wire) = additional data
   record body = ciphertext || 16-byte tag
                              |
                              v
               AES-GCM decrypt, tag checked
                              |
                              v
   TLSInnerPlaintext: content || content type || zero padding          RFC 8446 5.2
   strip trailing zeros, last byte is the real content type
```

Each direction starts under its handshake traffic secret. When that direction's Finished message has been consumed, it switches to the application traffic secret and the sequence number starts again at 0. The labels in the key log are `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0` and `SERVER_TRAFFIC_SECRET_0`.

## Fixtures

`tests/fixtures/` holds two captures of a single `curl` request against a local `openssl s_server`, one per cipher suite, with their key logs: TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384. The commands that produced them are in PLAN.md, section "Test fixture". Nothing in them belongs to anyone else.

## Verification

The reference is Wireshark's own decryption of the same files:

```
tshark -r tests/fixtures/fixture-TLS_AES_128_GCM_SHA256.pcap -o tls.keylog_file:tests/fixtures/keys-TLS_AES_128_GCM_SHA256.log -o http.desegment_body:FALSE -Y http -V
```

and the same with `TLS_AES_256_GCM_SHA384` in both file names. `http.desegment_body:FALSE` is needed because `s_server -www` answers HTTP/1.0 without Content-Length.

The reference output is kept in `docs/`:

- `records-*.txt` the outer TLS record types and lengths per frame
- `inner-*.txt` the inner content types and handshake message types per frame
- `plaintext-*.txt` the decrypted application data per direction (`follow,tls,raw`)

The tool's HTTP request and response match `plaintext-*.txt` byte for byte on both fixtures, and NewSessionTicket appears under the application key.

Checks: `pytest`, `mypy --strict src`, `ruff check . && ruff format --check .`.

## Limits

- TLS 1.3 only. TLS_AES_128_GCM_SHA256 and TLS_AES_256_GCM_SHA384 only, no ChaCha20-Poly1305.
- Classic pcap with Ethernet link type, IPv4 without fragmentation. No pcapng, no IPv6.
- Exactly one TCP flow per capture, starting with its handshake. Gaps in a stream are an error, not skipped.
- No HelloRetryRequest, no KeyUpdate, no 0-RTT early data, no session resumption, no client certificates. No certificate validation: the tool decrypts, it does not authenticate.
- The key log must contain the four traffic secrets for the session's client random.
- The two directions are printed one after the other, not interleaved in capture order.
- No `--raw` output to files and no `--flow` selection.
- The tool only reads. It never modifies a capture and never sends anything.
