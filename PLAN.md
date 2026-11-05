# Plan

A five-day learning project. The goal is to understand the TLS 1.3 record layer and key schedule properly by building one small, real tool instead of reading about it: a decryptor that takes a packet capture of one TLS 1.3 session plus the session's key log, and prints the plaintext. Given the key, decrypt the traffic. Everything else exists only to make that possible.

## Ground rules

- All code is written by hand. An AI assistant is used as a reviewer, a test runner and a reference for the RFCs, never for writing code. The rules are in CLAUDE.md.
- One repository, small commits with real messages. The history is part of the result.
- Python 3.11 or newer. Standard library for everything except the AEAD primitive, which comes from the `cryptography` package. HKDF is written by hand on top of `hmac` and `hashlib`. AES-GCM is not.
- No pcap or TLS library. No scapy, no dpkt, no pyshark. Parsing the bytes is the point. Wireshark and tshark are used only to verify the result.
- Scope is fixed. If a day slips, cut from that day's cut list. Do not extend. The tool is done on day 4. Day 5 is for explaining it, not for code.

## Minimum

The day lists below are the full plan. This is the part that has to exist, about eight hours. Everything not in it is cut first.

- HKDF-Expand-Label green against the RFC 8448 vectors.
- One fixture, TLS_AES_128_GCM_SHA256, verified with tshark before any code.
- pcap to records, matching tshark's record list.
- Keys and IVs derived from the key log for that session.
- Application data decrypted, inner type recovered, HTTP byte for byte what tshark shows.
- The key switch at Finished. If the handshake message walker is not working by Saturday evening, use the shortcut: decrypt under the handshake key until the first tag failure, then switch to the application key and reset the sequence number. Document it as a shortcut and why it works.

Cut first, in this order: the second fixture, `--flow`, `--raw`, CI, ruff, polished error messages, the diagram as a picture.

Stop rule: Sunday 18:00, code stops in whatever state it is. Day 5 is not optional.

## The tool

One package, `tlsdec`, with a console entry point:

    tlsdec --pcap session.pcap --keylog keys.log [--flow a.b.c.d:p-e.f.g.h:q] [--raw outdir]

It prints one line per TLS record: direction, record sequence number, outer type, inner type, length, and then the plaintext, as text when printable and as a hex dump otherwise. With `--raw` it also writes each direction's decrypted application data to a file, so the HTTP request and response can be diffed against Wireshark's.

### Parts

1. pcap reader. Classic pcap only (magic 0xa1b2c3d4 or 0xd4c3b2a1, both byte orders), link type 1 (Ethernet), IPv4, TCP. Everything else is an error with a clear message. `struct` for every header. Explicit offsets, explicit big-endian.
2. Flow selection and TCP reassembly. Pick the flow from `--flow`, or if there is exactly one TCP flow in the file, that one. Per direction: order segments by sequence number, drop exact retransmissions, remember that SYN and FIN consume one sequence number each. Output is one byte stream per direction. Gaps are an error, not silently skipped.
3. TLS record layer. Split each byte stream into records: 5-byte header (content type, legacy version, length), then the body. Records span TCP segments, which is why reassembly comes first. Type 20 (change cipher spec) records are compatibility noise in TLS 1.3 and are skipped. Type 21 (alert) and type 22 (handshake) can appear in plaintext before encryption starts.
4. Handshake, minimal. From the ClientHello: the 32-byte client random, which is the key into the key log. From the ServerHello: the cipher suite, and the supported_versions extension to confirm 0x0304. Nothing else in the handshake is parsed in plaintext.
5. Key log. The NSS key log format, one line per secret: label, client random in hex, secret in hex. The labels that matter: `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`. Match on client random. A log can hold many sessions.
6. Key schedule, by hand. HKDF-Expand from RFC 5869 over `hmac`. HKDF-Expand-Label from RFC 8446 section 7.1: the HkdfLabel structure is a 16-bit length, a length-prefixed label made of "tls13 " plus the label, and a length-prefixed context, empty here. The write key is Expand-Label(secret, "key", "", key_length) and the write IV is Expand-Label(secret, "iv", "", 12). The hash and the key length come from the cipher suite: TLS_AES_128_GCM_SHA256 (0x1301) and TLS_AES_256_GCM_SHA384 (0x1302) are required. TLS_CHACHA20_POLY1305_SHA256 (0x1303) is on the cut list.
7. Record decryption. Per direction, a record sequence number that starts at zero and counts every encrypted record, and resets to zero when the key changes. Nonce is the sequence number as a 64-bit big-endian integer, left-padded with zeros to 12 bytes, XOR the static IV. Additional authenticated data is the 5-byte record header exactly as it was on the wire. The last 16 bytes of the body are the tag. A tag failure is reported with the direction and sequence number and stops that direction, because every later nonce would be wrong too.
8. Inner plaintext. Strip trailing zero bytes, the last non-zero byte is the real content type. 23 is application data, 22 is a handshake message, 21 an alert.
9. Key switching. Each direction starts in the handshake phase after its Hello and decrypts under the handshake traffic secret. The decrypted handshake content is walked as handshake messages (one-byte type, three-byte length, messages can span records). When a Finished message (type 20) has been consumed, that direction switches to the application traffic secret and the sequence number resets. After that, inner type 22 messages are still possible: the server normally sends NewSessionTicket under the application key, which is a good thing to be able to point at.
10. Output and `--raw`. One summary line per record, plaintext under it, the two application data streams written to files when asked.

### Test fixture

A capture of one session against a local server, so the repository holds nothing that belongs to anyone else and the test is deterministic.

- A self-signed certificate: `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout key.pem -out cert.pem -subj /CN=localhost -days 30`
- Server: `openssl s_server -accept 4443 -cert cert.pem -key key.pem -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -www`
- Capture: `tcpdump -i lo -w fixture.pcap port 4443`
- Client: `SSLKEYLOGFILE=keys.log curl -k https://localhost:4443/`
- A second fixture with `TLS_AES_256_GCM_SHA384` on both sides, so the SHA-384 and 32-byte key path is tested too.

Check the fixture before writing any code: `tshark -r fixture.pcap -o tls.keylog_file:keys.log -Y http -V` must show the request and the response. If tshark cannot decrypt it, the fixture is wrong, not the tool.

### Tests

pytest, `mypy --strict`, ruff. Test first for the pure parts.

- HKDF-Expand against RFC 5869 test case 1. HKDF-Expand-Label and the write key and IV against RFC 8448 section 3, which prints the client and server application traffic secrets and the keys and IVs derived from them. These vectors are the proof that the key schedule is right before any packet is touched.
- Nonce construction: sequence 0 gives the IV, sequence 1 flips the last bit, sequence 2^32 reaches the fifth byte from the end.
- Record splitting on crafted byte strings, including a record that ends exactly at a segment boundary and one that spans three.
- Inner plaintext stripping, including a record whose content is all zeros followed by the type byte.
- Key log parsing: several sessions in one file, the right one chosen by client random, a missing label reported by name.
- TCP reassembly: segments given out of order, an exact duplicate, a gap.
- End to end on both fixtures: the decrypted request and response equal what tshark prints for the same capture and key log, byte for byte for the HTTP bodies.

### Verification against Wireshark

- Record count and types: `tshark -r fixture.pcap -Y tls.record -T fields -e tcp.srcport -e tls.record.content_type -e tls.record.length`
- Plaintext: `tshark -r fixture.pcap -o tls.keylog_file:keys.log -Y http -T fields -e http.request.line -e http.response.code -e http.file_data`
- Inner content types: `tshark -r fixture.pcap -o tls.keylog_file:keys.log -Y tls -T fields -e tls.record.opaque_type -e tls.record.content_type`

If the tool and tshark disagree, tshark is right until proven otherwise.

## Day by day

### Day 1, evening (2 h): toolchain, fixture, key schedule

- Repository, `pyproject.toml` with a console entry point, pytest, `mypy --strict`, ruff, one failing test, GitHub Actions running it. Green before any real code.
- Both fixtures captured and verified with tshark.
- HKDF-Expand and HKDF-Expand-Label with the RFC 5869 and RFC 8448 vectors green.
- Done when: the key and IV for the RFC 8448 trace come out of my own code.
- Cut list if slipping: CI, do it on day 4.

### Day 2 (3 h): bytes to records

- pcap reader, flow selection, TCP reassembly, record splitting, with their tests.
- Done when: the tool lists every record of the fixture with the same types and lengths as tshark, nothing decrypted yet.
- Cut list if slipping: `--flow` (require a single-flow capture), duplicate handling (require a clean capture).

### Day 3 (3 h): decryption

- ClientHello and ServerHello extraction, key log, key and IV derivation for the fixture's suite, record decryption, inner type, handshake message walking and the switch at Finished, output, `--raw`.
- Done when: the HTTP request and response from the tool are byte for byte what tshark shows, on both fixtures, and NewSessionTicket shows up as an inner handshake message under the application key.
- Cut list if slipping: `--raw`, the SHA-384 fixture, pretty names for handshake message types.

### Day 4 (2 h): finish

- Error messages for every refusal: wrong link type, IPv6, more than one flow, missing secret, bad tag. Each one names what it saw.
- README with a diagram of the chain from secret to plaintext, the commands to reproduce the fixture, the verification commands, and the honest limits.
- Tests and mypy green, ruff clean, commit history readable.
- Cut list if slipping: the diagram as text instead of a picture.

### Day 5: no code

- Draw the chain on paper from memory: secret, HKDF-Expand-Label, key and IV, sequence number, nonce, AAD, AES-GCM, tag, inner type. Twice, until it comes out without looking.
- Say out loud, in under two minutes, what the tool does and what the three things are that go wrong first when writing one (nonce, AAD, sequence reset).

Stretch, only if day 3 ends early: TLS_CHACHA20_POLY1305_SHA256 through `ChaCha20Poly1305` from the same package. KeyUpdate handling: on an inner handshake message of type 24, derive the next traffic secret with Expand-Label(secret, "traffic upd", "", hash_length) and reset the sequence number.

Not in scope, ever, for this project: TLS 1.2, pcapng, IPv6, session resumption, early data, client certificates, certificate validation, anything that writes packets.

## Checklist

Tick each item when you can explain it and have used it once.

- Why the record sequence number is never on the wire and still has to be exact, and what happens to GCM if a nonce repeats under one key
- Why the record header is authenticated as additional data, and what an attacker could do if it were not
- Why there are separate handshake and application traffic secrets, and when each direction switches
- Why the real content type is inside the encryption and the outer type is always 23
- What the key log actually contains (secrets, not keys) and why that is enough
- What HKDF-Extract does that HKDF-Expand does not, and why this tool never needs Extract
- How the cipher suite determines the hash, the key length and the AEAD
- What changes in TLS 1.2: the PRF instead of HKDF, the explicit nonce in every record, no inner content type
- What the equivalent is for SMB 3.1.1: the SP800-108 counter-mode KDF over HMAC-SHA256 from the session key, with the cipher key labels and the pre-authentication integrity hash as context, then AES-GCM or CCM with the nonce in the transform header
- Why TCP reassembly has to come before record splitting, and why a lost segment makes everything after it undecryptable
