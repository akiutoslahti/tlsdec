# tlsdec

A small decryptor for TLS 1.3 sessions. Give it a packet capture of one session and the session's key log, and it prints the plaintext. Written to understand the TLS 1.3 record layer and key schedule by building the thing instead of reading about it.

- Reads classic pcap, Ethernet, IPv4, TCP. Reassembles both directions of one flow.
- Splits the streams into TLS records and reads the client random and the cipher suite from the Hellos.
- Takes the handshake and application traffic secrets from an NSS-format key log and derives the write keys and IVs with a hand-written HKDF-Expand-Label.
- Decrypts every record with AES-GCM, nonce from the record sequence number, record header as additional data, and recovers the inner content type.
- Switches from handshake to application keys at Finished, so NewSessionTicket and close_notify show up where they really are.

All code is written by hand. An AI assistant is used for review and as a reference, see CLAUDE.md. The design and the schedule are in PLAN.md.

Status: in progress.
