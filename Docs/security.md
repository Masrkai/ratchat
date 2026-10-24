# Security & Cryptographic Principles

This document outlines the security architecture, cryptographic guarantees, and mitigations against Man-in-the-Middle (MITM) attacks implemented in this E2EE Chat system.

---

## 1. Cryptographic Principles

### A. Extended Triple Diffie-Hellman (X3DH)
- **Asynchronous Key Agreement**: Allows two parties to establish a shared secret even when the recipient is offline, utilizing pre-published Prekey Bundles (`Identity Key`, `Signed Prekey`, and `One-Time Prekeys`).
- **Authentication**: Binds identity keys to ensure parties cryptographically verify who they are communicating with.

### B. The Double Ratchet Algorithm
- **Forward Secrecy (FS)**: Every message uses a unique message key derived via a symmetric ratchet. If an adversary compromises a client's current state at time $T$, past messages remain secure because old keys cannot be recalculated.
- **Post-Compromise Security (PCS / Self-Healing)**: Combines Diffie-Hellman ratchets with the symmetric ratchet. If an adversary compromises a key today, future message security automatically recovers as soon as the parties exchange new DH ratchet steps.

### C. Host OpenSSL FFI Primitives
- Avoids custom or experimental cryptographic implementations by leveraging battle-tested system OpenSSL primitives (`libcrypto`) via LuaJIT FFI (`X25519`, `HKDF`, `AES-GCM`).
- Guarantees cryptographically secure randomness via `RAND_bytes`.

---

## 2. Mitigating Man-in-the-Middle (MITM) Attacks

While the server relays encrypted payloads, a malicious server or network adversary could attempt a Man-in-the-Middle attack by substituting public keys in transit (e.g., swapping Bob's Prekey Bundle with the attacker's bundle). To completely mitigate MITM attacks, the following measures are enforced or recommended:

### A. Safety Number / Fingerprint Verification (Out-of-Band Verification)
- Implemented via the `/fingerprint [@user]` chat command.
- The fingerprint is SHA-256 over the peer's raw Identity Key bytes; the first 30 digest bytes each become two decimal digits (byte mod 100), yielding a **60-digit safety number** grouped 5 digits at a time (12 groups), Signal-style.
- Users compare these fingerprints out-of-band (in person or voice call). If the 60 digits match on both sides, no prekey-substitution MITM has occurred.
- A peer's fingerprint is available once an E2EE session exists (their IK is pinned in `peer_iks` at session setup); your own is available immediately.

### B. Certificate-Signed Prekeys
- Signed Prekeys (`SPK`) are signed by the user's long-term Identity Key (`IK`) using Ed25519 signatures.
- Clients verify the signature on the `SPK` using the recipient's known `IK` before establishing an X3DH session, preventing the server from tampering with signed prekeys.

### C. Trust-On-First-Use (TOFU) & Pinning
- Once an Identity Key is received for a user, the client pins that key locally. Any unexpected change in a user's Identity Key triggers a security alert and halts message decryption until verified.
