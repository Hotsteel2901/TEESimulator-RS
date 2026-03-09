## TEESimulator v4.0: Native Rust Cert Generation

Major release. Certificate chain generation rebuilt from the ground up in Rust, replacing the BouncyCastle Java path for EC and RSA keys. Hardened against every known detector app.

### Native Cert Generation

The headline feature. `libcertgen.so` generates X.509 certificate chains using `ring` (EC-P256/P384) and `rsa` (RSA-2048/4096) with manual DER assembly. No more BouncyCastle quirks — issuer/subject DN bytes are injected directly from the keybox, ensuring byte-perfect chain linkage. BouncyCastle remains as fallback for unsupported curves (P-224, P-521, Curve25519).

### Anti-Detection Hardening

- **Challenge validation** — Oversized attestation challenges (>128 bytes) now return `INVALID_INPUT_LENGTH (-21)`, matching real KeyMint behavior. Previously accepted silently — DuckDetector exploited this.
- **Per-UID rate limiter** — 2 hardware keygens per 30s burst, 2 concurrent max. Overflow falls back to software certs. Blocks DuckDetector-style keygen flooding that starves GMS.
- **importKey eviction guard** — Retained patch chains prevent generate-then-import attacks that evict cached attestation data.
- **256KB native payload cap** — Oversized binder payloads bypass interception cleanly instead of stalling threads.
- **Alias size rejection** — Oversized key aliases rejected before they hit the binder buffer.

### Key Persistence

Generated keys now survive reboots. File-backed storage with file-level locking, preserved across keybox rotations. Banking and biometric apps that cache attestation keys no longer break after restart.

### Attestation Fixes

- Null out all-zero `verifiedBootHash` from TEE cache (fingerprinting vector)
- Correct `module_hash` field to match AOSP Keystore2 format
- Override pre-existing attest keys instead of skipping them
- Strip HTML comments from PEM blocks in keybox parsing
- Security patch consistency — `system=prop` forces boot/vendor to match

### Module Lifecycle

- Supervisor daemon keeps the interceptor alive
- KSU Action button clears persistent key cache
- Clean uninstall removes all traces (persistent keys, TEE status, daemon)

### Stability

- FileObserver NPE on config deletion fixed
- Global uncaught exception handler — daemon stays alive on unexpected errors
- PEM parsing hardened against malformed keybox files

### Tested Against

DuckDetector, Luna, Play Integrity, Key Attestation Demo — all passing on Redmi 14C (Android 14, Beanpod KeyMaster, KSU).
