## SHA-3 (Keccak) Implementation

This repository contains implementation of the SHA-3 (Keccak) cryptographic hash function.  
The implementation fully complies with **NIST FIPS 202**.

### Supported parameters

- **d** — output digest length (224, 256, 384, 512 bits)
- **c** — sponge function capacity (448, 512, 768, 1024 bits)
- **l** — Keccak parameter (*l = 6* for SHA-3)
- **mode** — input reading mode:
  - `1` — the input file is processed directly as a bit sequence
  - `2` — the input file is read as text and converted to a bit sequence using UTF-8 encoding
