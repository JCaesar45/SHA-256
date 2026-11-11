# Aurum Seal

> Change one letter and half the fingerprint rewrites itself.

Aurum Seal fingerprints documents with SHA-256, stamps each fingerprint into a
hash-chained ledger, and lets anyone with the original file check it later.
Your document never leaves your machine. Only its 64-character fingerprint does.

```
  your file ──► SHA-256 ──► 64 hex characters ──► ledger entry
                                                    │
        entry N = SHA-256( entry N-1 | digest | time )
```

Tamper with any past entry and every link after it stops matching, which
`GET /api/ledger` reports as `"intact": false`.

## Project layout

```
aurum-seal/
├─ public/index.html        landing page with a live SHA-256 sealing demo
├─ src/index.ts             TypeScript HTTP API and static server
├─ tools/aurum.py           Python CLI: hash, seal, verify, merkle
├─ java/SealClient.java     Java 17 client: hash, seal, verify
└─ data/ledger.json         created on first seal
```

## Run it

Requires Node 18+, Python 3.9+ and Java 17+.

```bash
npm install
npm run dev                       # http://localhost:8787
```

```bash
python3 tools/aurum.py seal contract.pdf --label "Ashgrove Lease"
python3 tools/aurum.py verify contract.pdf
python3 tools/aurum.py merkle ./deliverables --seal
```

```bash
javac -d out java/SealClient.java
java -cp out SealClient seal contract.pdf "Ashgrove Lease"
java -cp out SealClient verify contract.pdf
```

Set `AURUM_API` to point the Python and Java clients at another host.

## API

| Method | Route                  | Purpose                                              |
|--------|------------------------|------------------------------------------------------|
| GET    | `/api/health`          | liveness and seal count                              |
| POST   | `/api/seal`            | body `{ "digest" \| "text", "label"? }`, returns 201 |
| GET    | `/api/verify/:digest`  | 200 with the seal, or 404                            |
| GET    | `/api/ledger`          | chain integrity, head hash, 20 most recent seals     |

## Design choices

- **Hashing happens client-side.** Clients send a digest, so the server never holds your files.
- **Hash chain over a database.** The ledger needs to prove its own order, and a chain does that with no extra infrastructure.
- **Merkle roots for batches.** One seal can cover a whole folder, and changing any file changes the root.
- **Serialized writes.** The ledger file is written through a single promise queue so concurrent seals cannot interleave.

## Limits

The chain proves the order of entries and that none were edited after the fact.
Because the server writes its own timestamps, a strong time guarantee would
need an external timestamp authority, such as an RFC 3161 service.

## References

Haber, S., & Stornetta, W. S. (1991). How to time-stamp a digital document.
*Journal of Cryptology, 3*(2), 99–111. https://doi.org/10.1007/BF00196791

Merkle, R. C. (1988). A digital signature based on a conventional encryption
function. In C. Pomerance (Ed.), *Advances in cryptology: CRYPTO '87*
(pp. 369–378). Springer. https://doi.org/10.1007/3-540-48184-2_32

National Institute of Standards and Technology. (2015). *Secure hash standard
(SHS)* (FIPS PUB 180-4). U.S. Department of Commerce.
https://doi.org/10.6028/NIST.FIPS.180-4
