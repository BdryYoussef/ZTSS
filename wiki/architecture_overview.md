# Architecture Overview

## Four Subsystems (weakly coupled)

- **[[crypto_layer]]** — AES-GCM, PRE, PoP; outputs encrypted keys/ciphertexts
- **[[storage_layer]]** — Merkle DAG, chunks; addresses data by content
- **[[api_auth_layer]]** — JWT, REST endpoints, audit log
- **[[network_layer]]** — P2P Go nodes, replication, inter-node transfer

## Tech Stack (mandatory)

| Layer | Language / Runtime | Library / Protocol |
|---|---|---|
| Crypto | Go 1.22+ | `golang.org/x/crypto`, libsodium-equivalent |
| Storage | Go 1.22+ | Custom Merkle DAG, BlockStore |
| Network | Go 1.22+ | `net` (TCP), goroutines |
| Client alt. | Java 21 | raw sockets |
| API | Go 1.22+ | `net/http` or Fiber |
| Infra | Docker | `docker-compose.yml` (4 nodes) |
| CI | GitHub Actions | `go test ./...` |

## Performance Targets

- Upload 10 MB file: **< 3 s** on local network
- Availability: **≥ 99%** with 3/4 nodes active
- Crypto test coverage: **≥ 70%** (crypto module target: **≥ 80%**)

## Module → Repo Directory Mapping

```
ztss/
  go.mod / go.sum
  docker-compose.yml
  Makefile
  ztss-crypto/        → [[crypto_layer]]
  ztss-storage/       → [[storage_layer]]
  ztss-node/          → [[network_layer]]
  ztss-api/           → [[api_auth_layer]]
  demo.ipynb
  rapport/rapport.tex
```
