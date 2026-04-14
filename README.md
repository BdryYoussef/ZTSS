# ZTSS

ZTSS is a **decentralized, end-to-end encrypted file storage system** built with Go and Python.

## 🚀 Quick Start (4-Node Cluster)

### Prerequisites
- Docker & Docker Compose
- Python 3.8+

### 1. Start the Cluster
```bash
cd ZTSS/ZTSS
docker-compose up --build -d
```

This starts a 4-node cluster with:
- **Node 1**: API + Web UI (port 8090)
- **Nodes 2-4**: Storage nodes (ports 7002-7004)

### 2. Run the Demo (Python Client)
```bash
python3 ztss_client.py
```

This will:
1. Generate a 300 KB test file
2. Encrypt it with AES-256-GCM (client-side)
3. Split into 256 KB chunks
4. Compute Merkle root
5. Authenticate via JWT + EdDSA Proof-of-Possession
6. Upload to the cluster

### 3. Verify in Web UI
Open [http://localhost:8090](http://localhost:8090) in your browser.
- Go to **Files** tab
- You should see the uploaded file with its Merkle root
- All 4 nodes show green (healthy)

## 🏗️ Architecture

ZTSS has four weakly coupled subsystems:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              ZTSS System                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  │  Crypto Layer   │  │  Storage Layer  │  │  API/Auth Layer │  │  Network Layer  │
│  │  (Go)           │  │  (Go)           │  │  (Go)           │  │  (Go)           │
│  │                 │  │                 │  │                 │  │                 │
│  │  - AES-256-GCM  │  │  - Merkle DAG   │  │  - JWT (RS256)  │  │  - P2P Gossip   │
│  │  - PRE          │  │  - Chunking     │  │  - EdDSA PoP    │  │  - Replication  │
│  │  - ECIES        │  │  - BlockStore   │  │  - Audit Log    │  │  - Discovery    │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  └─────────────────┘
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Key Features
- **End-to-End Encryption**: All data encrypted client-side with AES-256-GCM
- **Content-Addressed Storage**: Files identified by Merkle root (root_cid)
- **Decentralized**: 4-node P2P cluster with gossip protocol
- **Secure Authentication**: JWT RS256 + EdDSA Proof-of-Possession
- **Replication**: Files replicated across multiple nodes for availability

## 🛠️ Tech Stack

| Layer | Language | Library / Protocol |
|-------|----------|--------------------|
| Crypto | Go 1.22+ | `golang.org/x/crypto`, libsodium-equivalent |
| Storage | Go 1.22+ | Custom Merkle DAG, BlockStore |
| Network | Go 1.22+ | `net` (TCP), goroutines |
| API | Go 1.22+ | `net/http` or Fiber |
| Client | Python 3.8+ | `cryptography`, `requests` |
| Infra | Docker | `docker-compose.yml` |
| CI | GitHub Actions | `go test ./...` |

## 📂 Project Structure

```
ZTSS/
├── ZTSS/
│   ├── ztss-crypto/        # Crypto primitives (AES-GCM, PRE, ECIES)
│   ├── ztss-storage/       # Merkle DAG, chunking, BlockStore
│   ├── ztss-node/          # P2P network, gossip, replication
│   ├── ztss-api/           # REST API, JWT auth, audit log
│   ├── ztss_client.py      # Python demo client
│   ├── demo.ipynb          # Jupyter notebook demo
│   └── rapport/            # LaTeX reports
└── docker-compose.yml      # 4-node cluster definition
```

## 🧪 Testing

### Run All Tests
```bash
cd ZTSS/ZTSS
make test
```

### Run Specific Subsystem Tests
```bash
# Crypto tests
cd ztss-crypto && go test ./...

# Storage tests
cd ztss-storage && go test ./...

# Network tests
cd ztss-node && go test ./...

# API tests
cd ztss-api && go test ./...
```

## 📊 Performance Targets

- **Upload 10 MB file**: < 3 seconds (local network)
- **Availability**: ≥ 99% with 3/4 nodes active
- **Crypto test coverage**: ≥ 70% (module target: ≥ 80%)

## 📝 Documentation

- [Architecture Overview](wiki/architecture_overview.md)
- [Crypto Layer](wiki/crypto_layer.md)
- [Storage Layer](wiki/storage_layer.md)
- [API & Auth Layer](wiki/api_auth_layer.md)
- [Network Layer](wiki/network_layer.md)
- [Auth Requirements](wiki/auth_requirements.md)
- [Deployment Guide](wiki/deployment_guide.md)
- [API Reference](wiki/api_reference.md)
- [Testing Guide](wiki/testing_guide.md)
- [Troubleshooting](wiki/troubleshooting.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.