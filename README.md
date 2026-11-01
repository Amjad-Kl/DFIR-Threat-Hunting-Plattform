# 🛡️ Threat Hunting Workbench

A local, offline-first DFIR and Threat Hunting platform for analyzing forensic artifacts and security data to find indicators of compromise, malware, and suspicious activity.

## Philosophy

- **Local only** – No cloud, no telemetry, no background processes
- **Manual analysis** – The analyst decides when to run analyses
- **Iterative development** – Each version is fully usable and stable
- **Forensic integrity** – SHA-256 hashing and audit logging from day one

## Current Version: v1 (MVP) – In Development

### Features
- Windows Event Log (EVTX) parsing
- Sysmon Log analysis
- Registry artifact extraction (Persistence, UserAssist, ShellBags)
- Prefetch file analysis
- Amcache/Shimcache parsing
- Unified timeline generation
- IOC matching (hashes, IPs, domains, filenames)
- YARA rule scanning
- Persistence mechanism detection
- Suspicious event pattern detection
- Case management with evidence integrity
- HTML/PDF report generation

## Tech Stack

| Component | Technology |
|---|---|
| Backend | Python 3.12+ / FastAPI |
| Database | SQLite + FTS5 |
| Frontend | React + TypeScript + Vite |
| Visualization | Recharts + D3.js + Cytoscape.js |
| Parsers | python-evtx, dissect, yara-python |
| Reporting | Jinja2 + WeasyPrint |

## Project Structure

```
threat-hunting-workbench/
├── backend/
│   ├── app/
│   │   ├── api/              # REST API endpoints
│   │   ├── models/            # Data models (Pydantic + DB)
│   │   ├── parsers/           # Artifact parsers
│   │   ├── analysis/          # Analysis engines
│   │   ├── reporting/         # Report generation
│   │   └── utils/             # Utilities (hashing, audit)
│   ├── tests/                 # Test suites
│   └── data/                  # Default rules & IOC lists
├── frontend/
│   └── src/
│       ├── components/        # React components
│       ├── hooks/             # Custom React hooks
│       ├── services/          # API client
│       ├── types/             # TypeScript type definitions
│       └── utils/             # Frontend utilities
├── docs/                      # Documentation
└── scripts/                   # Setup & migration scripts
```

## Roadmap

- **v1 (MVP):** Windows Artifact Investigator
- **v2:** Detection & Correlation Engine (Sigma, MITRE ATT&CK)
- **v3:** Network Forensics (PCAP, DNS, Beaconing)
- **v4:** Memory Forensics (Volatility 3, EDR Integration)
- **v5:** AI-Assisted Analysis (Ollama, Local LLM)

## Setup

```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
python -m app.main

# Frontend
cd frontend
npm install
npm run dev
```

## License

MIT
