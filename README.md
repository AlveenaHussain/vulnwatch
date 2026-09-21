vulnwatch/
├── backend/             # FastAPI application
│   ├── main.py          # API endpoints
│   ├── database.py      # PostgreSQL connection helpers
│   ├── requirements.txt # Pinned Python dependencies
│   └── Dockerfile       # Backend container (runs as non-root user)
├── collectors/          # Scripts that send Nmap/log data to the API
├── frontend/            # Dashboard
├── docs/                # Documentation and screenshots
├── docker-compose.yml   # Runs backend + PostgreSQL together
└── .env.example         # Template for local settings (no real secrets)