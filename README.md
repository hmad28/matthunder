# Matthunder v2.0 - Total Overhaul

> AI-Powered Bug Hunting & Penetration Testing Automation Platform

## Overview

Matthunder is a comprehensive bug bounty reconnaissance and vulnerability scanning automation platform. Version 2.0 represents a complete architectural overhaul with modern technologies.

## Architecture

### Shared Core Engine
- **matthunder_core** - single service layer for CLI, Web, and Telegram surfaces
- **Scope gatekeeper** - public target validation is enforced before scan execution
- **Scanner registry metadata** - canonical scanner list with aliases and mode metadata
- **SQLite progress state** - `scans` rows include `progress_pct`, `current_stage`, and `error_message`

### Backend (FastAPI + PostgreSQL + Celery)
- **FastAPI** - Modern async web framework
- **PostgreSQL** - Robust relational database
- **SQLAlchemy 2.0** - Async ORM
- **Celery + Redis** - Distributed task queue
- **WebSocket** - Real-time scan logs

### Frontend (Next.js + TypeScript)
- **Next.js 14** - React framework with App Router
- **TypeScript** - Type safety
- **Tailwind CSS** - Utility-first styling
- **shadcn/ui** - Accessible components
- **Zustand** - State management

### Infrastructure
- **Docker + Docker Compose** - Containerization
- **Nginx** - Reverse proxy
- **Redis** - Cache + message broker

## Features

### Scanning
- **Light Scan** - Quick recon (subfinder + httpx + nuclei)
- **Dark Scan** - Medium recon (adds assetfinder + katana)
- **Deep Scan** - Full recon (4-stage nuclei + takeover)
- **Pipeline** - 6-phase automated workflow

### Unified Interfaces
- **CLI** - `matthunder_cli.py` delegates scan execution through `matthunder_core`
- **Web** - `web/` uses the same service layer for deep scans, inline scanners, and pipeline runs
- **Telegram Bot** - `/deep`, `/light`, `/dark`, `/blh`, `/tpa`, `/cred`, `/takeover`, and `/sensitive` share the same scan path

### Inline Scanners (20+)
- **Discovery**: BLH, TPA, Cred
- **Vulnerability**: SSTI, CORS, XSS, SQLi, LFI, CRLF, Open Redirect, SSRF, Host Header, GraphQL
- **Infrastructure**: Port Scan, WAF Detection, JS Analysis, Fuzzer, Tech Fingerprint, Attack Rank, GF Patterns

### AI Integration
- Multi-provider support (OpenAI, Anthropic, Gemini, OpenRouter)
- AI-powered vulnerability analysis
- Automated hunting with context
- Remediation suggestions

### Integrations
- **Acunetix** - Pull scans and vulnerabilities
- **WebSocket** - Real-time log streaming
- **REST API** - Full programmatic access

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Git

### Installation

1. Clone the repository:
```bash
git clone https://github.com/hmad28/matthunder.git
cd matthunder
```

2. Configure environment:
```bash
cp backend/.env.example backend/.env
# Edit backend/.env with your settings
```

3. Start all services:
```bash
docker-compose up -d
```

4. Access the application:
- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

## Development

### Backend
```bash
cd backend
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

### Database Migrations
```bash
cd backend
alembic upgrade head
```

## Configuration

### Environment Variables

#### Backend (.env)
```env
# Database
DATABASE_URL=postgresql+asyncpg://user:pass@localhost:5432/matthunder

# Redis
REDIS_URL=redis://localhost:6379/0

# AI Providers (BYOK)
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GEMINI_API_KEY=...
OPENROUTER_API_KEY=sk-or-...

# Acunetix
ACUNETIX_URL=https://localhost:3443
ACUNETIX_API_KEY=your_key
```

#### Frontend (.env.local)
```env
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_WS_URL=ws://localhost:8000
```

## API Documentation

Interactive API documentation available at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Key Endpoints

#### Authentication
- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Login and get token

#### Targets
- `GET /api/v1/targets` - List targets
- `POST /api/v1/targets` - Create target
- `DELETE /api/v1/targets/{id}` - Delete target

#### Scans
- `GET /api/v1/scans` - List scans
- `POST /api/v1/scans` - Start scan
- `GET /api/v1/scans/{id}/status` - Get scan status
- `WS /api/v1/scans/{id}/ws` - Real-time logs

#### Findings
- `GET /api/v1/findings` - List findings
- `GET /api/v1/findings/stats` - Get statistics

#### Scanners
- `GET /api/v1/scanners` - List available scanners
- `POST /api/v1/scanners/{name}/run` - Run scanner

#### AI
- `GET /api/v1/ai/providers` - List AI providers
- `POST /api/v1/ai/analyze` - Analyze with AI
- `POST /api/v1/ai/hunt` - AI-powered hunting

## Project Structure

```
matthunder/
├── backend/
│   ├── app/
│   │   ├── api/v1/          # API routes
│   │   ├── core/            # Core utilities
│   │   ├── models/          # SQLAlchemy models
│   │   ├── schemas/         # Pydantic schemas
│   │   ├── services/        # Business logic
│   │   └── tasks/           # Celery tasks
│   ├── alembic/             # Database migrations
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   │   ├── app/             # Next.js pages
│   │   ├── components/      # React components
│   │   ├── lib/             # Utilities
│   │   └── types/           # TypeScript types
│   └── package.json
│
├── docker/
│   └── nginx/               # Nginx config
│
└── docker-compose.yml
```

## Security Notice

This tool is for **authorized security testing only**. You are responsible for how you use it. Do not scan targets without explicit permission.

## License

MIT License - See LICENSE file for details

## Author

**Matt (hmad28)**
- GitHub: [@hmad28](https://github.com/hmad28)
- Repository: [hmad28/matthunder](https://github.com/hmad28/matthunder)

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## Changelog

### v2.0.0 (2026)
- Complete architectural overhaul
- Migrated to FastAPI + PostgreSQL backend
- New Next.js + TypeScript frontend
- Added Celery for async task processing
- WebSocket support for real-time logs
- Multi-provider AI integration
- Docker containerization
- 20+ inline vulnerability scanners
- Full REST API with OpenAPI docs

### v1.x (Legacy)
- Original CLI-based tool
- SQLite database
- Basic Telegram bot integration
