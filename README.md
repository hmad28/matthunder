# Matthunder v2.0

**AI-Powered Bug Hunting & Penetration Testing Automation Platform**

Matthunder is a unified security validation platform with one backend control plane, one scanner orchestration layer, and three first-class clients: Web Dashboard, CLI, and Telegram Bot.

## 🎯 Overview

Matthunder provides operator-supervised, scope-aware, approval-gated automation for authorized security testing. Every high-impact action is guardrailed, auditable, and stoppable.

### Key Features

- **Unified Backend Control Plane**: FastAPI-based backend with PostgreSQL, Celery workers, and Redis
- **Multi-Client Architecture**: Web dashboard, CLI, and Telegram bot all talk to the same backend
- **Scanner Orchestration**: 20+ inline scanners + Go tool adapters with standardized execution contracts
- **Approval Workflow**: Dangerous operations require explicit approval before execution
- **Audit Trail**: Complete audit logging of all actions with user attribution
- **AI Integration**: Multi-provider AI analysis (OpenAI, Anthropic, Gemini, OpenRouter)
- **Real-Time Updates**: WebSocket-based live scan log streaming
- **Scope Enforcement**: Automatic validation of targets against authorized scope
- **Evidence Management**: Structured evidence collection with file hashing and deduplication

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Client Layer                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Web Dashboard│  │     CLI      │  │ Telegram Bot │      │
│  │  (Next.js)   │  │   (Typer)    │  │              │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
└─────────┼──────────────────┼──────────────────┼─────────────┘
          │                  │                  │
          └──────────────────┼──────────────────┘
                             │ HTTPS / WSS
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                  Backend Control Plane                        │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              FastAPI Application                       │  │
│  │  • Authentication (JWT + Refresh Tokens + API Keys)   │  │
│  │  • Rate Limiting (slowapi)                            │  │
│  │  • CORS & Security Headers                            │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Auth Service │  │ Audit Service│  │Approval Svc  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │           Scanner Adapter Registry                     │  │
│  │  • Go Tool Adapters (subfinder, httpx, nuclei, etc.) │  │
│  │  • Inline Python Scanners (XSS, SQLi, LFI, etc.)     │  │
│  │  • Standardized Input/Output Contracts                 │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              Celery Worker Pool                        │  │
│  │  • Scan Execution Workers                             │  │
│  │  • AI Analysis Workers                                │  │
│  │  • Report Generation Workers                          │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
          │                  │                  │
          ▼                  ▼                  ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  PostgreSQL  │  │    Redis     │  │ File Storage │
│   (Database) │  │ (Cache+Queue)│  │  (Evidence)  │
└──────────────┘  └──────────────┘  └──────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.10+ (for local development)
- Node.js 20+ (for frontend development)

### 1. Clone the Repository

```bash
git clone https://github.com/hmad28/matthunder.git
cd matthunder
```

### 2. Configure Environment

Create a `.env` file in the root directory:

```bash
# Database
POSTGRES_USER=matthunder
POSTGRES_PASSWORD=your-secure-password-here
POSTGRES_DB=matthunder

# Backend
SECRET_KEY=your-super-secret-key-min-32-chars
CORS_ORIGINS=["http://localhost:3000"]

# Optional: AI Providers
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
GEMINI_API_KEY=...
OPENROUTER_API_KEY=...

# Optional: Telegram Bot
MATTHUNDER_BOT_TOKEN=...
MATTHUNDER_OWNER_ID=...
MATTHUNDER_API_TOKEN=...
```

### 3. Start with Docker Compose

```bash
docker-compose up -d
```

This starts:
- **PostgreSQL** on port 5432
- **Redis** on port 6379
- **Backend API** on port 8000
- **Celery Worker** (background tasks)
- **Celery Beat** (scheduled tasks)
- **Frontend** on port 3000
- **Nginx** reverse proxy on port 80

### 4. Access the Platform

- **Web Dashboard**: http://localhost:3000
- **API Documentation**: http://localhost:8000/docs
- **API (via Nginx)**: http://localhost/api/v1/

### 5. Create Your First User

```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "email": "admin@example.com", "password": "securepassword"}'
```

## 📚 Usage

### Web Dashboard

1. Navigate to http://localhost:3000
2. Login with your credentials
3. Add a target: **Targets** → **Add Target**
4. Start a scan: **Scans** → **New Scan**
5. View real-time logs via WebSocket
6. Review findings in the **Findings** tab
7. Generate reports in the **Reports** tab

### CLI

Install the CLI:

```bash
cd cli
pip install -e .
```

Login:

```bash
matthunder login --username admin --password securepassword
```

Manage targets:

```bash
# List targets
matthunder targets list

# Add target
matthunder targets add --domain example.com

# Delete target
matthunder targets delete --id <target-id>
```

Run scans:

```bash
# Start a deep scan
matthunder scan <target-id> --type deep --speed standard

# List recent scans
matthunder scans --limit 10

# View scan logs
matthunder logs <scan-id> --limit 100

# Cancel a running scan
matthunder cancel <scan-id>
```

View findings:

```bash
# List all findings
matthunder findings --limit 50

# Filter by severity
matthunder findings --severity critical

# Filter by scan
matthunder findings --scan <scan-id>
```

Manage approvals:

```bash
# List pending approvals
matthunder approvals --status pending

# Approve a request
matthunder review-approval <approval-id> approve --comment "Looks good"

# Reject a request
matthunder review-approval <approval-id> reject --comment "Out of scope"
```

Download reports:

```bash
# List available reports
matthunder reports --limit 20

# Download a report
matthunder download-report <report-id> --output report.pdf
```

JSON output mode:

```bash
# All commands support --json flag for machine-readable output
matthunder targets list --json
matthunder findings --json
```

### Telegram Bot

1. Create a bot via [@BotFather](https://t.me/BotFather)
2. Set environment variables:
   ```bash
   export MATTHUNDER_BOT_TOKEN="your-bot-token"
   export MATTHUNDER_OWNER_ID="your-telegram-user-id"
   export MATTHUNDER_API_TOKEN="your-api-token"
   ```
3. Start the bot:
   ```bash
   cd bot
   pip install -r requirements.txt
   python telegram_bot/main.py
   ```
4. In Telegram:
   - `/start` - Show main menu
   - `/targets` - List targets
   - `/scans` - Show recent scans
   - `/findings` - Show recent findings
   - `/approvals` - View pending approvals
   - `/cancel <scan-id>` - Cancel a running scan
   - `/settings` - View configuration
   - `/help` - Show help

## 🔒 Security Model

### Authentication

- **JWT Access Tokens**: Short-lived (30 minutes), used for API requests
- **Refresh Tokens**: Long-lived (7 days), stored in database, rotatable
- **API Keys**: For service accounts (CLI, bot, integrations)

### Authorization

- **Owner Validation**: All resources validate ownership before access
- **Superuser Role**: Elevated privileges for admin operations
- **Scope Enforcement**: Targets are validated against authorized scope before scanning

### Approval Workflow

Dangerous operations require explicit approval:

- Deep scans (resource-intensive)
- AI-powered hunting (costly)
- Bulk operations
- Out-of-scope targets

Approval requests can be reviewed via:
- Web Dashboard (Approvals page)
- CLI (`matthunder approvals`, `matthunder review-approval`)
- Telegram Bot (`/approvals` command)

### Audit Trail

All actions are logged with:
- User ID
- Action type
- Resource type and ID
- Timestamp
- IP address
- User agent

View audit logs:
- Web Dashboard (Admin → Audit Logs)
- API: `GET /api/v1/audit`

### Network Guardrails

- Private IP ranges blocked by default (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Localhost blocked (127.0.0.1, ::1)
- Local domains blocked (.local, .lan, .internal)
- Explicit authorization required for private ranges

### Rate Limiting

- API: 30 requests/minute per IP (burst: 20)
- Login: 5 requests/minute per IP (burst: 3)
- Configurable via slowapi

### Security Headers

All responses include:
- `X-Frame-Options: SAMEORIGIN`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Content-Security-Policy`: Configured for self-hosted resources

## 🛠️ Development

### Local Backend Development

```bash
cd backend
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements-local.txt

# Run with SQLite (no PostgreSQL needed)
uvicorn app.main:app --reload --port 8000
```

### Local Frontend Development

```bash
cd frontend
npm install
npm run dev
```

### Running Tests

```bash
# Backend tests
cd backend
pytest

# Frontend E2E tests
cd frontend
npm run e2e
```

### Database Migrations

```bash
cd backend

# Generate migration
alembic revision --autogenerate -m "description"

# Apply migrations
alembic upgrade head

# Rollback
alembic downgrade -1
```

## 📊 Scanner Categories

### Discovery
- **BLH**: Broken Link Hunter
- **TPA**: Third-Party Asset discovery
- **Cred**: Credential URL finder

### Vulnerability
- **SSTI**: Server-Side Template Injection
- **CORS**: CORS Misconfiguration
- **XSS**: Cross-Site Scripting
- **SQLi**: SQL Injection
- **LFI**: Local File Inclusion
- **CRLF**: CRLF Injection
- **OpenRedirect**: Open Redirect
- **SSRF**: Server-Side Request Forgery
- **HostHeader**: Host Header Injection
- **GraphQL**: GraphQL Introspection

### Infrastructure
- **PortScan**: Port scanning
- **WAF**: Web Application Firewall detection
- **JSAnalysis**: JavaScript analysis
- **Fuzzer**: Directory/path fuzzing
- **TechFingerprint**: Technology fingerprinting
- **AttackRank**: Attack surface ranking
- **GFPatterns**: GF pattern filtering

## 🔌 API Reference

Full API documentation available at:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **OpenAPI JSON**: http://localhost:8000/openapi.json

### Authentication Endpoints

- `POST /api/v1/auth/register` - Register new user
- `POST /api/v1/auth/login` - Login (HTTP Basic Auth)
- `POST /api/v1/auth/refresh` - Refresh access token
- `POST /api/v1/auth/logout` - Logout (revoke tokens)
- `GET /api/v1/auth/me` - Get current user
- `POST /api/v1/auth/api-keys` - Create API key
- `GET /api/v1/auth/api-keys` - List API keys
- `DELETE /api/v1/auth/api-keys/{key_id}` - Revoke API key

### Target Endpoints

- `GET /api/v1/targets` - List targets
- `POST /api/v1/targets` - Create target
- `GET /api/v1/targets/{id}` - Get target
- `PUT /api/v1/targets/{id}` - Update target
- `DELETE /api/v1/targets/{id}` - Delete target

### Scan Endpoints

- `GET /api/v1/scans` - List scans
- `POST /api/v1/scans` - Create scan
- `GET /api/v1/scans/{id}` - Get scan
- `POST /api/v1/scans/{id}/stop` - Stop scan
- `GET /api/v1/scans/{id}/logs` - Get scan logs
- `WS /api/v1/scans/{id}/ws` - WebSocket for real-time logs

### Finding Endpoints

- `GET /api/v1/findings` - List findings
- `GET /api/v1/findings/stats` - Get finding statistics
- `GET /api/v1/findings/{id}` - Get finding
- `PUT /api/v1/findings/{id}` - Update finding

### Approval Endpoints

- `POST /api/v1/approvals` - Create approval request
- `GET /api/v1/approvals` - List approval requests
- `GET /api/v1/approvals/{id}` - Get approval request
- `POST /api/v1/approvals/{id}/review` - Review approval
- `POST /api/v1/approvals/{id}/cancel` - Cancel approval

### Audit Endpoints

- `GET /api/v1/audit` - List audit logs (superuser)
- `GET /api/v1/audit/me` - Get current user's audit logs
- `GET /api/v1/audit/me/activity` - Get activity summary

### Scanner Endpoints

- `GET /api/v1/scanners` - List available scanners
- `POST /api/v1/scanners/{name}/run` - Run scanner

### AI Endpoints

- `GET /api/v1/ai/providers` - List AI providers
- `POST /api/v1/ai/analyze` - Run AI analysis
- `POST /api/v1/ai/hunt` - Run AI-powered hunting

### Report Endpoints

- `GET /api/v1/reports` - List reports
- `GET /api/v1/reports/{id}` - Get report
- `GET /api/v1/reports/{id}/download` - Download report

## 🐳 Docker Deployment

### Production Deployment

1. Set strong passwords in `.env`:
   ```bash
   POSTGRES_PASSWORD=your-strong-password
   SECRET_KEY=your-strong-secret-key
   ```

2. Start services:
   ```bash
   docker-compose up -d
   ```

3. Check logs:
   ```bash
   docker-compose logs -f
   ```

4. Stop services:
   ```bash
   docker-compose down
   ```

### Scaling Workers

Edit `docker-compose.yml`:

```yaml
celery-worker:
  command: celery -A app.tasks.celery_app worker --loglevel=info --concurrency=8
```

Or run multiple workers:

```bash
docker-compose up -d --scale celery-worker=4
```

## 📝 Configuration

### Backend Configuration

All backend configuration via environment variables in `backend/.env`:

- `DATABASE_URL`: PostgreSQL connection string
- `REDIS_URL`: Redis connection string
- `CELERY_BROKER_URL`: Celery broker URL
- `SECRET_KEY`: JWT signing key (min 32 chars)
- `CORS_ORIGINS`: Allowed CORS origins (JSON array)
- `ACCESS_TOKEN_EXPIRE_MINUTES`: JWT expiration (default: 30)
- `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.: AI provider keys
- `ACUNETIX_URL`, `ACUNETIX_API_KEY`: Acunetix integration

### Frontend Configuration

Environment variables in `frontend/.env.local`:

- `NEXT_PUBLIC_API_URL`: Backend API URL
- `NEXT_PUBLIC_WS_URL`: WebSocket URL

## 🔄 Migration from v1

The v2 architecture is a complete rewrite. Key changes:

- **Database**: SQLite → PostgreSQL (with migration support)
- **Authentication**: None → JWT + Refresh Tokens + API Keys
- **Task Queue**: Synchronous → Celery + Redis
- **Real-Time**: None → WebSocket
- **Frontend**: Legacy SPA → Next.js 16 + TypeScript
- **CLI**: Monolithic script → Typer-based modular CLI
- **Bot**: Single-owner → Multi-user with approval workflow

### Migrating Data

1. Export data from v1 SQLite database
2. Transform to v2 schema
3. Import via API or direct database insertion

See `docs/migration-guide.md` for detailed instructions.

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details

## ⚠️ Disclaimer

Matthunder is designed for **authorized security testing only**. Users must:

- Have explicit permission to test target systems
- Comply with all applicable laws and regulations
- Follow responsible disclosure practices
- Use the platform ethically and responsibly

The developers are not responsible for misuse or unauthorized testing.

## 🙏 Acknowledgments

Built with:
- FastAPI
- SQLAlchemy
- Celery
- Next.js
- React
- Typer
- python-telegram-bot
- And many more open-source libraries

---

**Version**: 2.0.0  
**Last Updated**: 2026-01-20  
**Repository**: https://github.com/hmad28/matthunder
