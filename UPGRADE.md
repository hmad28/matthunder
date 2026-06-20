# Matthunder v2.0 - Total Overhaul

## What's New in v2.0

### Complete Architecture Overhaul
- **Backend**: Migrated from monolithic Python scripts to FastAPI + PostgreSQL + Celery
- **Frontend**: New modern web interface built with Next.js + TypeScript + Tailwind CSS
- **Database**: Upgraded from SQLite to PostgreSQL with proper ORM (SQLAlchemy 2.0)
- **Task Queue**: Added Celery + Redis for distributed async task processing
- **Real-time**: WebSocket support for live scan log streaming
- **Containerization**: Full Docker + Docker Compose setup

### New Features
- **20+ Inline Scanners**: SSTI, CORS, XSS, SQLi, LFI, CRLF, Open Redirect, SSRF, Host Header, GraphQL, and more
- **Multi-Provider AI**: Support for OpenAI, Anthropic, Gemini, OpenRouter
- **Full REST API**: OpenAPI 3.0 documented endpoints
- **Modern Web UI**: Responsive dashboard with real-time updates
- **Pipeline Engine**: 6-phase automated reconnaissance workflow
- **Acunetix Integration**: Pull scans and vulnerabilities from Acunetix

### Technology Stack

#### Backend
- FastAPI (async web framework)
- PostgreSQL 16 (database)
- SQLAlchemy 2.0 (async ORM)
- Celery 5.3 (task queue)
- Redis 7 (cache + broker)
- Pydantic v2 (validation)
- Structlog (logging)

#### Frontend
- Next.js 14 (React framework)
- TypeScript (type safety)
- Tailwind CSS (styling)
- shadcn/ui (components)
- Zustand (state management)
- TanStack Query (server state)

#### Infrastructure
- Docker + Docker Compose
- Nginx (reverse proxy)
- Alembic (database migrations)

### Migration from v1.x

The v1.x CLI tool is still available in the root directory for backward compatibility. The new v2.0 architecture provides:

1. **Web Interface**: Access via http://localhost:3000
2. **REST API**: Full programmatic access via http://localhost:8000
3. **Better Scalability**: PostgreSQL + Celery for concurrent scans
4. **Real-time Updates**: WebSocket streaming of scan logs
5. **Modern UI**: Responsive design with better UX

### Breaking Changes

- Database migrated from SQLite to PostgreSQL
- Configuration moved to environment variables
- API endpoints changed (now versioned: /api/v1/)
- Authentication required (JWT tokens)

### Backward Compatibility

The original CLI tool (`matthunder_cli.py`) remains functional for users who prefer command-line interface. However, new features are only available in the web interface.

## Getting Started

```bash
# Clone repository
git clone https://github.com/hmad28/matthunder.git
cd matthunder

# Configure
cp backend/.env.example backend/.env
# Edit backend/.env

# Start services
docker-compose up -d

# Access
# Frontend: http://localhost:3000
# API Docs: http://localhost:8000/docs
```

## Documentation

- **API Documentation**: http://localhost:8000/docs
- **Architecture**: See [docs/architecture.md](docs/architecture.md)
- **Deployment**: See [docs/deployment.md](docs/deployment.md)

## Support

For issues and questions:
- GitHub Issues: https://github.com/hmad28/matthunder/issues
- Author: [@hmad28](https://github.com/hmad28)
