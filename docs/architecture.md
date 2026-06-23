# Matthunder Architecture

## System Overview

Matthunder v2.0 is a unified security validation platform built on a modern, scalable architecture with clear separation of concerns across multiple layers.

## Architecture Layers

### 1. Client Layer

Three first-class clients communicate with the backend via REST API and WebSocket:

#### Web Dashboard (Next.js 16)
- React 19 with TypeScript
- Tailwind CSS + shadcn/ui components
- Zustand for state management
- Real-time WebSocket connections for scan logs
- JWT authentication with httpOnly cookies
- Responsive design (desktop-first)

#### CLI (Typer)
- Python-based CLI using Typer framework
- Rich library for terminal formatting
- httpx for HTTP requests
- JSON output mode for scripting
- Profile-based configuration (~/.matthunder/config.json)
- API key authentication

#### Telegram Bot
- python-telegram-bot library
- Conversation handlers for multi-step workflows
- Inline keyboards for quick actions
- Approval workflow integration
- Owner-only access control

### 2. API Gateway Layer (Nginx)

- Reverse proxy for backend and frontend
- SSL/TLS termination (production)
- Rate limiting (30 req/min API, 5 req/min login)
- Security headers (X-Frame-Options, CSP, etc.)
- WebSocket proxying with connection upgrades
- Static file caching

### 3. Backend Application Layer (FastAPI)

#### Core Services

**Authentication Service** (`backend/app/services/auth_service.py`)
- JWT access token generation and validation
- Refresh token rotation (7-day expiry)
- API key management for service accounts
- Password hashing with bcrypt
- User registration and login

**Audit Service** (`backend/app/services/audit_service.py`)
- Comprehensive audit logging for all actions
- User activity tracking
- Resource history tracking
- Convenience functions for common audit events

**Approval Service** (`backend/app/services/approval_service.py`)
- Dangerous action detection
- Approval request creation and management
- Review workflow (approve/reject)
- Expiration handling
- Guardrail enforcement

**Scanner Adapter System** (`backend/app/services/scanner_adapter.py`)
- Base `ScannerAdapter` class with standardized interface
- `GoToolAdapter` for Go-based tools (subfinder, httpx, nuclei, etc.)
- `InlinePythonAdapter` for Python-based scanners
- Input validation and scope checking
- Evidence collection with SHA-256 hashing
- Finding candidate generation

**Scan Service** (`backend/app/services/scan_service.py`)
- Scan lifecycle management
- Task dispatch (Celery or background tasks)
- Progress tracking
- Log streaming via Redis pub/sub

**AI Service** (`backend/app/services/ai_service.py`)
- Multi-provider support (OpenAI, Anthropic, Gemini, OpenRouter)
- Prompt engineering and response parsing
- Cost tracking (tokens, USD)
- Analysis history storage

**Acunetix Service** (`backend/app/services/acunetix_service.py`)
- Integration with Acunetix Enterprise
- Scan import and vulnerability sync

#### API Routes

All routes are versioned under `/api/v1/`:

- `/auth` - Authentication and user management
- `/targets` - Target CRUD and scope management
- `/scans` - Scan execution and monitoring
- `/findings` - Finding management and triage
- `/scanners` - Scanner registry and execution
- `/pipeline` - Multi-phase scan pipelines
- `/ai` - AI analysis and hunting
- `/approvals` - Approval workflow
- `/audit` - Audit log queries
- `/reports` - Report generation and download
- `/config` - Configuration management
- `/acunetix` - Acunetix integration

### 4. Task Queue Layer (Celery + Redis)

#### Worker Types

**Scan Workers** (concurrency=4)
- Execute scanner adapters
- Collect evidence and findings
- Stream logs via Redis pub/sub
- Handle timeouts and retries

**AI Workers** (concurrency=2)
- Run AI analysis tasks
- Structured output parsing
- Cost tracking

**Report Workers** (concurrency=2)
- Generate PDF/HTML reports
- Aggregate findings
- Format output

#### Task Dispatch

```python
# Celery mode (production)
if settings.CELERY_BROKER_URL:
    task = run_scan_task.delay(scan_id)
    
# Background mode (development)
else:
    background_tasks.add_task(execute_scan, scan_id)
```

### 5. Data Layer

#### PostgreSQL Database

**Core Tables:**
- `users` - User accounts with roles
- `targets` - Target domains with scope rules
- `scans` - Scan execution records
- `findings` - Vulnerability findings
- `scan_logs` - Real-time log entries
- `reports` - Generated reports

**Enhanced Tables:**
- `audit_logs` - Comprehensive audit trail
- `approval_requests` - Approval workflow
- `evidence` - Evidence files with hashes
- `scope_rules` - Target scope definitions
- `refresh_tokens` - JWT refresh tokens
- `api_keys` - Service account API keys
- `target_verifications` - Target verification records
- `rate_limits` - Per-target rate limits
- `scan_templates` - Predefined scan configs
- `finding_comments` - Finding annotations
- `finding_relationships` - Finding relationships

**Database Features:**
- SQLAlchemy 2.0 async ORM
- Alembic migrations for schema versioning
- Composite indexes for performance
- Foreign key constraints with cascades
- JSON columns for flexible metadata

#### Redis

- **Cache**: Session data, rate limit counters
- **Pub/Sub**: Real-time log streaming
- **Celery Broker**: Task queue backend
- **Celery Backend**: Task result storage

#### File Storage

- **Evidence Files**: Screenshots, HTTP responses, source code
- **Reports**: PDF, HTML, JSON exports
- **Scan Outputs**: Raw scanner output files

Storage locations configured via:
- `UPLOAD_DIR` (default: ./uploads)
- `REPORTS_DIR` (default: ./reports)
- `SCANS_DIR` (default: ./scans)

## Data Flow

### Scan Execution Flow

```
1. User creates scan via API
   ↓
2. Backend validates target ownership and scope
   ↓
3. Approval service checks if approval required
   ├─ Yes → Create approval request, wait for review
   └─ No → Continue
   ↓
4. Dispatch scan task to Celery worker
   ↓
5. Worker executes scanner adapters in sequence
   ├─ Validate input
   ├─ Check scope
   ├─ Execute scanner
   ├─ Collect evidence
   └─ Generate findings
   ↓
6. Stream logs via Redis pub/sub → WebSocket → Client
   ↓
7. Store findings and evidence in database
   ↓
8. Update scan status to completed
   ↓
9. Notify user via WebSocket/Telegram
```

### Approval Workflow

```
1. User requests dangerous action (e.g., deep scan)
   ↓
2. Approval service detects dangerous pattern
   ↓
3. Create approval request with payload
   ↓
4. Notify reviewers via WebSocket/Telegram
   ↓
5. Reviewer approves/rejects via Web/CLI/Bot
   ↓
6. If approved → Execute action
   If rejected → Notify requestor
   If expired → Mark as expired
```

### Authentication Flow

```
1. User logs in with username/password
   ↓
2. Backend validates credentials
   ↓
3. Generate JWT access token (30 min)
   ↓
4. Generate refresh token (7 days)
   ↓
5. Store refresh token in database
   ↓
6. Return both tokens to client
   ↓
7. Client uses access token for API requests
   ↓
8. When access token expires:
   ├─ Client calls /auth/refresh with refresh token
   ├─ Backend validates refresh token
   ├─ Backend revokes old refresh token
   ├─ Backend generates new access + refresh tokens
   └─ Client stores new tokens
```

## Security Architecture

### Authentication

- **JWT Access Tokens**: Short-lived, stateless, signed with HMAC-SHA256
- **Refresh Tokens**: Long-lived, stored in database, rotatable, revocable
- **API Keys**: For service accounts, scoped permissions, expirable

### Authorization

- **Owner Validation**: All resources check `created_by` field
- **Superuser Role**: Elevated privileges for admin operations
- **Scope Enforcement**: Targets validated against scope rules before scanning

### Network Security

- **Private IP Blocking**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
- **Localhost Blocking**: 127.0.0.1, ::1
- **Local Domain Blocking**: .local, .lan, .internal
- **WebSocket Authentication**: Token-based auth with ownership validation
- **Origin Validation**: CORS restricted to configured origins

### Rate Limiting

- **API**: 30 requests/minute per IP (burst: 20)
- **Login**: 5 requests/minute per IP (burst: 3)
- **WebSocket**: Connection limits per user

### Audit Trail

All actions logged with:
- User ID
- Action type (e.g., "scan.create", "finding.update")
- Resource type and ID
- Timestamp
- IP address
- User agent
- Status (success/failure)

### Secret Management

- **Environment Variables**: All secrets via .env files
- **No Hardcoded Credentials**: Database passwords, API keys, etc.
- **Git Ignore**: .env files excluded from version control
- **Secret Redaction**: AI prompts and logs redact sensitive patterns

## Scalability

### Horizontal Scaling

**Backend**:
- Stateless FastAPI instances behind Nginx
- Load balance across multiple containers
- Shared PostgreSQL and Redis

**Celery Workers**:
- Scale workers independently: `docker-compose up --scale celery-worker=4`
- Different worker pools for different task types
- Priority queues for critical tasks

**Database**:
- PostgreSQL read replicas for query scaling
- Connection pooling (pool_size=5, max_overflow=10)
- Query optimization with composite indexes

### Performance Optimizations

- **Async I/O**: All database operations use async/await
- **Connection Pooling**: SQLAlchemy async engine with connection pool
- **Caching**: Redis cache for frequently accessed data
- **Pagination**: All list endpoints support skip/limit
- **Indexing**: Composite indexes on foreign keys and status fields
- **WebSocket**: Redis pub/sub for efficient log distribution

## Monitoring & Observability

### Logging

- **Structured Logging**: structlog with JSON output
- **Log Levels**: DEBUG, INFO, WARNING, ERROR, CRITICAL
- **Context Variables**: Request ID, user ID, scan ID
- **Log Aggregation**: Compatible with ELK, Loki, etc.

### Health Checks

- **Backend**: `GET /health` returns database and Redis status
- **PostgreSQL**: `pg_isready` health check
- **Redis**: `redis-cli ping` health check
- **Docker**: Health checks configured in docker-compose.yml

### Metrics (Future)

- Prometheus metrics endpoint
- Request latency histograms
- Scan execution times
- AI token usage
- Error rates

## Deployment Modes

### Development (Local)

```bash
# Backend with SQLite (no PostgreSQL needed)
cd backend
uvicorn app.main:app --reload

# Frontend
cd frontend
npm run dev
```

### Production (Docker)

```bash
# All services in containers
docker-compose up -d

# With custom .env
POSTGRES_PASSWORD=strong-password docker-compose up -d
```

### Hybrid (Local Backend + Docker Services)

```bash
# Start PostgreSQL and Redis
docker-compose up -d postgres redis

# Run backend locally
cd backend
uvicorn app.main:app --reload
```

## Technology Stack

### Backend
- **Framework**: FastAPI 0.110+
- **ORM**: SQLAlchemy 2.0 (async)
- **Database**: PostgreSQL 16
- **Cache/Queue**: Redis 7
- **Task Queue**: Celery 5.3+
- **Authentication**: python-jose (JWT), passlib (bcrypt)
- **Validation**: Pydantic 2.6+
- **HTTP Client**: httpx 0.27+
- **Logging**: structlog 24.1+

### Frontend
- **Framework**: Next.js 16
- **UI Library**: React 19
- **Language**: TypeScript 5.4+
- **Styling**: Tailwind CSS 3.4+
- **Components**: shadcn/ui (Radix UI)
- **State**: Zustand 4.5+
- **HTTP**: Axios 1.6+
- **Icons**: Lucide React

### CLI
- **Framework**: Typer 0.12+
- **Formatting**: Rich 13.7+
- **HTTP**: httpx 0.27+

### Bot
- **Framework**: python-telegram-bot 20.7+
- **HTTP**: httpx 0.27+

### Infrastructure
- **Reverse Proxy**: Nginx
- **Containerization**: Docker + Docker Compose
- **CI/CD**: GitHub Actions (recommended)

## Future Enhancements

### Planned Features

1. **MCP Integration**: Model Context Protocol for AI tool orchestration
2. **Graph Database**: Neo4j for finding relationships and attack paths
3. **Vector Search**: pgvector for semantic finding deduplication
4. **Multi-Tenancy**: Team-based access control
5. **Plugin System**: Custom scanner adapters
6. **Webhook Integrations**: Slack, Discord, Jira notifications
7. **Compliance Reports**: PCI-DSS, HIPAA, SOC2 templates
8. **Attack Path Visualization**: Interactive graph of attack chains
9. **Collaborative Triage**: Multi-user finding review workflow
10. **API Rate Limit Dashboard**: Visual rate limit monitoring

### Architecture Improvements

1. **Microservices**: Split into auth, scan, finding, report services
2. **Event Sourcing**: Full event log for all state changes
3. **CQRS**: Separate read/write models for performance
4. **Service Mesh**: Istio for inter-service communication
5. **Kubernetes**: Migrate from Docker Compose to K8s
6. **Observability Stack**: Prometheus + Grafana + Jaeger

## Conclusion

Matthunder v2.0 provides a modern, scalable, and secure architecture for automated security testing. The unified backend control plane ensures consistency across all clients, while the approval workflow and audit trail provide the governance needed for authorized security operations.

The modular design allows for easy extension with new scanners, AI providers, and integrations, making it a flexible platform for bug bounty programs and penetration testing engagements.
