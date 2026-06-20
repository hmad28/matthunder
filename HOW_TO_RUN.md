# Matthunder v2.0 - Cara Jalanin Tanpa Docker

## Prerequisites
- Python 3.10+
- Node.js 18+
- npm atau yarn

## Setup Backend

```bash
cd backend

# Install dependencies
pip install -r requirements-local.txt

# Run backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Backend akan jalan di: http://localhost:8000
API Docs: http://localhost:8000/docs

## Setup Frontend

```bash
cd frontend

# Install dependencies (kalau belum)
npm install

# Run frontend
npm run dev
```

Frontend akan jalan di: http://localhost:3000

## Quick Start (Windows)

Buka 2 terminal:

**Terminal 1 - Backend:**
```bash
cd C:\Projects\Tools-Automation-main\backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

**Terminal 2 - Frontend:**
```bash
cd C:\Projects\Tools-Automation-main\frontend
npm run dev
```

## Troubleshooting

### Backend Error: ModuleNotFoundError
```bash
cd backend
pip install -r requirements-local.txt
```

### Backend Error: Port already in use
Ganti port:
```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8002 --reload
```

### Frontend Error: npm not found
Install Node.js dari https://nodejs.org/

### Frontend Error: Dependencies missing
```bash
cd frontend
npm install
```

### Database Error
Backend pake SQLite, database file akan otomatis ke-create di `backend/matthunder.db`

Kalau ada error database:
```bash
cd backend
del matthunder.db
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

## Access

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs
- Health Check: http://localhost:8000/health

## Features

- User registration & login
- Target management
- Scan execution (light, dark, deep, pipeline)
- 20+ inline scanners
- AI analysis (OpenAI, Anthropic, Gemini, OpenRouter)
- Real-time scan logs
- Findings management
- Reports generation

## Notes

- Backend pake SQLite (no PostgreSQL needed)
- No Redis/Celery needed (pake background tasks)
- No Docker needed
- All data stored locally
