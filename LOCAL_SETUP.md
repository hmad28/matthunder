# Matthunder v2.0 - Local Development Setup

## Quick Start (Tanpa Docker)

### 1. Backend Setup

```bash
cd backend
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

pip install -r requirements-local.txt

# Database akan auto-create (SQLite)
python -m uvicorn app.main:app --reload --port 8000
```

### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

### 3. Access

- Frontend: http://localhost:3000
- Backend: http://localhost:8000
- API Docs: http://localhost:8000/docs

## Features

- SQLite database (no setup needed)
- Background tasks (no Celery/Redis needed)
- Hot reload for development
- All features working

## Notes

- Database file: `backend/matthunder.db`
- For production, switch to PostgreSQL + Celery + Redis
