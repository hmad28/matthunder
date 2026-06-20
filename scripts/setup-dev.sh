#!/bin/bash

# Matthunder v2.0 - Development Setup Script

set -e

echo "⚡ Matthunder v2.0 - Development Setup"
echo "======================================"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed."
    exit 1
fi

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed."
    exit 1
fi

echo "✓ Python and Node.js found"
echo ""

# Backend setup
echo "Setting up backend..."
cd backend

# Create virtual environment
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✓ Created virtual environment"
fi

# Activate and install dependencies
source venv/bin/activate
pip install -r requirements.txt
echo "✓ Backend dependencies installed"

# Create .env if not exists
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "✓ Created .env file"
fi

cd ..

# Frontend setup
echo ""
echo "Setting up frontend..."
cd frontend

# Install dependencies
npm install
echo "✓ Frontend dependencies installed"

cd ..

# CLI setup
echo ""
echo "Setting up CLI..."
cd cli

# Create virtual environment
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✓ Created CLI virtual environment"
fi

# Activate and install dependencies
source venv/bin/activate
pip install -r requirements.txt
echo "✓ CLI dependencies installed"

cd ..

# Bot setup
echo ""
echo "Setting up Telegram bot..."
cd bot

# Create virtual environment
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✓ Created bot virtual environment"
fi

# Activate and install dependencies
source venv/bin/activate
pip install -r requirements.txt
echo "✓ Bot dependencies installed"

cd ..

echo ""
echo "======================================"
echo "✅ Development setup complete!"
echo ""
echo "To start development:"
echo ""
echo "1. Start infrastructure (PostgreSQL + Redis):"
echo "   docker-compose up postgres redis"
echo ""
echo "2. Start backend:"
echo "   cd backend"
echo "   source venv/bin/activate"
echo "   uvicorn app.main:app --reload"
echo ""
echo "3. Start frontend:"
echo "   cd frontend"
echo "   npm run dev"
echo ""
echo "4. Start Celery worker (in another terminal):"
echo "   cd backend"
echo "   source venv/bin/activate"
echo "   celery -A app.tasks.celery_app worker --loglevel=info"
echo ""
echo "5. Access the application:"
echo "   Frontend: http://localhost:3000"
echo "   Backend: http://localhost:8000"
echo "   API Docs: http://localhost:8000/docs"
echo "======================================"
