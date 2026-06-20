#!/bin/bash

# Matthunder v2.0 - Setup Script for Linux/macOS

set -e

echo "⚡ Matthunder v2.0 - Setup"
echo "========================="
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    echo "   https://docs.docker.com/get-docker/"
    exit 1
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    echo "   https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✓ Docker and Docker Compose found"
echo ""

# Create backend .env
if [ ! -f backend/.env ]; then
    echo "Creating backend/.env from template..."
    cp backend/.env.example backend/.env
    echo "✓ Created backend/.env"
    echo ""
    echo "⚠️  IMPORTANT: Edit backend/.env and set your configuration:"
    echo "   - SECRET_KEY (change this!)"
    echo "   - AI provider API keys (optional)"
    echo "   - Acunetix settings (optional)"
    echo ""
else
    echo "✓ backend/.env already exists"
fi

# Create necessary directories
echo "Creating directories..."
mkdir -p backend/scans backend/reports backend/uploads
echo "✓ Directories created"
echo ""

# Pull Docker images
echo "Pulling Docker images (this may take a few minutes)..."
docker-compose pull
echo "✓ Images pulled"
echo ""

# Build and start services
echo "Building and starting services..."
docker-compose up -d --build
echo "✓ Services started"
echo ""

# Wait for services to be ready
echo "Waiting for services to be ready..."
sleep 10

# Check health
echo "Checking service health..."
if curl -f http://localhost:8000/health > /dev/null 2>&1; then
    echo "✓ Backend is healthy"
else
    echo "⚠️  Backend may still be starting. Check logs with: docker-compose logs backend"
fi

echo ""
echo "========================="
echo "✅ Setup complete!"
echo ""
echo "Access the application:"
echo "  Frontend: http://localhost:3000"
echo "  Backend API: http://localhost:8000"
echo "  API Docs: http://localhost:8000/docs"
echo ""
echo "Useful commands:"
echo "  View logs: docker-compose logs -f"
echo "  Stop services: docker-compose down"
echo "  Restart services: docker-compose restart"
echo ""
echo "Next steps:"
echo "  1. Edit backend/.env with your configuration"
echo "  2. Restart services: docker-compose restart"
echo "  3. Open http://localhost:3000 in your browser"
echo "========================="
