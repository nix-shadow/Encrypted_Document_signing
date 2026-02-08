#!/bin/bash
# Local development setup (without Docker)

set -e

echo "🔐 Local Development Setup"
echo "=========================="

# Backend setup
echo ""
echo "📦 Setting up backend..."
cd backend

if [ ! -f .env ]; then
    cp .env.example .env
    SECRET_KEY=$(openssl rand -hex 32)
    SESSION_SECRET=$(openssl rand -hex 32)
    sed -i "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" .env
    sed -i "s/SESSION_SECRET=.*/SESSION_SECRET=$SESSION_SECRET/" .env
    # Use local database
    sed -i "s|DATABASE_URL=.*|DATABASE_URL=postgresql://cryptouser:cryptopass@localhost:5432/cryptodb|" .env
    echo "✅ Created .env with secrets"
fi

if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

echo "Installing Python dependencies..."
source venv/bin/activate
pip install -q -r requirements.txt

echo "✅ Backend ready"
cd ..

# Frontend setup
echo ""
echo "📦 Setting up frontend..."
cd frontend

if [ ! -d "node_modules" ]; then
    echo "Installing npm dependencies..."
    npm install
fi

echo "✅ Frontend ready"
cd ..

echo ""
echo "🎯 Setup complete!"
echo ""
echo "To start development:"
echo "  1. Start PostgreSQL (docker run -p 5432:5432 -e POSTGRES_USER=cryptouser -e POSTGRES_PASSWORD=cryptopass -e POSTGRES_DB=cryptodb postgres:15)"
echo "  2. Terminal 1: cd backend && source venv/bin/activate && uvicorn app.main:app --reload"
echo "  3. Terminal 2: cd frontend && npm run dev"
echo ""
echo "Or use Docker: ./start.sh"
