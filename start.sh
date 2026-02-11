#!/bin/bash
# Quick setup script for Encrypted Document Signing Platform

set -e

echo "🔐 Encrypted Document Signing Platform - Setup"
echo "=============================================="

# Check if .env exists
if [ ! -f backend/.env ]; then
    echo "📝 Creating backend/.env from template..."
    cp backend/.env.example backend/.env
    
    # Generate random secrets
    SECRET_KEY=$(openssl rand -hex 32)
    SESSION_SECRET=$(openssl rand -hex 32)
    
    # Update .env with generated secrets
    sed -i "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" backend/.env
    sed -i "s/SESSION_SECRET=.*/SESSION_SECRET=$SESSION_SECRET/" backend/.env
    
    echo "✅ Generated random secrets in backend/.env"
else
    echo "✅ backend/.env already exists"
fi

echo ""
echo "� Checking Docker status..."

# Check if Docker daemon is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

echo "✅ Docker is running"

# Check if containers already exist
BACKEND_RUNNING=$(docker-compose ps -q backend 2>/dev/null)
FRONTEND_RUNNING=$(docker-compose ps -q frontend 2>/dev/null)
DB_RUNNING=$(docker-compose ps -q db 2>/dev/null)

if [ -n "$BACKEND_RUNNING" ] && [ -n "$FRONTEND_RUNNING" ] && [ -n "$DB_RUNNING" ]; then
    # Check if containers are actually running (not just existing)
    BACKEND_STATE=$(docker inspect -f '{{.State.Running}}' $(docker-compose ps -q backend) 2>/dev/null)
    FRONTEND_STATE=$(docker inspect -f '{{.State.Running}}' $(docker-compose ps -q frontend) 2>/dev/null)
    DB_STATE=$(docker inspect -f '{{.State.Running}}' $(docker-compose ps -q db) 2>/dev/null)
    
    if [ "$BACKEND_STATE" = "true" ] && [ "$FRONTEND_STATE" = "true" ] && [ "$DB_STATE" = "true" ]; then
        echo "✅ All containers are already running!"
        echo ""
        echo "   Frontend: http://localhost:3000"
        echo "   Backend:  http://localhost:3001"
        echo "   Database: PostgreSQL on port 5433"
        echo "   API Docs: http://localhost:3001/docs"
        echo ""
        
        # Check for code changes
        echo "🔍 Checking for code changes..."
        NEEDS_RESTART=false
        
        # Check if there are uncommitted changes in backend or frontend
        if git diff --quiet HEAD -- backend/ frontend/ 2>/dev/null; then
            echo "✅ No code changes detected since last commit"
        else
            echo "⚠️  Code changes detected in backend/ or frontend/"
            NEEDS_RESTART=true
        fi
        
        # Check container uptime (if running for less than 5 minutes, likely just started)
        BACKEND_UPTIME=$(docker inspect -f '{{.State.StartedAt}}' $(docker-compose ps -q backend) 2>/dev/null)
        CURRENT_TIME=$(date -u +%s)
        STARTED_TIME=$(date -d "$BACKEND_UPTIME" +%s 2>/dev/null || echo $CURRENT_TIME)
        UPTIME_SECONDS=$((CURRENT_TIME - STARTED_TIME))
        
        if [ $UPTIME_SECONDS -lt 300 ]; then
            echo "✅ Containers recently started (${UPTIME_SECONDS}s ago)"
            NEEDS_RESTART=false
        fi
        
        if [ "$NEEDS_RESTART" = true ]; then
            echo ""
            echo "🔄 Restart recommended to apply code changes"
            read -p "   Do you want to restart the services? (y/N): " -n 1 -r
            echo ""
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                echo "🔄 Restarting services..."
                docker-compose restart
                echo "✅ Services restarted successfully!"
            else
                echo "⏭️  Skipping restart"
            fi
        fi
        
        echo ""
        echo "💡 Tip: Use 'docker-compose restart' to restart services manually"
        echo "📊 View logs: docker-compose logs -f"
        echo "🛑 Stop services: docker-compose down"
        exit 0
    else
        echo "🔄 Some containers exist but are stopped. Starting them..."
        docker-compose start
        echo ""
        echo "✅ Services started!"
    fi
else
    echo "🚀 Starting services with Docker Compose (first-time build)..."
    echo ""
    docker-compose up --build -d
    echo ""
    echo "✅ Services built and started!"
fi

echo ""
echo "   Frontend: http://localhost:3000"
echo "   Backend:  http://localhost:3001"
echo "   Database: PostgreSQL on port 5433"
echo "   API Docs: http://localhost:3001/docs"
echo ""
echo "📊 View logs: docker-compose logs -f"
echo "🔄 Restart services: docker-compose restart"
echo "🛑 Stop services: docker-compose down"
