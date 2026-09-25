#!/bin/bash
echo "🚀 Starting Honeypot Defense System..."

# Create network if not exists
docker network create --subnet 192.168.0.0/24 honeynet 2>/dev/null || echo "✅ Network already exists"

# Start all containers
docker-compose up -d

echo "⏳ Waiting for services to start..."
sleep 15

echo "
✅ System Ready!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 Kibana:        http://localhost:5601
📈 Streamlit:     http://localhost:8501
🔍 Elasticsearch: http://localhost:9200
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📝 To view logs:  docker-compose logs -f
🛑 To stop:       ./scripts/stop_all.sh
📡 Test attack:   ssh -p 2222 root@localhost (any password)
"