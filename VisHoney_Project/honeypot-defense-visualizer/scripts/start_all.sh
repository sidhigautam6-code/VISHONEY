#!/bin/bash
echo "🚀 Starting Honeypot Defense System..."

# Create network if not exists
docker network create --subnet 192.168.0.0/24 honeynet 2>/dev/null

# Start all containers
docker-compose up -d

echo "⏳ Waiting for services to start..."
sleep 10

echo "
✅ System Ready!
📊 Kibana: http://localhost:5601
📈 Streamlit: http://localhost:8501
🔍 Elasticsearch: http://localhost:9200

Default Credentials:
  Elastic User: elastic
  Elastic Password: changeme123!
"