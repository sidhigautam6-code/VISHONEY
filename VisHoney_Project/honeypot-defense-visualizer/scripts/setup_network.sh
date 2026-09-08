#!/bin/bash
echo "Setting up Docker network..."
docker network create --subnet 192.168.0.0/24 honeynet 2>/dev/null || echo "Network already exists"
echo "✅ Network ready"