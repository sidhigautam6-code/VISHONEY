# 🛡️ Visual Intelligence for Honeypot Defense

## Overview
A real-time security monitoring system that uses honeypots (Cowrie & Dionaea) to trap attacker activity, processes logs through Logstash, stores them in Elasticsearch, and visualizes them using Kibana and Streamlit dashboards.

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.11+ (for local development)

### Setup
1. Clone this repository
2. Copy `.env.example` to `.env` and set your passwords
3. Run: `./scripts/start_all.sh`

### Access
- **Streamlit Dashboard:** http://localhost:8501
- **Kibana:** http://localhost:5601
- **Elasticsearch:** http://localhost:9200

## Architecture