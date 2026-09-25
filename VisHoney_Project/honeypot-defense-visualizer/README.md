# 🛡️ Visual Intelligence for Honeypot Defense

> **Real-time Security Operations Center (SOC) for Capturing, Processing, and Visualizing Cyber Attacks**

[![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Elasticsearch](https://img.shields.io/badge/Elasticsearch-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)](https://www.elastic.co/)
[![Streamlit](https://img.shields.io/badge/Streamlit-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io/)

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Technology Stack](#-technology-stack)
- [Prerequisites](#-prerequisites)
- [Quick Start](#-quick-start)
- [Project Structure](#-project-structure)
- [Usage](#-usage)
- [Generating Test Data](#-generating-test-data)
- [Accessing Dashboards](#-accessing-dashboards)
- [Configuration](#-configuration)
- [API Reference](#-api-reference)
- [Troubleshooting](#-troubleshooting)
- [Deployment](#-deployment)
- [Future Enhancements](#-future-enhancements)
- [Contributing](#-contributing)
- [License](#-license)
- [Authors](#-authors)
- [Acknowledgments](#-acknowledgments)

---

## 🎯 Overview

**Visual Intelligence for Honeypot Defense** is a containerized honeypot-based threat intelligence system that captures, processes, and visualizes cyber attacks in real-time. The system uses two honeypots (**Cowrie** for SSH attacks and **Dionaea** for malware/HTTP attacks) to trap attackers, processes logs through **Logstash**, stores them in **Elasticsearch**, and provides real-time visualization through **Kibana** and a custom **Streamlit** dashboard.

### Why This Project?

Traditional security monitoring relies on detecting attacks after they happen. This project takes a **proactive approach** by deploying decoy systems (honeypots) that attract attackers, capture their behavior, and provide actionable threat intelligence — all in real-time.

---

## ✨ Features

### 🔍 Attack Capture
- **SSH Honeypot (Cowrie)** — Captures SSH login attempts, commands, and attacker behavior
- **Malware Honeypot (Dionaea)** — Captures HTTP, FTP, HTTPS, MySQL malware attacks
- **Real-time logging** — All attacker activity logged instantly

### 🔄 Data Processing
- **Logstash pipeline** — Parses, structures, and enriches raw logs
- **GeoIP enrichment** — Maps attack origins to countries and cities
- **Field extraction** — Converts unstructured logs into searchable JSON

### 💾 Data Storage
- **Elasticsearch** — Fast, scalable, indexed storage
- **Time-based indices** — Daily indices for efficient querying
- **Persistent data** — Data survives container restarts

### 📊 Visualization
- **Kibana dashboards** — Analyst-grade querying and filtering
- **Streamlit SOC dashboard** — Custom real-time monitoring interface
- **Attack trends** — Hourly, daily, and weekly attack patterns
- **Geolocation map** — Interactive world map of attack origins
- **Threat scoring** — Automated threat level assessment
- **Automated insights** — Peak hours, top credentials, attack patterns

### 🔒 Security & Reliability
- **Container isolation** — Each service runs in its own container
- **Auto-restart** — Containers restart automatically on crash
- **Network isolation** — Custom Docker network for inter-container communication
- **Data persistence** — Bind mounts ensure data durability

---

## 🏗️ Architecture
┌─────────────────────────────────────────────────────────────────┐
│ DATA INGESTION ZONE │
│ │
│ ┌──────────────┐ ┌──────────────┐ │
│ │ COWRIE │ │ DIONAEA │ │
│ │ SSH: 2222 │ │ HTTP: 80 │ │
│ │ Telnet: 23 │ │ FTP: 21 │ │
│ │ │ │ HTTPS: 443 │ │
│ │ │ │ MySQL: 3306 │ │
│ └──────┬───────┘ └──────┬───────┘ │
│ │ │ │
│ └──────────┬───────────────┘ │
│ ▼ │
│ ┌─────────────────────┐ │
│ │ RAW LOGS │ │
│ └──────────┬──────────┘ │
└─────────────────────┼───────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────────┐
│ INTELLIGENCE HUB │
│ ┌─────────────────────┐ │
│ │ LOGSTASH │ │
│ │ • Parse logs │ │
│ │ • Structure data │ │
│ │ • Enrich GeoIP │ │
│ └──────────┬──────────┘ │
└─────────────────────┼───────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────────┐
│ KNOWLEDGE VAULT │
│ ┌─────────────────────┐ │
│ │ ELASTICSEARCH │ │
│ │ Port: 9200 │ │
│ │ Index: honeypot-* │ │
│ └──────────┬──────────┘ │
└─────────────────────┼───────────────────────────────────────────┘
▼
┌─────────────────────────────────────────────────────────────────┐
│ SITUATION ROOM │
│ │
│ ┌──────────────┐ ┌──────────────┐ │
│ │ KIBANA │ │ STREAMLIT │ │
│ │ Port: 5601 │ │ Port: 8501 │ │
│ └──────────────┘ └──────────────┘ │
└─────────────────────────────────────────────────────────────────┘

text

---

---

## 🛠️ Technology Stack

| Component | Technology | Version | Purpose |
|-----------|-----------|---------|---------|
| **Containerization** | Docker | Latest | Container runtime |
| **Orchestration** | Docker Compose | v2 | Multi-container management |
| **SSH Honeypot** | Cowrie | Latest | Captures SSH attacks |
| **Malware Honeypot** | Dionaea | Latest | Captures malware attacks |
| **Data Pipeline** | Logstash | 7.17.15 | Log parsing and enrichment |
| **Data Storage** | Elasticsearch | 7.17.15 | Indexed data storage |
| **Visualization** | Kibana | 7.17.15 | Analytics dashboard |
| **Custom Dashboard** | Streamlit | 1.28.0 | Python-based SOC dashboard |
| **Programming Language** | Python | 3.11 | Application logic |
| **Data Manipulation** | Pandas | 2.1.0 | Data processing |
| **Visualization** | Plotly | 5.17.0 | Interactive charts |

---

## 📋 Prerequisites

Before you begin, ensure you have the following installed:

- **Docker Desktop** (v24.0 or higher)
  - [Download for Windows](https://www.docker.com/products/docker-desktop/)
  - [Download for Mac](https://www.docker.com/products/docker-desktop/)
- **Python** (v3.11 or higher) — [Download](https://www.python.org/downloads/)
- **VS Code** (Recommended) — [Download](https://code.visualstudio.com/)
- **Git** (Optional) — [Download](https://git-scm.com/)

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **RAM** | 8 GB | 16 GB |
| **Storage** | 20 GB free | 40 GB free |
| **CPU** | 2 cores | 4 cores |
| **OS** | Windows 10 / macOS 10.15+ / Ubuntu 20.04+ | Latest |

---

