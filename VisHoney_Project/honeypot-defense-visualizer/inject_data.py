from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import random
import time

# Connect to Elasticsearch
es = Elasticsearch(['http://localhost:9200'])

# Check connection
if not es.ping():
    print("❌ Cannot connect to Elasticsearch")
    exit()

print("✅ Connected to Elasticsearch")

# Sample data
attack_types = ['login_attempt', 'connection', 'malware_detected', 'command_executed']
usernames = ['root', 'admin', 'user', 'test', 'ubuntu', 'oracle', 'postgres', 'deploy', 'git']
ips = [
    '192.168.1.100', '10.0.0.50', '45.33.32.156', '185.220.101.23',
    '94.102.61.78', '80.82.77.139', '45.155.205.233', '91.121.89.12',
    '5.188.210.15', '37.49.230.130', '89.248.168.59', '185.165.29.101'
]
countries = ['US', 'CN', 'RU', 'IN', 'GB', 'DE', 'FR', 'JP', 'BR', 'AU', 'CA']

# Generate 50 attack events
print("🔄 Generating 50 attack events...")

for i in range(50):
    # Random timestamp in last 24 hours
    timestamp = datetime.now() - timedelta(seconds=random.randint(0, 86400))
    
    # Random attack data
    attack = {
        '@timestamp': timestamp.isoformat(),
        'src_ip': random.choice(ips),
        'event_type': random.choice(attack_types),
        'username': random.choice(usernames) if random.random() > 0.3 else '',
        'src_port': random.randint(1024, 65535),
        'dst_port': random.choice([22, 23, 80, 443, 445, 3306, 3389, 5060]),
        'geoip': {
            'country_name': random.choice(countries),
            'location': {
                'lat': random.uniform(-90, 90),
                'lon': random.uniform(-180, 180)
            }
        }
    }
    
    # Add command for command_executed type
    if attack['event_type'] == 'command_executed':
        commands = ['cat /etc/passwd', 'ls -la', 'whoami', 'id', 'uname -a']
        attack['command'] = random.choice(commands)
    
    # Add payload for malware_detected type
    if attack['event_type'] == 'malware_detected':
        payloads = ['trojan.exe', 'ransomware.zip', 'virus.bin', 'backdoor.sh']
        attack['payload'] = random.choice(payloads)
    
    # Index the document
    index_name = f"honeypot-{timestamp.strftime('%Y.%m.%d')}"
    es.index(index=index_name, body=attack)
    
    print(f"✅ Event {i+1}: {attack['event_type']} from {attack['src_ip']}")
    time.sleep(0.05)

print("=" * 50)
print("✅ 50 attack events injected successfully!")
print(f"📊 Check your dashboard: http://localhost:8501")