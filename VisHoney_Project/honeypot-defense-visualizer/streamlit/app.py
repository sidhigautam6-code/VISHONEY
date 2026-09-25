import streamlit as st
import pandas as pd
from elasticsearch import Elasticsearch
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os

# ============================================================
# PAGE CONFIGURATION
# ============================================================
st.set_page_config(
    page_title="Honeypot Defense SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# CUSTOM STYLING
# ============================================================
st.markdown("""
<style>
    .hero-header {
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
        padding: 2.5rem 2rem;
        border-radius: 16px;
        margin-bottom: 2rem;
        border: 1px solid rgba(72, 219, 251, 0.2);
    }
    .hero-title {
        font-size: 2.5rem;
        font-weight: 800;
        background: linear-gradient(90deg, #48dbfb, #0abde3, #54a0ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin: 0;
    }
    .hero-subtitle {
        color: #8892b0;
        font-size: 1.1rem;
        margin-top: 0.5rem;
    }
    .hero-status {
        display: inline-block;
        padding: 0.4rem 1rem;
        border-radius: 20px;
        font-size: 0.85rem;
        font-weight: 600;
        margin-top: 1rem;
        background: rgba(0, 255, 136, 0.15);
        color: #00ff88;
        border: 1px solid rgba(0, 255, 136, 0.3);
    }
    .metric-card {
        background: linear-gradient(135deg, #1e1e2e 0%, #2a2a3e 100%);
        padding: 1.5rem;
        border-radius: 12px;
        border: 1px solid rgba(72, 219, 251, 0.15);
        height: 100%;
    }
    .metric-icon {
        font-size: 2rem;
        margin-bottom: 0.5rem;
    }
    .metric-label {
        color: #8892b0;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-weight: 600;
    }
    .metric-value {
        color: #ffffff;
        font-size: 2rem;
        font-weight: 700;
        margin: 0.3rem 0;
    }
    .section-header {
        color: #ffffff;
        font-size: 1.5rem;
        font-weight: 700;
        margin: 2rem 0 1rem 0;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid rgba(72, 219, 251, 0.3);
    }
    .alert-critical {
        padding: 1.2rem 1.5rem;
        border-radius: 10px;
        margin-bottom: 1rem;
        border-left: 4px solid #ff4b4b;
        background: rgba(255, 75, 75, 0.1);
        color: #ff8b8b;
    }
    .alert-warning {
        padding: 1.2rem 1.5rem;
        border-radius: 10px;
        margin-bottom: 1rem;
        border-left: 4px solid #feca57;
        background: rgba(254, 202, 87, 0.1);
        color: #feca57;
    }
    .alert-success {
        padding: 1.2rem 1.5rem;
        border-radius: 10px;
        margin-bottom: 1rem;
        border-left: 4px solid #48dbfb;
        background: rgba(72, 219, 251, 0.1);
        color: #48dbfb;
    }
    .footer {
        text-align: center;
        color: #4a5568;
        padding: 2rem 0 1rem 0;
        font-size: 0.85rem;
        border-top: 1px solid rgba(72, 219, 251, 0.1);
        margin-top: 3rem;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================
# HERO HEADER
# ============================================================
st.markdown("""
<div class="hero-header">
    <h1 class="hero-title">Visual Intelligence for Honeypot Defense</h1>
    <p class="hero-subtitle">Real-time Security Operations Center — Monitoring, Detecting and Analyzing Cyber Threats</p>
    <span class="hero-status">LIVE MONITORING ACTIVE</span>
</div>
""", unsafe_allow_html=True)

# ============================================================
# ELASTICSEARCH CONNECTION
# ============================================================
es_host = os.getenv("ES_HOST", "elasticsearch")
es_port = os.getenv("ES_PORT", "9200")

@st.cache_resource
def connect_elasticsearch():
    try:
        es = Elasticsearch([f"http://{es_host}:{es_port}"], request_timeout=30)
        return es if es.ping() else None
    except Exception:
        return None

es = connect_elasticsearch()

# ============================================================
# DATA FETCH
# ============================================================
@st.cache_data(ttl=15)
def fetch_all_data():
    if not es:
        return pd.DataFrame()
    try:
        response = es.search(index="honeypot-*", body={"query": {"match_all": {}}}, size=10000)
        hits = response['hits']['hits']
        if not hits:
            return pd.DataFrame()
        return pd.DataFrame([h['_source'] for h in hits])
    except Exception:
        return pd.DataFrame()

# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown("### Dashboard Controls")
    st.markdown("---")
    
    if es:
        st.success("Elasticsearch Connected")
    else:
        st.error("Elasticsearch Disconnected")
    
    st.markdown("---")
    st.markdown("#### Time Range")
    time_range = st.selectbox(
        "Time Range",
        ["Last Hour", "Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"],
        index=1,
        label_visibility="collapsed"
    )
    
    st.markdown("#### Filter Attack Types")
    event_filter = st.multiselect(
        "Event Types",
        ["login_attempt", "connection", "malware_detected", "command_executed"],
        default=["login_attempt", "connection", "malware_detected", "command_executed"],
        label_visibility="collapsed"
    )
    
    st.markdown("---")
    if st.button("Refresh Data", use_container_width=True):
        st.cache_data.clear()
        st.rerun()
    
    st.markdown("---")
    st.markdown("""
    <div style="text-align: center; color: #4a5568; font-size: 0.8rem;">
        <b>Honeypot Defense System</b><br>
        Version 1.0.0
    </div>
    """, unsafe_allow_html=True)

# ============================================================
# LOAD DATA
# ============================================================
df = fetch_all_data()

if df.empty:
    st.markdown("""
    <div class="alert-warning">
        <b>No Attack Data Available</b><br>
        Waiting for honeypot logs. Generate test data to see insights.
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("### Generate Test Data")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("**1. SSH Attack (Cowrie)**")
        st.code("ssh -p 2222 root@localhost\n# Password: any\n# Type: whoami, ls -la, exit", language="bash")
    
    with col2:
        st.markdown("**2. HTTP Attack (Dionaea)**")
        st.code("curl http://localhost:80\ncurl http://localhost:80/admin", language="bash")
    
    with col3:
        st.markdown("**3. Python Injection**")
        st.code("python inject_data.py", language="bash")
    
    st.stop()

# Parse timestamps
if "@timestamp" in df.columns:
    df['@timestamp'] = pd.to_datetime(df['@timestamp'], errors='coerce')

# Time filter
now = datetime.now()
if time_range == "Last Hour":
    start_time = now - timedelta(hours=1)
elif time_range == "Last 24 Hours":
    start_time = now - timedelta(days=1)
elif time_range == "Last 7 Days":
    start_time = now - timedelta(days=7)
elif time_range == "Last 30 Days":
    start_time = now - timedelta(days=30)
else:
    start_time = datetime(2020, 1, 1)

df_filtered = df[df['@timestamp'] >= start_time] if '@timestamp' in df.columns else df

# Event type filter
if event_filter and 'event_type' in df_filtered.columns:
    df_filtered = df_filtered[df_filtered['event_type'].isin(event_filter)]

# Extract country
if 'geoip' in df_filtered.columns:
    df_filtered['country'] = df_filtered['geoip'].apply(
        lambda x: x.get('country_name', 'Unknown') if isinstance(x, dict) else 'Unknown'
    )

if df_filtered.empty:
    st.warning("No data matches the current filters. Try adjusting the filters.")
    st.stop()

# ============================================================
# METRICS CALCULATION
# ============================================================
total_attacks = len(df_filtered)
unique_ips = df_filtered['src_ip'].nunique() if 'src_ip' in df_filtered.columns else 0
unique_countries = df_filtered['country'].nunique() if 'country' in df_filtered.columns else 0
attack_types = df_filtered['event_type'].nunique() if 'event_type' in df_filtered.columns else 0

# ============================================================
# ALERT BANNER
# ============================================================
if total_attacks > 100 and unique_countries > 5:
    st.markdown(f"""
    <div class="alert-critical">
        <b>CRITICAL ALERT: High Attack Volume Detected</b><br>
        {total_attacks} attacks from {unique_countries} countries — {unique_ips} unique attackers.
    </div>
    """, unsafe_allow_html=True)
elif total_attacks > 50:
    st.markdown(f"""
    <div class="alert-warning">
        <b>ELEVATED THREAT LEVEL</b><br>
        {total_attacks} attacks detected from {unique_countries} countries.
    </div>
    """, unsafe_allow_html=True)
else:
    st.markdown(f"""
    <div class="alert-success">
        <b>SYSTEM OPERATIONAL</b><br>
        {total_attacks} events monitored across {unique_countries} countries.
    </div>
    """, unsafe_allow_html=True)

# ============================================================
# KPI METRICS
# ============================================================
st.markdown('<div class="section-header">Key Performance Indicators</div>', unsafe_allow_html=True)

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-icon">🔄</div>
        <div class="metric-label">Total Attacks</div>
        <div class="metric-value">{total_attacks}</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-icon">👤</div>
        <div class="metric-label">Unique Attackers</div>
        <div class="metric-value">{unique_ips}</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-icon">🎯</div>
        <div class="metric-label">Attack Types</div>
        <div class="metric-value">{attack_types}</div>
    </div>
    """, unsafe_allow_html=True)

with col4:
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-icon">🌍</div>
        <div class="metric-label">Countries</div>
        <div class="metric-value">{unique_countries}</div>
    </div>
    """, unsafe_allow_html=True)

with col5:
    if 'dst_port' in df_filtered.columns and not df_filtered['dst_port'].mode().empty:
        top_port = df_filtered['dst_port'].mode().iloc[0]
    else:
        top_port = 'N/A'
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-icon">🔌</div>
        <div class="metric-label">Top Target Port</div>
        <div class="metric-value">{top_port}</div>
    </div>
    """, unsafe_allow_html=True)

# ============================================================
# THREAT SCORE + TOP ATTACKERS
# ============================================================
st.markdown('<div class="section-header">Threat Assessment</div>', unsafe_allow_html=True)

col_gauge, col_attackers = st.columns([1, 1])

with col_gauge:
    volume_score = min(total_attacks / 10, 40)
    diversity_score = min(attack_types * 5, 20)
    geo_score = min(unique_countries * 2, 20)
    ip_score = min(unique_ips / 2, 20)
    threat_score = int(volume_score + diversity_score + geo_score + ip_score)

    if threat_score >= 70:
        risk_label = "CRITICAL"
        risk_color = "#ff4b4b"
    elif threat_score >= 50:
        risk_label = "HIGH"
        risk_color = "#ff6b6b"
    elif threat_score >= 30:
        risk_label = "MEDIUM"
        risk_color = "#feca57"
    else:
        risk_label = "LOW"
        risk_color = "#48dbfb"

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=threat_score,
        title={'text': f"THREAT SCORE<br><span style='color:{risk_color};font-weight:bold'>{risk_label}</span>"},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': risk_color},
            'bgcolor': '#1e1e2e',
            'steps': [
                {'range': [0, 30], 'color': 'rgba(72, 219, 251, 0.15)'},
                {'range': [30, 50], 'color': 'rgba(254, 202, 87, 0.15)'},
                {'range': [50, 70], 'color': 'rgba(255, 107, 107, 0.15)'},
                {'range': [70, 100], 'color': 'rgba(255, 75, 75, 0.15)'}
            ]
        }
    ))
    fig.update_layout(
        height=320,
        margin=dict(l=20, r=20, t=60, b=20),
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ccc')
    )
    st.plotly_chart(fig, use_container_width=True)

with col_attackers:
    st.markdown("#### Top 5 Attackers")
    if 'src_ip' in df_filtered.columns:
        top_ips = df_filtered['src_ip'].value_counts().head(5).reset_index()
        top_ips.columns = ['IP', 'Attacks']
        
        fig = px.bar(
            top_ips,
            x='Attacks',
            y='IP',
            orientation='h',
            color='Attacks',
            color_continuous_scale='Reds',
            text='Attacks'
        )
        fig.update_traces(textposition='outside')
        fig.update_layout(
            height=320,
            margin=dict(l=0, r=20, t=20, b=0),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#ccc'),
            showlegend=False,
            coloraxis_showscale=False
        )
        st.plotly_chart(fig, use_container_width=True)

# ============================================================
# ATTACK ANALYTICS
# ============================================================
st.markdown('<div class="section-header">Attack Analytics</div>', unsafe_allow_html=True)

col1, col2 = st.columns([2, 1])

with col1:
    st.markdown("#### Attack Frequency Over Time")
    if "@timestamp" in df_filtered.columns:
        df_ts = df_filtered.groupby(pd.Grouper(key='@timestamp', freq='1H')).size().reset_index(name='count')
        
        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df_ts['@timestamp'],
            y=df_ts['count'],
            mode='lines+markers',
            line=dict(color='#48dbfb', width=3),
            fill='tozeroy',
            fillcolor='rgba(72, 219, 251, 0.15)'
        ))
        fig.update_layout(
            height=380,
            margin=dict(l=0, r=0, t=20, b=0),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#ccc'),
            showlegend=False
        )
        st.plotly_chart(fig, use_container_width=True)

with col2:
    st.markdown("#### Attack Types")
    if 'event_type' in df_filtered.columns:
        type_counts = df_filtered['event_type'].value_counts().reset_index()
        type_counts.columns = ['Type', 'Count']
        
        fig = px.pie(
            type_counts,
            values='Count',
            names='Type',
            hole=0.55,
            color_discrete_sequence=['#48dbfb', '#ff6b6b', '#feca57', '#5f27cd']
        )
        fig.update_traces(textposition='outside', textinfo='percent')
        fig.update_layout(
            height=380,
            margin=dict(l=0, r=0, t=20, b=0),
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#ccc')
        )
        st.plotly_chart(fig, use_container_width=True)

# ============================================================
# GEOGRAPHIC & PORT ANALYSIS
# ============================================================
st.markdown('<div class="section-header">Geographic and Port Intelligence</div>', unsafe_allow_html=True)

col1, col2 = st.columns(2)

with col1:
    st.markdown("#### Top 10 Attack Origins")
    if 'country' in df_filtered.columns:
        country_counts = df_filtered['country'].value_counts().head(10).reset_index()
        country_counts.columns = ['Country', 'Attacks']
        
        fig = px.bar(
            country_counts,
            x='Country',
            y='Attacks',
            color='Attacks',
            color_continuous_scale='Reds',
            text='Attacks'
        )
        fig.update_traces(textposition='outside')
        fig.update_layout(
            height=400,
            margin=dict(l=0, r=0, t=20, b=0),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#ccc'),
            showlegend=False,
            coloraxis_showscale=False
        )
        st.plotly_chart(fig, use_container_width=True)

with col2:
    st.markdown("#### Top 10 Targeted Ports")
    if 'dst_port' in df_filtered.columns:
        port_counts = df_filtered['dst_port'].value_counts().head(10).reset_index()
        port_counts.columns = ['Port', 'Attacks']
        port_counts['Port'] = port_counts['Port'].astype(str)
        
        fig = px.bar(
            port_counts,
            x='Attacks',
            y='Port',
            orientation='h',
            color='Attacks',
            color_continuous_scale='Blues',
            text='Attacks'
        )
        fig.update_traces(textposition='outside')
        fig.update_layout(
            height=400,
            margin=dict(l=0, r=20, t=20, b=0),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#ccc'),
            showlegend=False,
            coloraxis_showscale=False
        )
        st.plotly_chart(fig, use_container_width=True)

# ============================================================
# RECENT ACTIVITY
# ============================================================
st.markdown('<div class="section-header">Recent Attack Activity</div>', unsafe_allow_html=True)

if '@timestamp' in df_filtered.columns:
    recent = df_filtered.sort_values('@timestamp', ascending=False).head(15).copy()
    
    display_cols = []
    for col in ['@timestamp', 'src_ip', 'event_type', 'username', 'dst_port', 'country']:
        if col in recent.columns:
            display_cols.append(col)
    
    if display_cols:
        st.dataframe(
            recent[display_cols],
            use_container_width=True,
            height=400
        )

# ============================================================
# AUTOMATED INSIGHTS
# ============================================================
st.markdown('<div class="section-header">Automated Insights</div>', unsafe_allow_html=True)

col1, col2, col3 = st.columns(3)

with col1:
    peak_val = "N/A"
    if '@timestamp' in df_filtered.columns:
        df_hour = df_filtered.copy()
        df_hour['hour'] = df_hour['@timestamp'].dt.hour
        if not df_hour['hour'].mode().empty:
            peak_val = f"{df_hour['hour'].mode().iloc[0]}:00"
    
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-icon">⏰</div>
        <div class="metric-label">Peak Attack Hour</div>
        <div class="metric-value">{peak_val}</div>
    </div>
    """, unsafe_allow_html=True)

with col2:
    top_user_val = "N/A"
    if 'username' in df_filtered.columns:
        valid_users = df_filtered[df_filtered['username'] != '']['username']
        if not valid_users.empty and not valid_users.mode().empty:
            top_user_val = valid_users.mode().iloc[0]
    
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-icon">🔑</div>
        <div class="metric-label">Top Credential</div>
        <div class="metric-value">{top_user_val}</div>
    </div>
    """, unsafe_allow_html=True)

with col3:
    top_event_val = "N/A"
    if 'event_type' in df_filtered.columns and not df_filtered['event_type'].mode().empty:
        top_event_val = df_filtered['event_type'].mode().iloc[0]
    
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-icon">🎯</div>
        <div class="metric-label">Top Attack Type</div>
        <div class="metric-value">{top_event_val}</div>
    </div>
    """, unsafe_allow_html=True)

# ============================================================
# FOOTER
# ============================================================
st.markdown("""
<div class="footer">
    <b>Visual Intelligence for Honeypot Defense</b><br>
    Real-time Security Operations Center | Powered by Cowrie, Dionaea, Logstash, Elasticsearch, Kibana and Streamlit<br>
    Academic Project 2026
</div>
""", unsafe_allow_html=True)