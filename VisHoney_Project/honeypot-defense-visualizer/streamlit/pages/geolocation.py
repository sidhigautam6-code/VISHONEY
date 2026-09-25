import streamlit as st
import pandas as pd
from elasticsearch import Elasticsearch
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os

# ---------- PAGE CONFIG ----------
st.set_page_config(
    page_title="Attack Geolocation Intelligence",
    page_icon="🌍",
    layout="wide"
)

# ---------- CUSTOM CSS ----------
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        background: linear-gradient(90deg, #ff4b4b, #ff6b6b, #feca57);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        padding: 1rem 0;
    }
    .sub-header {
        text-align: center;
        color: #888;
        margin-bottom: 2rem;
        font-size: 1.1rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #1e1e2e, #2a2a3e);
        padding: 1.5rem;
        border-radius: 12px;
        border-left: 4px solid #ff4b4b;
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    }
    .threat-high {
        color: #ff4b4b;
        font-weight: bold;
    }
    .threat-medium {
        color: #feca57;
        font-weight: bold;
    }
    .threat-low {
        color: #48dbfb;
        font-weight: bold;
    }
    div[data-testid="stMetricValue"] {
        font-size: 1.8rem;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# ---------- HEADER ----------
st.markdown('<div class="main-header">🌍 Global Attack Intelligence Map</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Real-time geolocation analysis of honeypot attack origins</div>', unsafe_allow_html=True)

# ---------- CONNECT TO ELASTICSEARCH ----------
es_host = os.getenv("ES_HOST", "elasticsearch")
es_port = os.getenv("ES_PORT", "9200")

@st.cache_resource
def connect_es():
    try:
        es = Elasticsearch([f'http://{es_host}:{es_port}'], request_timeout=30)
        return es if es.ping() else None
    except:
        return None

es = connect_es()

if not es:
    st.error("❌ Not connected to Elasticsearch")
    st.stop()

# ---------- QUERY DATA ----------
@st.cache_data(ttl=30)
def fetch_data():
    response = es.search(index="honeypot-*", body={"query": {"match_all": {}}}, size=10000)
    hits = response['hits']['hits']
    if not hits:
        return pd.DataFrame()
    return pd.DataFrame([h['_source'] for h in hits])

df = fetch_data()

if df.empty:
    st.warning("📭 No attack data available. Generate test data first!")
    st.code("python inject_data.py", language="bash")
    st.stop()

# Parse timestamp
if "@timestamp" in df.columns:
    df['@timestamp'] = pd.to_datetime(df['@timestamp'])

# Extract geoip fields
if 'geoip' in df.columns:
    df['country'] = df['geoip'].apply(lambda x: x.get('country_name', 'Unknown') if isinstance(x, dict) else 'Unknown')
    df['city'] = df['geoip'].apply(lambda x: x.get('city_name', 'Unknown') if isinstance(x, dict) else 'Unknown')
    df['lat'] = df['geoip'].apply(lambda x: x.get('location', {}).get('lat', None) if isinstance(x, dict) else None)
    df['lon'] = df['geoip'].apply(lambda x: x.get('location', {}).get('lon', None) if isinstance(x, dict) else None)

# ---------- TOP METRICS ROW ----------
st.markdown("### 📊 Attack Summary")
col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric("🌍 Countries", df['country'].nunique(), help="Unique source countries")
with col2:
    st.metric("📍 Locations", df['lat'].notna().sum(), help="Geolocated events")
with col3:
    st.metric("🎯 Total Attacks", len(df), help="Total attack events")
with col4:
    st.metric("👤 Attackers", df['src_ip'].nunique() if 'src_ip' in df.columns else 0, help="Unique IPs")
with col5:
    top_country = df['country'].mode()
    st.metric("🔥 Top Origin", top_country.iloc[0] if not top_country.empty else 'N/A', help="Most active country")

st.markdown("---")

# ---------- THREAT LEVEL INDICATOR ----------
st.markdown("### 🚨 Threat Level Assessment")

total_attacks = len(df)
unique_countries = df['country'].nunique()

if total_attacks > 100 and unique_countries > 10:
    threat_level = "HIGH"
    threat_color = "#ff4b4b"
    threat_desc = "Multiple countries actively attacking. Elevated threat detected."
elif total_attacks > 50 and unique_countries > 5:
    threat_level = "MEDIUM"
    threat_color = "#feca57"
    threat_desc = "Moderate attack activity from several countries."
else:
    threat_level = "LOW"
    threat_color = "#48dbfb"
    threat_desc = "Low attack activity observed."

st.markdown(f"""
<div style="background: linear-gradient(135deg, #1e1e2e, #2a2a3e); padding: 1.5rem; border-radius: 12px; border-left: 4px solid {threat_color}; margin-bottom: 2rem;">
    <h3 style="color: {threat_color}; margin: 0;">Threat Level: {threat_level}</h3>
    <p style="color: #ccc; margin: 0.5rem 0 0 0;">{threat_desc}</p>
</div>
""", unsafe_allow_html=True)

st.markdown("---")

# ---------- WORLD MAP ----------
st.markdown("### 🗺️ Global Attack Distribution")
st.markdown("_Each dot represents an attack origin. Dot size indicates number of attacks from that location._")

# Group by location for better visualization
map_df = df.dropna(subset=['lat', 'lon']).copy()

if not map_df.empty:
    # Group by lat/lon and count
    location_counts = map_df.groupby(['lat', 'lon', 'country', 'city']).size().reset_index(name='attack_count')
    
    # Create world map
    fig = px.scatter_geo(
        location_counts,
        lat='lat',
        lon='lon',
        size='attack_count',
        color='country',
        hover_name='city',
        hover_data={
            'country': True,
            'attack_count': True,
            'lat': ':.2f',
            'lon': ':.2f'
        },
        projection='natural earth',
        title='',
        size_max=40,
        color_discrete_sequence=px.colors.qualitative.Bold
    )
    
    fig.update_layout(
        geo=dict(
            showframe=False,
            showcoastlines=True,
            coastlinecolor='#444',
            showland=True,
            landcolor='#1e1e2e',
            showocean=True,
            oceancolor='#0e0e1e',
            showcountries=True,
            countrycolor='#333',
            bgcolor='rgba(0,0,0,0)',
        ),
        height=600,
        margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ccc'),
        legend=dict(
            title="Country",
            bgcolor='rgba(30,30,46,0.8)',
            bordercolor='#444',
            borderwidth=1
        )
    )
    
    st.plotly_chart(fig, use_container_width=True)
else:
    st.info("No geolocation data available")

st.markdown("---")

# ---------- TWO COLUMN CHARTS ----------
col1, col2 = st.columns(2)

with col1:
    st.markdown("### 🏆 Top 10 Attacking Countries")
    
    country_counts = df['country'].value_counts().head(10).reset_index()
    country_counts.columns = ['Country', 'Attacks']
    
    fig = px.bar(
        country_counts,
        x='Attacks',
        y='Country',
        orientation='h',
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
        coloraxis_showscale=False,
        yaxis=dict(autorange='reversed')
    )
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.markdown("### 🎯 Attack Type Distribution")
    
    if 'event_type' in df.columns:
        type_counts = df['event_type'].value_counts().reset_index()
        type_counts.columns = ['Type', 'Count']
        
        fig = px.pie(
            type_counts,
            values='Count',
            names='Type',
            hole=0.5,
            color_discrete_sequence=px.colors.qualitative.Set2
        )
        fig.update_traces(
            textposition='outside',
            textinfo='percent+label'
        )
        fig.update_layout(
            height=400,
            margin=dict(l=0, r=0, t=20, b=0),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#ccc'),
            showlegend=False
        )
        st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

# ---------- TIMELINE ----------
st.markdown("### ⏱️ Attack Timeline")

if "@timestamp" in df.columns:
    # Hourly timeline
    df_hourly = df.groupby(pd.Grouper(key='@timestamp', freq='1H')).size().reset_index(name='count')
    
    fig = px.area(
        df_hourly,
        x='@timestamp',
        y='count',
        color_discrete_sequence=['#ff4b4b']
    )
    fig.update_layout(
        height=350,
        margin=dict(l=0, r=0, t=20, b=0),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#ccc'),
        xaxis_title="Time",
        yaxis_title="Number of Attacks"
    )
    fig.update_traces(
        line=dict(width=2),
        fill='tozeroy',
        fillcolor='rgba(255,75,75,0.2)'
    )
    st.plotly_chart(fig, use_container_width=True)

st.markdown("---")

# ---------- ATTACK SOURCES TABLE ----------
st.markdown("### 📋 Detailed Attack Sources")

# Aggregate by source IP
if 'src_ip' in df.columns:
    ip_summary = df.groupby('src_ip').agg({
        'event_type': lambda x: ', '.join(x.unique()[:3]),
        'country': 'first',
        'city': 'first',
        '@timestamp': 'max'
    }).reset_index()
    ip_summary.columns = ['Source IP', 'Attack Types', 'Country', 'City', 'Last Seen']
    ip_summary['Attack Count'] = df.groupby('src_ip').size().values
    ip_summary = ip_summary.sort_values('Attack Count', ascending=False).head(20)
    ip_summary = ip_summary[['Source IP', 'Country', 'City', 'Attack Types', 'Attack Count', 'Last Seen']]
    
    st.dataframe(
        ip_summary,
        use_container_width=True,
        height=400,
        column_config={
            "Source IP": st.column_config.TextColumn("🌐 Source IP", width="medium"),
            "Country": st.column_config.TextColumn("🌍 Country", width="small"),
            "City": st.column_config.TextColumn("🏙️ City", width="small"),
            "Attack Types": st.column_config.TextColumn("🎯 Attack Types", width="large"),
            "Attack Count": st.column_config.NumberColumn("📊 Count", width="small"),
            "Last Seen": st.column_config.DatetimeColumn("🕐 Last Seen", format="DD/MM/YY HH:mm")
        }
    )

st.markdown("---")

# ---------- INSIGHTS ----------
st.markdown("### 💡 Key Insights")

col1, col2 = st.columns(2)

with col1:
    st.markdown("#### 🎯 Attack Patterns")
    
    # Most common attack type
    if 'event_type' in df.columns:
        top_attack = df['event_type'].mode()
        if not top_attack.empty:
            st.info(f"**Most common attack:** `{top_attack.iloc[0]}`")
    
    # Most targeted port
    if 'dst_port' in df.columns:
        top_port = df['dst_port'].mode()
        if not top_port.empty:
            st.info(f"**Most targeted port:** `{top_port.iloc[0]}`")
    
    # Peak attack hour
    if "@timestamp" in df.columns:
        df['hour'] = df['@timestamp'].dt.hour
        peak_hour = df['hour'].mode()
        if not peak_hour.empty:
            st.info(f"**Peak attack hour:** `{peak_hour.iloc[0]}:00`")
    
    # Most targeted username
    if 'username' in df.columns:
        usernames = df[df['username'] != '']['username']
        if not usernames.empty:
            top_user = usernames.mode()
            if not top_user.empty:
                st.info(f"**Most targeted username:** `{top_user.iloc[0]}`")

with col2:
    st.markdown("#### 🌍 Geographic Insights")
    
    # Top 3 countries
    top_countries = df['country'].value_counts().head(3)
    if not top_countries.empty:
        st.markdown("**Top 3 attack origins:**")
        for i, (country, count) in enumerate(top_countries.items(), 1):
            st.markdown(f"{i}. **{country}** — {count} attacks")
    
    # Geographic spread
    total_countries = df['country'].nunique()
    st.info(f"**Geographic spread:** Attacks from `{total_countries}` different countries")
    
    # Most active city
    if 'city' in df.columns:
        cities = df[df['city'] != 'Unknown']['city']
        if not cities.empty:
            top_city = cities.mode()
            if not top_city.empty:
                st.info(f"**Most active city:** `{top_city.iloc[0]}`")

# ---------- FOOTER ----------
st.markdown("---")
st.markdown(
    "<p style='text-align: center; color: #666; font-size: 0.9rem;'>"
    "🛡️ Visual Intelligence for Honeypot Defense | Real-time Attack Geolocation"
    "</p>",
    unsafe_allow_html=True
)