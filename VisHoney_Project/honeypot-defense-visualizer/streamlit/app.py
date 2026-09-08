import streamlit as st
import pandas as pd
from elasticsearch import Elasticsearch
import plotly.express as px
from datetime import datetime, timedelta
import os
import folium
from streamlit_folium import folium_static

# ---------- CONFIG ----------
st.set_page_config(
    page_title="Honeypot Defense Visualizer",
    page_icon="🛡️",
    layout="wide"
)

# ---------- CONNECT TO ELASTICSEARCH ----------
es_host = os.getenv("ES_HOST", "elasticsearch")
es_port = os.getenv("ES_PORT", "9200")
es_user = os.getenv("ES_USER", "elastic")
es_pass = os.getenv("ES_PASS", "changeme123!")

@st.cache_resource
def connect_elasticsearch():
    try:
        es = Elasticsearch(
            [f"http://{es_host}:{es_port}"],
            basic_auth=(es_user, es_pass),
            request_timeout=30
        )
        if es.ping():
            return es
        else:
            st.error("⚠️ Cannot connect to Elasticsearch")
            return None
    except Exception as e:
        st.error(f"⚠️ Connection error: {e}")
        return None

es = connect_elasticsearch()

# ---------- QUERY FUNCTION ----------
def query_elasticsearch(query_body, index="honeypot-*"):
    if not es:
        return pd.DataFrame()
    try:
        response = es.search(index=index, body=query_body, size=1000)
        hits = response['hits']['hits']
        if not hits:
            return pd.DataFrame()
        data = [hit['_source'] for hit in hits]
        return pd.DataFrame(data)
    except Exception as e:
        st.error(f"Query error: {e}")
        return pd.DataFrame()

# ---------- SIDEBAR ----------
st.sidebar.title("🔍 Filter Controls")
time_range = st.sidebar.selectbox(
    "Time Range",
    ["Last 24 Hours", "Last 7 Days", "Last 30 Days", "All Time"]
)

attack_type = st.sidebar.multiselect(
    "Attack Type",
    ["login_attempt", "command_executed", "connection", "malware_detected"],
    default=["login_attempt", "connection", "malware_detected"]
)

# ---------- MAIN DASHBOARD ----------
st.title("🛡️ Visual Intelligence for Honeypot Defense")
st.markdown("---")

# Calculate time filter
now = datetime.now()
if time_range == "Last 24 Hours":
    start_time = now - timedelta(days=1)
elif time_range == "Last 7 Days":
    start_time = now - timedelta(days=7)
elif time_range == "Last 30 Days":
    start_time = now - timedelta(days=30)
else:
    start_time = datetime(2020, 1, 1)

# ---------- STATISTICS ROW ----------
col1, col2, col3, col4 = st.columns(4)

# Total Attacks
query_total = {
    "query": {
        "bool": {
            "filter": [
                {"range": {"@timestamp": {"gte": start_time.isoformat()}}}
            ]
        }
    }
}
df_total = query_elasticsearch(query_total)
col1.metric("🔄 Total Events", len(df_total))

# Unique Attackers
if not df_total.empty and "src_ip" in df_total.columns:
    unique_attackers = df_total['src_ip'].nunique()
    col2.metric("👤 Unique Attackers", unique_attackers)

# Top Attack Type
if not df_total.empty and "event_type" in df_total.columns:
    top_type = df_total['event_type'].mode()
    if not top_type.empty:
        col3.metric("🎯 Top Attack", top_type.iloc[0])

# Malware Detected
if not df_total.empty and "event_type" in df_total.columns:
    malware_count = len(df_total[df_total['event_type'] == 'malware_detected'])
    col4.metric("🦠 Malware Samples", malware_count)

st.markdown("---")

# ---------- CHARTS ----------
col1_chart, col2_chart = st.columns(2)

with col1_chart:
    st.subheader("📊 Attacks Over Time")
    if not df_total.empty and "@timestamp" in df_total.columns:
        df_total['@timestamp'] = pd.to_datetime(df_total['@timestamp'])
        df_ts = df_total.groupby(pd.Grouper(key='@timestamp', freq='1H')).size().reset_index(name='count')
        fig = px.line(df_ts, x='@timestamp', y='count', title="Attack Frequency (Hourly)")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No data for time series")

with col2_chart:
    st.subheader("🌍 Top Attackers by Country")
    if not df_total.empty and "geoip" in df_total.columns:
        country_counts = df_total['geoip'].apply(lambda x: x.get('country_name', 'Unknown') if isinstance(x, dict) else 'Unknown')
        country_df = country_counts.value_counts().reset_index()
        country_df.columns = ['Country', 'Count']
        fig = px.pie(country_df, values='Count', names='Country', title="Attack Origin Distribution")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No GeoIP data available")

st.markdown("---")

# ---------- GEO MAP ----------
st.subheader("🗺️ Global Attack Map")
if not df_total.empty and "geoip" in df_total.columns:
    map_df = df_total[df_total['geoip'].apply(lambda x: isinstance(x, dict) and 'location' in x)]
    if not map_df.empty:
        m = folium.Map(location=[20, 0], zoom_start=2)
        for _, row in map_df.iterrows():
            lat = row['geoip'].get('location', {}).get('lat')
            lon = row['geoip'].get('location', {}).get('lon')
            if lat and lon:
                folium.CircleMarker(
                    [lat, lon],
                    radius=3,
                    popup=f"{row.get('src_ip', 'Unknown')}<br>{row.get('event_type', '')}",
                    color='red',
                    fill=True
                ).add_to(m)
        folium_static(m, width=1200, height=500)
    else:
        st.info("No geolocation data available")
else:
    st.info("No location data available")

# ---------- RECENT ATTACKS ----------
st.markdown("---")
st.subheader("🕐 Recent Attack Activity")
if not df_total.empty:
    recent_df = df_total.sort_values('@timestamp', ascending=False).head(20)
    display_cols = ['@timestamp', 'src_ip', 'event_type', 'geoip.country_name', 'geoip.city_name']
    display_cols = [c for c in display_cols if c in recent_df.columns or c in recent_df]
    # Flatten geoip
    if 'geoip' in recent_df.columns:
        recent_df['geoip.country_name'] = recent_df['geoip'].apply(lambda x: x.get('country_name', '') if isinstance(x, dict) else '')
        recent_df['geoip.city_name'] = recent_df['geoip'].apply(lambda x: x.get('city_name', '') if isinstance(x, dict) else '')
    st.dataframe(recent_df[display_cols], use_container_width=True)
else:
    st.info("No recent activity")