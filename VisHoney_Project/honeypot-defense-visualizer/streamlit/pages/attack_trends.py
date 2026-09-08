import streamlit as st
import plotly.express as px
from app import query_elasticsearch, es
import pandas as pd

st.set_page_config(page_title="Attack Trends", page_icon="📊")

st.title("📈 Attack Trends Analysis")

if not es:
    st.error("Not connected to Elasticsearch")
    st.stop()

# Query all data
query = {"query": {"match_all": {}}}
df = query_elasticsearch(query)

if df.empty:
    st.info("No data available")
    st.stop()

# Top targeted ports
st.subheader("🎯 Top Targeted Ports")
if "src_port" in df.columns:
    port_counts = df['src_port'].value_counts().head(10).reset_index()
    port_counts.columns = ['Port', 'Count']
    fig = px.bar(port_counts, x='Port', y='Count', title="Most Targeted Ports")
    st.plotly_chart(fig, use_container_width=True)

# Attack type distribution
st.subheader("📊 Attack Type Distribution")
if "event_type" in df.columns:
    type_counts = df['event_type'].value_counts().reset_index()
    type_counts.columns = ['Type', 'Count']
    fig = px.pie(type_counts, values='Count', names='Type', title="Attack Types")
    st.plotly_chart(fig, use_container_width=True)

# Top usernames (for Cowrie)
st.subheader("👤 Top Usernames Targeted")
if "username" in df.columns:
    user_counts = df['username'].value_counts().head(10).reset_index()
    user_counts.columns = ['Username', 'Count']
    fig = px.bar(user_counts, x='Username', y='Count', title="Most Targeted Usernames")
    st.plotly_chart(fig, use_container_width=True)