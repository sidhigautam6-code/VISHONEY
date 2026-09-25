import streamlit as st
import pandas as pd
from elasticsearch import Elasticsearch
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import os

# ---------- PAGE CONFIG ----------
st.set_page_config(
    page_title="Attack Trends Analytics",
    page_icon="📊",
    layout="wide"
)

# ---------- CUSTOM CSS ----------
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        background: linear-gradient(90deg, #48dbfb, #0abde3, #54a0ff);
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
    .insight-card {
        background: linear-gradient(135deg, #1e1e2e, #2a2a3e);
        padding: 1.2rem;
        border-radius: 12px;
        border-left: 4px solid #48dbfb;
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
        margin-bottom: 1rem;
    }
    .insight-card h4 {
        color: #48dbfb;
        margin: 0 0 0.5rem 0;
        font-size: 1rem;
    }
    .insight-card p {
        color: #ccc;
        margin: 0;
        font-size: 0.95rem;
    }
    div[data-testid="stMetricValue"] {
        font-size: 1.8rem;
        font-weight: bold;
        color: #48dbfb;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #1e1e2e;
        border-radius: 8px;
        padding: 10px 20px;
        color: #ccc;
    }
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #48dbfb, #0abde3);
        color: white;
    }
</style>
""", unsafe_allow_html=True)

# ---------- HEADER ----------
st.markdown('<div class="main-header">📊 Attack Trends Analytics</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Comprehensive analysis of attack patterns, trends, and behaviors</div>', unsafe_allow_html=True)

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

# ---------- FETCH DATA ----------
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
    df['date'] = df['@timestamp'].dt.date
    df['hour'] = df['@timestamp'].dt.hour
    df['day_of_week'] = df['@timestamp'].dt.day_name()
    df['day_num'] = df['@timestamp'].dt.dayofweek

# Extract geoip
if 'geoip' in df.columns:
    df['country'] = df['geoip'].apply(lambda x: x.get('country_name', 'Unknown') if isinstance(x, dict) else 'Unknown')

# ---------- TOP METRICS ----------
st.markdown("### 🎯 Attack Summary Metrics")

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric("🔄 Total Events", len(df), help="Total attack events captured")
with col2:
    st.metric("👤 Unique Attackers", df['src_ip'].nunique() if 'src_ip' in df.columns else 0, help="Distinct source IPs")
with col3:
    st.metric("🎯 Attack Types", df['event_type'].nunique() if 'event_type' in df.columns else 0, help="Different attack categories")
with col4:
    st.metric("🌍 Countries", df['country'].nunique() if 'country' in df.columns else 0, help="Source countries")
with col5:
    if 'dst_port' in df.columns:
        st.metric("🔌 Target Ports", df['dst_port'].nunique(), help="Distinct target ports")

st.markdown("---")

# ---------- TABS FOR ORGANIZED VIEW ----------
tab1, tab2, tab3, tab4 = st.tabs(["📈 Trends & Timeline", "🎯 Attack Analysis", "👤 Attacker Profile", "💡 Insights"])

# ============================================================
# TAB 1: TRENDS & TIMELINE
# ============================================================
with tab1:
    st.markdown("### 📈 Attack Trends Over Time")
    
    col1, col2 = st.columns([3, 1])
    
    with col2:
        freq = st.selectbox(
            "Time Interval",
            ["Hourly", "Daily", "Weekly"],
            index=0
        )
        freq_map = {"Hourly": "1H", "Daily": "1D", "Weekly": "1W"}
        freq_code = freq_map[freq]
    
    with col1:
        if "@timestamp" in df.columns:
            df_ts = df.groupby(pd.Grouper(key='@timestamp', freq=freq_code)).size().reset_index(name='count')
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=df_ts['@timestamp'],
                y=df_ts['count'],
                mode='lines+markers',
                name='Attacks',
                line=dict(color='#48dbfb', width=3),
                marker=dict(size=8, color='#0abde3', line=dict(width=2, color='white')),
                fill='tozeroy',
                fillcolor='rgba(72, 219, 251, 0.15)'
            ))
            
            fig.update_layout(
                title=f"Attack Frequency ({freq})",
                height=400,
                margin=dict(l=0, r=0, t=40, b=0),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='#ccc'),
                xaxis=dict(title="Time", gridcolor='#333'),
                yaxis=dict(title="Number of Attacks", gridcolor='#333'),
                hovermode='x unified'
            )
            st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # ---------- ATTACK HEATMAP BY HOUR AND DAY ----------
    st.markdown("### 🔥 Attack Heatmap (Day × Hour)")
    st.markdown("_Shows which days and hours have the most attack activity_")
    
    if "@timestamp" in df.columns:
        heatmap_data = df.groupby(['day_of_week', 'hour']).size().reset_index(name='count')
        
        # Order days properly
        day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
        heatmap_data['day_of_week'] = pd.Categorical(heatmap_data['day_of_week'], categories=day_order, ordered=True)
        heatmap_data = heatmap_data.sort_values('day_of_week')
        
        # Pivot for heatmap
        heatmap_pivot = heatmap_data.pivot(index='day_of_week', columns='hour', values='count').fillna(0)
        
        fig = px.imshow(
            heatmap_pivot,
            labels=dict(x="Hour of Day", y="Day of Week", color="Attacks"),
            color_continuous_scale='Reds',
            aspect='auto'
        )
        fig.update_layout(
            height=350,
            margin=dict(l=0, r=0, t=20, b=0),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#ccc')
        )
        st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # ---------- CUMULATIVE ATTACKS ----------
    st.markdown("### 📊 Cumulative Attack Growth")
    
    if "@timestamp" in df.columns:
        df_sorted = df.sort_values('@timestamp').copy()
        df_sorted['cumulative'] = range(1, len(df_sorted) + 1)
        
        fig = px.area(
            df_sorted,
            x='@timestamp',
            y='cumulative',
            title="Total Attacks Over Time"
        )
        fig.update_traces(
            line=dict(color='#54a0ff', width=2),
            fillcolor='rgba(84, 160, 255, 0.2)'
        )
        fig.update_layout(
            height=350,
            margin=dict(l=0, r=0, t=40, b=0),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#ccc'),
            xaxis_title="Time",
            yaxis_title="Cumulative Attacks"
        )
        st.plotly_chart(fig, use_container_width=True)

# ============================================================
# TAB 2: ATTACK ANALYSIS
# ============================================================
with tab2:
    st.markdown("### 🎯 Attack Type Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if "event_type" in df.columns:
            type_counts = df['event_type'].value_counts().reset_index()
            type_counts.columns = ['Type', 'Count']
            
            fig = px.pie(
                type_counts,
                values='Count',
                names='Type',
                hole=0.5,
                title="Attack Type Distribution",
                color_discrete_sequence=px.colors.qualitative.Set2
            )
            fig.update_traces(
                textposition='outside',
                textinfo='percent+label',
                marker=dict(line=dict(color='#1e1e2e', width=2))
            )
            fig.update_layout(
                height=400,
                margin=dict(l=0, r=0, t=40, b=0),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='#ccc'),
                showlegend=True,
                legend=dict(bgcolor='rgba(30,30,46,0.8)')
            )
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        if "dst_port" in df.columns:
            port_counts = df['dst_port'].value_counts().head(10).reset_index()
            port_counts.columns = ['Port', 'Count']
            port_counts['Port'] = port_counts['Port'].astype(str)
            
            fig = px.bar(
                port_counts,
                x='Port',
                y='Count',
                title="Top 10 Targeted Ports",
                color='Count',
                color_continuous_scale='Reds',
                text='Count'
            )
            fig.update_traces(textposition='outside')
            fig.update_layout(
                height=400,
                margin=dict(l=0, r=0, t=40, b=0),
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color='#ccc'),
                showlegend=False,
                coloraxis_showscale=False,
                xaxis_title="Port Number",
                yaxis_title="Number of Attacks"
            )
            st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # ---------- ATTACK TYPE TIMELINE ----------
    st.markdown("### 📊 Attack Types Over Time")
    
    if "@timestamp" in df.columns and "event_type" in df.columns:
        df_typed = df.groupby([pd.Grouper(key='@timestamp', freq='1H'), 'event_type']).size().reset_index(name='count')
        
        fig = px.line(
            df_typed,
            x='@timestamp',
            y='count',
            color='event_type',
            title="Attack Type Trends",
            markers=True,
            color_discrete_sequence=px.colors.qualitative.Bold
        )
        fig.update_layout(
            height=400,
            margin=dict(l=0, r=0, t=40, b=0),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#ccc'),
            xaxis=dict(gridcolor='#333'),
            yaxis=dict(gridcolor='#333'),
            legend=dict(bgcolor='rgba(30,30,46,0.8)', title="Attack Type")
        )
        st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # ---------- SOURCE PORT ANALYSIS ----------
    if "src_port" in df.columns:
        st.markdown("### 🔌 Source Port Distribution (Top 10)")
        
        src_ports = df['src_port'].value_counts().head(10).reset_index()
        src_ports.columns = ['Port', 'Count']
        src_ports['Port'] = src_ports['Port'].astype(str)
        
        fig = px.bar(
            src_ports,
            x='Port',
            y='Count',
            color='Count',
            color_continuous_scale='Blues',
            text='Count'
        )
        fig.update_traces(textposition='outside')
        fig.update_layout(
            height=350,
            margin=dict(l=0, r=0, t=20, b=0),
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#ccc'),
            showlegend=False,
            coloraxis_showscale=False
        )
        st.plotly_chart(fig, use_container_width=True)

# ============================================================
# TAB 3: ATTACKER PROFILE
# ============================================================
with tab3:
    st.markdown("### 👤 Attacker Profiling")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🏆 Top 10 Attacking IPs")
        
        if "src_ip" in df.columns:
            ip_counts = df['src_ip'].value_counts().head(10).reset_index()
            ip_counts.columns = ['IP', 'Attacks']
            
            fig = px.bar(
                ip_counts,
                x='Attacks',
                y='IP',
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
        st.markdown("#### 👤 Top Targeted Usernames")
        
        if "username" in df.columns:
            valid_users = df[df['username'] != '']['username']
            if not valid_users.empty:
                user_counts = valid_users.value_counts().head(10).reset_index()
                user_counts.columns = ['Username', 'Attempts']
                
                fig = px.bar(
                    user_counts,
                    x='Attacks' if 'Attacks' in user_counts.columns else 'Attempts',
                    y='Username',
                    orientation='h',
                    color='Attempts',
                    color_continuous_scale='Oranges',
                    text='Attempts'
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
    
    st.markdown("---")
    
    # ---------- ATTACKER BEHAVIOR ----------
    st.markdown("### 📋 Attacker Behavior Summary")
    
    if "src_ip" in df.columns:
        attacker_summary = df.groupby('src_ip').agg({
            'event_type': lambda x: ', '.join(x.unique()[:3]),
            '@timestamp': ['min', 'max', 'count']
        }).reset_index()
        attacker_summary.columns = ['IP', 'Attack Types', 'First Seen', 'Last Seen', 'Count']
        attacker_summary = attacker_summary.sort_values('Count', ascending=False).head(15)
        
        st.dataframe(
            attacker_summary,
            use_container_width=True,
            height=450,
            column_config={
                "IP": st.column_config.TextColumn("🌐 IP Address", width="medium"),
                "Attack Types": st.column_config.TextColumn("🎯 Attack Types", width="large"),
                "First Seen": st.column_config.DatetimeColumn("⏰ First Seen", format="DD/MM/YY HH:mm"),
                "Last Seen": st.column_config.DatetimeColumn("🕐 Last Seen", format="DD/MM/YY HH:mm"),
                "Count": st.column_config.NumberColumn("📊 Total Attacks", width="small")
            }
        )

# ============================================================
# TAB 4: INSIGHTS
# ============================================================
with tab4:
    st.markdown("### 💡 Automated Threat Insights")
    st.markdown("_AI-computed patterns and recommendations from your attack data_")
    st.markdown("---")
    
    # Insight 1: Attack Volume Trend
    if "@timestamp" in df.columns:
        df_recent = df.sort_values('@timestamp', ascending=False).head(int(len(df) * 0.5))
        df_older = df.sort_values('@timestamp', ascending=False).tail(int(len(df) * 0.5))
        
        col1, col2 = st.columns(2)
        
        with col1:
            trend_icon = "📈" if len(df_recent) > len(df_older) else "📉"
            trend_text = "increasing" if len(df_recent) > len(df_older) else "decreasing"
            st.markdown(f"""
            <div class="insight-card">
                <h4>{trend_icon} Attack Volume Trend</h4>
                <p>Attack activity is <b>{trend_text}</b>. Recent activity shows {len(df_recent)} attacks versus {len(df_older)} in the previous period.</p>
            </div>
            """, unsafe_allow_html=True)
        
        # Insight 2: Peak Attack Time
        with col2:
            if 'hour' in df.columns:
                peak_hour = df['hour'].mode().iloc[0] if not df['hour'].mode().empty else 0
                st.markdown(f"""
                <div class="insight-card">
                    <h4>⏰ Peak Attack Window</h4>
                    <p>Most attacks occur around <b>{peak_hour}:00</b>. Recommend heightened monitoring during this period.</p>
                </div>
                """, unsafe_allow_html=True)
    
    col3, col4 = st.columns(2)
    
    # Insight 3: Top Targeted Asset
    with col3:
        if "dst_port" in df.columns:
            top_port = df['dst_port'].mode().iloc[0] if not df['dst_port'].mode().empty else 'N/A'
            port_service = {
                22: "SSH", 21: "FTP", 23: "Telnet", 80: "HTTP", 443: "HTTPS",
                3306: "MySQL", 3389: "RDP", 445: "SMB", 5060: "SIP"
            }.get(top_port, "Unknown")
            st.markdown(f"""
            <div class="insight-card">
                <h4>🎯 Most Targeted Port</h4>
                <p>Port <b>{top_port} ({port_service})</b> receives the most attacks. Ensure this service is properly secured.</p>
            </div>
            """, unsafe_allow_html=True)
    
    # Insight 4: Top Credential Attempts
    with col4:
        if "username" in df.columns:
            valid = df[df['username'] != '']['username']
            if not valid.empty:
                top_user = valid.mode().iloc[0]
                st.markdown(f"""
                <div class="insight-card">
                    <h4>🔑 Top Credential Attack</h4>
                    <p>Attackers most frequently try username <b>'{top_user}'</b>. Consider blocking or alerting on this credential.</p>
                </div>
                """, unsafe_allow_html=True)
    
    st.markdown("---")
    
    # ---------- ATTACK SEVERITY SCORE ----------
    st.markdown("### 🎯 Overall Threat Score")
    
    # Calculate threat score (0-100)
    volume_score = min(len(df) / 10, 40)  # Max 40 points
    diversity_score = min(df['event_type'].nunique() * 5, 20) if 'event_type' in df.columns else 0  # Max 20
    geo_score = min(df['country'].nunique() * 2, 20) if 'country' in df.columns else 0  # Max 20
    ip_score = min(df['src_ip'].nunique() / 2, 20) if 'src_ip' in df.columns else 0  # Max 20
    
    total_score = int(volume_score + diversity_score + geo_score + ip_score)
    
    if total_score >= 70:
        risk_level = "🔴 CRITICAL"
        risk_color = "#ff4b4b"
    elif total_score >= 50:
        risk_level = "🟠 HIGH"
        risk_color = "#ff6b6b"
    elif total_score >= 30:
        risk_level = "🟡 MEDIUM"
        risk_color = "#feca57"
    else:
        risk_level = "🟢 LOW"
        risk_color = "#48dbfb"
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=total_score,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': f"Threat Score<br><span style='font-size:1.2em;color:{risk_color}'>{risk_level}</span>", 'font': {'color': '#ccc'}},
            gauge={
                'axis': {'range': [0, 100], 'tickcolor': '#ccc'},
                'bar': {'color': risk_color},
                'bgcolor': '#1e1e2e',
                'steps': [
                    {'range': [0, 30], 'color': 'rgba(72, 219, 251, 0.2)'},
                    {'range': [30, 50], 'color': 'rgba(254, 202, 87, 0.2)'},
                    {'range': [50, 70], 'color': 'rgba(255, 107, 107, 0.2)'},
                    {'range': [70, 100], 'color': 'rgba(255, 75, 75, 0.2)'}
                ],
                'threshold': {
                    'line': {'color': "white", 'width': 4},
                    'thickness': 0.75,
                    'value': total_score
                }
            }
        ))
        fig.update_layout(
            height=350,
            margin=dict(l=20, r=20, t=60, b=20),
            paper_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#ccc')
        )
        st.plotly_chart(fig, use_container_width=True)
    
    st.markdown("---")
    
    # ---------- RECOMMENDATIONS ----------
    st.markdown("### 🛡️ Recommended Actions")
    
    recommendations = []
    
    if len(df) > 100:
        recommendations.append("⚠️ **High attack volume** — Consider rate limiting or blocking top attacking IPs")
    
    if 'src_ip' in df.columns and df['src_ip'].nunique() > 10:
        recommendations.append("🌍 **Multiple attack sources** — Implement geo-blocking for suspicious regions")
    
    if 'dst_port' in df.columns:
        top_port = df['dst_port'].mode().iloc[0] if not df['dst_port'].mode().empty else None
        if top_port == 22:
            recommendations.append("🔒 **SSH is heavily targeted** — Disable password auth, use SSH keys only")
        elif top_port == 80:
            recommendations.append("🌐 **HTTP is targeted** — Enable WAF, use HTTPS with valid certificates")
    
    if 'username' in df.columns:
        common_users = ['root', 'admin', 'test', 'user']
        targeted = [u for u in common_users if u in df['username'].values]
        if targeted:
            recommendations.append(f"🔑 **Common usernames targeted** ({', '.join(targeted)}) — Use strong unique credentials")
    
    if not recommendations:
        recommendations.append("✅ **No critical issues detected** — Continue monitoring for new patterns")
    
    for rec in recommendations:
        st.markdown(f"- {rec}")

# ---------- FOOTER ----------
st.markdown("---")
st.markdown(
    "<p style='text-align: center; color: #666; font-size: 0.9rem;'>"
    "🛡️ Visual Intelligence for Honeypot Defense | Attack Trends Analytics"
    "</p>",
    unsafe_allow_html=True
)