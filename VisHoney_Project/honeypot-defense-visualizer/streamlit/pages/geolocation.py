import streamlit as st
import folium
from streamlit_folium import folium_static
from app import query_elasticsearch, es
import pandas as pd

st.set_page_config(page_title="Geolocation Map", page_icon="🗺️")

st.title("🗺️ Global Attack Map")

if not es:
    st.error("Not connected to Elasticsearch")
    st.stop()

# Query data with geoip
query = {
    "query": {
        "exists": {"field": "geoip.location"}
    },
    "size": 500
}
df = query_elasticsearch(query)

if df.empty:
    st.info("No geolocation data available")
    st.stop()

# Create map
m = folium.Map(location=[20, 0], zoom_start=2)

for _, row in df.iterrows():
    if 'geoip' in row and isinstance(row['geoip'], dict):
        loc = row['geoip'].get('location')
        if loc and isinstance(loc, dict):
            lat = loc.get('lat')
            lon = loc.get('lon')
            if lat and lon:
                popup_text = f"""
                <b>IP:</b> {row.get('src_ip', 'Unknown')}<br>
                <b>Type:</b> {row.get('event_type', 'Unknown')}<br>
                <b>Country:</b> {row['geoip'].get('country_name', 'Unknown')}<br>
                <b>City:</b> {row['geoip'].get('city_name', 'Unknown')}
                """
                folium.CircleMarker(
                    [lat, lon],
                    radius=5,
                    popup=folium.Popup(popup_text, max_width=300),
                    color='red',
                    fill=True,
                    fill_opacity=0.7
                ).add_to(m)

folium_static(m, width=1200, height=700)