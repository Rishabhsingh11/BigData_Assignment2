import folium
import pandas as pd
import requests
import streamlit as st
from streamlit_folium import st_folium

PREFIX = "http://fastapi:8000"


def nextrad_stations(access_token):
    headers = {"Authorization": f"Bearer {access_token}"}

    st.title("Next Generation Weather Radar(NEXRAD) Locations")
    st.caption("Source: National Oceanic and Atmospheric Administration")
    # send a GET request to retrieve the list of stations
    response = requests.get(f"{PREFIX}/nexrad_stations", headers=headers).json()
    # load the data into a pandas dataframe
    df = pd.DataFrame(response)
    m = folium.Map(
        location=[df["LAT"].mean(), df["LON"].mean()],
        width=700,
        height=1000,
        zoom_start=5,
        min_zoom=4,
        no_wrap=True,
        max_bounds=True,
        tiles="OpenStreetMap",
    )
    # Add markers to the map
    for i, row in df.iterrows():
        state = row["ST"] if row["ST"] != 0 else "N/A"
        county = row["COUNTY"] if row["COUNTY"] != 0 else "N/A"
        folium.Marker(
            [row["LAT"], row["LON"]],
            tooltip=f"Station Name: {row['NAME']}<br>Station ID: {row['ICAO']}<br>Country: {row['COUNTRY']}<br>State: {state}<br>County: {county}<br>Latitude: {row['LAT']:.4f}<br>Longitude: {row['LON']:.4f}",
        ).add_to(m)
    # Add the map to the Streamlit app
    st_data = st_folium(m, width=700)
    st.metric(label="Total NEXRAD Stations :", value=df["NAME"].count())
