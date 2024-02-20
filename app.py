import streamlit as st # Data app/visualization framework
import pydeck as pdk # Geomap plots that work with streamlit
from monitor import get_ip_traffic

if __name__ == '__main__':
    st.set_page_config(page_title='Web Traffic Map', layout='wide',)
    
    # Set up sidebar controls
    st.sidebar.title("Monitor Controls")
    st.sidebar.caption("Configure your filters and configurations here to rerun the application.")
    packet_count = st.sidebar.number_input(label="Packets to Wait For", min_value=1, max_value=10000, value=100)
    traffic_filter = st.sidebar.text_input(label='Wireshark BPF Filters', value='ip || ip6')
    interface = st.sidebar.text_input(label='Wireshark Interface', value='Wi-Fi')
    local_regex = st.sidebar.text_input(label='Regex for Local IPs', value='^192\.', help="Any IP that fails geolocation lookup will use this machine's location if it matches this regex.")

    # Monitor traffic for data
    chart_data = get_ip_traffic(packet_count=packet_count, traffic_filter=traffic_filter, interface=interface, local_regex=local_regex)

    # Display results
    st.title("Web Traffic Map")

    st.pydeck_chart(pdk.Deck(
        map_style="dark",
        initial_view_state=pdk.ViewState(
            latitude=40,
            longitude=-95.4,
            zoom=2.8,
            pitch=0,
        ),
        layers=[
            pdk.Layer(
            'ArcLayer',
            data=chart_data,
            get_source_position=['lon_src', 'lat_src'],
            get_target_position=['lon_dst', 'lat_dst'],
            get_source_color=[0, 255, 0, 40],
            get_target_color=[240, 100, 0, 40],
            width='packets',
            auto_highlight=True,
            ),
        ],
    ))

    st.subheader('Packet Data')
    st.dataframe(data=chart_data, use_container_width=True, hide_index=True)