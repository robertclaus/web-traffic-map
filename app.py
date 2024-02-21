import streamlit as st # Data app/visualization framework
import pydeck as pdk # Geomap plots that work with streamlit
import altair as alt
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
            get_source_color=['direction === "Inbound" ? 255 : 0', 'direction === "Inbound" ? 0 : 255', 0, 80],
            get_target_color=['direction === "Outbound" ? 255 : 0', 'direction === "Outbound" ? 0 : 255', 0, 80],
            width=10,
            auto_highlight=True,
            ),
        ],
    ))

    st.subheader('Summary Data')
    col1, col2 = st.columns(2)

    with col1:
        c = (
            alt.Chart(chart_data, 
                    title=alt.TitleParams('Traffic Breakdown (bytes)', anchor='middle')
            ).mark_arc(innerRadius=50).encode(
                theta="total_size",
                color="direction:N",
                tooltip=['not_me_country', 'not_me_organization', 'ip_src', 'ip_dst', 'total_size', 'packets']
            )
        )
        st.altair_chart(c, use_container_width=False)

        c = (
            alt.Chart(chart_data, 
                    title=alt.TitleParams('Server Organization (bytes)', anchor='middle')
            ).mark_arc(innerRadius=50).encode(
                theta="total_size",
                color="not_me_organization:N",
                tooltip=['not_me_country', 'not_me_organization', 'ip_src', 'ip_dst', 'total_size', 'packets']
            )
        )
        st.altair_chart(c, use_container_width=False)

    with col2:
        c = (
            alt.Chart(chart_data, 
                    title=alt.TitleParams('Server Country (packets)', anchor='middle')
            ).mark_arc(innerRadius=50).encode(
                theta="packets",
                color="not_me_country:N",
                tooltip=['not_me_country', 'not_me_organization', 'ip_src', 'ip_dst', 'total_size', 'packets']
            )
        )
        st.altair_chart(c, use_container_width=False)

        c = (
            alt.Chart(chart_data, 
                    title=alt.TitleParams('Total Size vs Packets', anchor='middle')
            ).mark_circle(size=60).encode(
                x='packets',
                y='total_size',
                color='not_me_organization',
                tooltip=['not_me_country', 'not_me_organization', 'ip_src', 'ip_dst', 'total_size', 'packets']
            )
        )
        st.altair_chart(c, use_container_width=False)

    st.subheader('Packet Data')
    st.dataframe(data=chart_data, use_container_width=True, hide_index=True)