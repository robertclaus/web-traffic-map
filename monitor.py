import pandas as pd # Used to return a standardized data table
from ip_utils import get_ip_metadata, get_packets, get_packet_data, get_direction

def get_ip_traffic(packet_count=5, traffic_filter="ip || ip6", interface='Wi-Fi', local_regex='^192\.'):
    # Run the monitor in another process to avoid asyncio conflicts between streamlit and pyshark
    packets = get_packets(packet_count, traffic_filter, interface)
    ip_metadata = get_ip_metadata(packets, local_regex)

    # Convert the ip connections into a table representation
    df_array = []
    for packet in packets:
        (src_ip, dst_ip, size) = get_packet_data(packet)
        if src_ip in ip_metadata and dst_ip in ip_metadata:
            (src_lat, src_lon, src_country, src_organization) = ip_metadata[src_ip]
            (dst_lat, dst_lon, dst_country, dst_organization) = ip_metadata[dst_ip]
            direction = get_direction(src_ip, dst_ip, local_regex)
            not_me_country = src_country if direction == "Inbound" else dst_country
            not_me_organization = src_organization if direction == "Inbound" else dst_organization
            df_array.append([direction, src_ip, dst_ip, src_lat, src_lon, src_country, src_organization, dst_lat, dst_lon, dst_country, dst_organization, size, not_me_country, not_me_organization])

    column_names = ['direction', 'ip_src', 'ip_dst', 'lat_src', 'lon_src', 'country_src', 'organization_src', 'lat_dst', 'lon_dst', 'country_dst', 'organization_dst', 'size', 'not_me_country', 'not_me_organization']
    chart_data = pd.DataFrame(df_array, columns=column_names)

    # Compute how many packets correspond to the same source and destination, then remove those duplicates.
    chart_data["packets"] = chart_data.groupby(['ip_src', 'ip_dst'], sort=False)['ip_src'].transform('size')
    chart_data["total_size"] = chart_data.groupby(['ip_src', 'ip_dst'], sort=False)['size'].transform('sum')
    chart_data = chart_data.drop_duplicates(['ip_src', 'ip_dst'])
    
    return chart_data

if __name__ == '__main__':
    d = get_ip_traffic()
    print(d)