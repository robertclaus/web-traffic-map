import pyshark # Used to listen in on Wireshark's internet monitoring
import pandas as pd # Used to return a standardized data table
import multiprocessing
from ip_utils import get_ip_locations_mapping

def monitor_traffic_in_worker(return_dict, packet_count, traffic_filter, interface, local_regex):
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=traffic_filter)

    ip_addresses = set()
    ip_connections = []

    for packet in capture.sniff_continuously(packet_count=packet_count):
        try:
            src = packet.ip.src
            dst = packet.ip.dst
        except:
            src = packet.ipv6.src
            dst = packet.ipv6.dst

        ip_addresses.add(src)
        ip_addresses.add(dst)
        ip_connections.append([src, dst])

    return_dict["ip_geolocations"] = get_ip_locations_mapping(ip_addresses, local_regex)
    return_dict["ip_connections"] = ip_connections

def get_ip_traffic(packet_count=5, traffic_filter="ip || ip6", interface='Wi-Fi', local_regex='^192\.'):
    # Run the monitor in another process to avoid asyncio conflicts between streamlit and pyshark
    return_dict = multiprocessing.Manager().dict()
    p = multiprocessing.Process(target=monitor_traffic_in_worker, args=(return_dict, packet_count, traffic_filter, interface, local_regex))
    p.start()
    p.join()

    ip_connections = return_dict.get("ip_connections", {})
    ip_to_geolocation_map = return_dict.get("ip_geolocations", {})
    
    # Convert the ip connections into a table representation
    df_array = []
    for [src_ip, dst_ip] in ip_connections:
        if src_ip in ip_to_geolocation_map and dst_ip in ip_to_geolocation_map:
            [src_lat, src_lon] = ip_to_geolocation_map[src_ip]
            [dst_lat, dst_lon] = ip_to_geolocation_map[dst_ip]
            df_array.append([src_ip, dst_ip, src_lat, src_lon, dst_lat, dst_lon])

    column_names = ['ip_src', 'ip_dst', 'lat_src', 'lon_src', 'lat_dst', 'lon_dst']
    chart_data = pd.DataFrame(df_array, columns=column_names)

    # Compute how many packets correspond to the same source and destination, then remove those duplicates.
    chart_data["packets"] = chart_data.groupby(column_names, sort=False)['ip_src'].transform('size')
    chart_data = chart_data.drop_duplicates()
    
    return chart_data

if __name__ == '__main__':
    d = get_ip_traffic()
    print(d)