import pyshark # Used to listen in on Wireshark's internet monitoring
import requests
import re
import multiprocessing
from functools import lru_cache

def get_packets_in_worker(return_dict, packet_count, traffic_filter, interface):
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=traffic_filter)
    return_dict["packets"] = list(capture.sniff_continuously(packet_count=packet_count))

def get_packets(packet_count, traffic_filter, interface):
    # Run the monitor in another process to avoid asyncio conflicts between streamlit and pyshark
    return_dict = multiprocessing.Manager().dict()
    p = multiprocessing.Process(target=get_packets_in_worker, args=(return_dict, packet_count, traffic_filter, interface))
    p.start()
    p.join()
    return return_dict.get("packets", [])

@lru_cache(maxsize=None)
def get_my_ip():
    v4ip = requests.get('https://api.ipify.org').text
    v6ip = requests.get('https://api64.ipify.org').text
    return v4ip, v6ip

@lru_cache(maxsize=None)
def get_direction(src, dst, local_regex=None):
    my_v4, my_v6 = get_my_ip()
    if src == my_v4 or src == my_v6 or (local_regex and is_local(src, local_regex)):
        return "Outbound"
    if dst == my_v4 or dst == my_v6 or (local_regex and is_local(dst, local_regex)):
        return "Inbound"
    return "Unclear"

@lru_cache(maxsize=None)
def is_local(ip, local_regex):
    return bool(re.search(local_regex, ip))

def get_packet_data(packet):
    try:
        src = packet.ip.src
        dst = packet.ip.dst
        size = float(packet.captured_length)
    except:
        src = packet.ipv6.src
        dst = packet.ipv6.dst
        size = float(packet.captured_length)

    return (src, dst, size)

def get_ip_metadata(packets, local_regex='^192\.'):
    # Create an account and get the free API key here: https://app.ipgeolocation.io/dashboard
    API_KEY = "eba773bfcfe94fb192f5d524bdd8d8cb"

    ip_addresses = set()
    for packet in packets:
        (src, dst, size) = get_packet_data(packet)
        ip_addresses.add(src)
        ip_addresses.add(dst)

    ip_metadata = {}
    ips_without_metadata = []

    for ip in ip_addresses:
        url = f"https://api.ipgeolocation.io/ipgeo?apiKey={API_KEY}&ip={ip}"
        response = requests.get(url)
        json = response.json()
        if "latitude" in json and "longitude" in json:
            ip_metadata[ip] = (float(json["latitude"]), float(json["longitude"]), json["country_name"], json["organization"])
        else:
            ips_without_metadata.append(ip)
    
    # For local ips, copy my ip address's metadata if available
    my_v4, my_v6 = get_my_ip()
    my_loc = ip_metadata.get(my_v4, ip_metadata.get(my_v6, None))
    for ip in ips_without_metadata:
        if is_local(ip, local_regex) and my_loc:
            ip_metadata[ip] = my_loc
        else:
            print(f"Failed location lookup on {ip}")
    
    return ip_metadata

if __name__ == '__main__':
    v4, v6 = get_my_ip()
    print(v4)
    print(v6)