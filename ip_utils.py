import requests
import re

def get_my_ip():
    v4ip = requests.get('https://api.ipify.org').text
    v6ip = requests.get('https://api64.ipify.org').text
    return v4ip, v6ip

def get_ip_locations_mapping(ip_addresses, local_regex='^192\.'):
    # Create an account and get the free API key here: https://app.ipgeolocation.io/dashboard
    API_KEY = "eba773bfcfe94fb192f5d524bdd8d8cb"

    ip_to_location_map = {}
    local_ips = []

    for ip in ip_addresses:
        url = f"https://api.ipgeolocation.io/ipgeo?apiKey={API_KEY}&ip={ip}"
        response = requests.get(url)
        json = response.json()
        if "latitude" in json and "longitude" in json:
            ip_to_location_map[ip] = [float(json["latitude"]), float(json["longitude"])]
        else:
            if re.search(local_regex, ip):
                local_ips.append(ip)
            else:
                print(f"Failed location lookup on {ip}")
    
    my_v4, my_v6 = get_my_ip()
    my_loc = ip_to_location_map.get(my_v4, ip_to_location_map.get(my_v6, None))
    if my_loc:
        for ip in local_ips:
            ip_to_location_map[ip] = my_loc
    
    return ip_to_location_map

if __name__ == '__main__':
    v4, v6 = get_my_ip()
    print(v4)
    print(v6)