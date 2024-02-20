# Web Traffic App

This app displays traffic captured by Wireshark on a map in a simple browser app using Streamlit.

![image](https://github.com/robertclaus/web-traffic-map/assets/9631768/e0dd81d0-6f60-4c72-9006-ae2469f1dd67)

## Install
Installation requires Wireshark and the applicable Python libraries to be installed.

To install the Python dependencies:
```bash
pip install -r requirements.txt
```

To install Wireshark:
https://www.wireshark.org/download.html

## Running
Start Wireshark and make sure you can see individual packets. Preferrably apply a filter to make sure ip and/or ipv6 traffic is flowing and being captured.

Start the streamlit app:
```bash
python -m streamlit run app.py
```

By default the app will wait for about 100 IP packets. Once you see that it's working, I recommend bumping this up to 5000 or so.

For convenience, I've temporarily included my personal API key for the geolocation service in the code within `ip_utils.py`. Please note that I will likely remove and rotate this key if I run into any bandwidth issues on the free tier.

## Feature Requests and Bug Reports
Please open issues on this repo for any requested changes. Please also feel free to open a pull request with suggestions!
