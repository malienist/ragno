import requests

url = "https://www.virustotal.com/api/v3/ip_addresses/5.230.147.179/communicating_files"

querystring = {"limit":"1"}

headers = {'x-apikey': '01e1da8663a736e01d2f43ac210ac8ddc303e6f711a1f992275df4dd5155121e'}

response = requests.request("GET", url, headers=headers, params=querystring)

print(response.text)