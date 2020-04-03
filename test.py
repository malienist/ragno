import requests
import json

url = "https://www.virustotal.com/api/v3/ip_addresses/5.230.147.179/communicating_files"

querystring = {"limit":"10"}

headers = {'x-apikey': '01e1da8663a736e01d2f43ac210ac8ddc303e6f711a1f992275df4dd5155121e'}

response = requests.request("GET", url, headers=headers, params=querystring)
json_response = response.json()
f = open("IOC-list.txt", "w")
f.write('Ragno: Network IOC List. \n')
f.close()
print('Casting Web 1...\n')
try:
    if 'network_infrastructure' in json_response['data'][0]['attributes']:
        web_1=json_response['data'][0]['attributes']['network_infrastructure']
        print('Web 1 results: \n')
        print(json_response['data'][0]['attributes']['network_infrastructure'])
        with open('IOC-list.txt', 'a+') as file:
            json.dump(web_1, file)
    else:
        print('Web did not find any Network-specific IOC.\n')
except IndexError:
    print("Web didn't return any results. \n")

print('Casting Web 2...\n')
try:
    if 'network_infrastructure' in json_response['data'][1]['attributes']:
        web_2=json_response['data'][1]['attributes']['network_infrastructure']
        print('Web 2 results: \n')
        print(json_response['data'][1]['attributes']['network_infrastructure'])
        with open('IOC-list.txt', 'a+') as file:
            json.dump(web_2, file)
    else:
        print('Web did not find any Network-specific IOC.\n')
except IndexError:
    print("Web didn't return any results. \n")

print('Casting Web 3...\n')
try:
    if 'network_infrastructure' in json_response['data'][2]['attributes']:
        print('Web 3 results: \n')
        print(json_response['data'][2]['attributes']['network_infrastructure'])
    else:
        print('Web did not find any Network-specific IOC.\n')
except IndexError:
    print("Web didn't return any results. \n")

print('Casting Web 4...\n')
try:
    if 'network_infrastructure' in json_response['data'][3]['attributes']:
        print('Web 4 results: \n')
        print(json_response['data'][3]['attributes']['network_infrastructure'])
    else:
        print('Web did not find any Network-specific IOC.\n')
except IndexError:
    print("Web didn't return any results. \n")

print('Casting Web 5...\n')
try:
    if 'network_infrastructure' in json_response['data'][4]['attributes']:
        print('Web 5 results: \n')
        print(json_response['data'][4]['attributes']['network_infrastructure'])
    else:
        print('Web did not find any Network-specific IOC.\n')
except IndexError:
    print("Web didn't return any results. \n")

print('Casting Web 6...\n')
try:
    if 'network_infrastructure' in json_response['data'][5]['attributes']:
        print('Web 6 results: \n')
        print(json_response['data'][5]['attributes']['network_infrastructure'])
    else:
        print('Web did not find any Network-specific IOC.\n')
except IndexError:
    print("Web didn't return any results. \n")

print('Casting Web 7...\n')
try:
    if 'network_infrastructure' in json_response['data'][6]['attributes']:
        print('Web 7 results: \n')
        print(json_response['data'][6]['attributes']['network_infrastructure'])
    else:
        print('Web did not find any Network-specific IOC.\n')
except IndexError:
    print("Web didn't return any results. \n")

print('Casting Web 8...\n')
try:
    if 'network_infrastructure' in json_response['data'][7]['attributes']:
        print('Web 8 results: \n')
        print(json_response['data'][7]['attributes']['network_infrastructure'])
    else:
        print('Web did not find any Network-specific IOC.\n')
except IndexError:
    print("Web didn't return any results. \n")

print('Casting Web 9...\n')
try:
    if 'network_infrastructure' in json_response['data'][8]['attributes']:
        print('Web 9 results: \n')
        print(json_response['data'][8]['attributes']['network_infrastructure'])
    else:
        print('Web did not find any Network-specific IOC.\n')
except IndexError:
    print("Web didn't return any results. \n")

print('Casting Web 10...\n')
try:
    if 'network_infrastructure' in json_response['data'][9]['attributes']:
        print('Web 7 results: \n')
        print(json_response['data'][9]['attributes']['network_infrastructure'])
    else:
        print('Web did not find any Network-specific IOC.\n')
except IndexError:
    print("Web didn't return any results. \n")

f1=open("IOC-list.txt","r+")
input=f1.read()
input=input.replace(',','\n')
f2=open("IOC-list.txt","w+")
f2.write(input)
f1.close()
f2.close()

f1=open("IOC-list.txt","r+")
input=f1.read()
input=input.replace('[',' ')
f2=open("IOC-list.txt","w+")
f2.write(input)
f1.close()
f2.close()

f1=open("IOC-list.txt","r+")
input=f1.read()
input=input.replace(']','\n')
f2=open("IOC-list.txt","w+")
f2.write(input)
print(input)
f1.close()
f2.close()