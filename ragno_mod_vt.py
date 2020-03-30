#!/usr/bin/env python3
#
__author__ = "Vishal Thakur"
__copyright__ = "Copyright 2020, Vishal Thakur"
__license__ = "Apache2"
__version__ = "1.0"
__email__ = "vishal@mailfence.com"
__status__ = "Prod"

import requests
import json
class ExecuteVT:
    from config_reader import apiKeyVT
    global apiKeyVT
    def ioc_ip_single():
        ipAddress=input('Please provide IP for lookup: \n\n')
        querystring = '?limit=1'
        relationship = input('Please select one option: \n\n'
                        'Press 1 for Communicating Files: \n'
                        'Press 2 for Downloaded Files: \n')
        if relationship=='1':
            relationship='communicating_files'
        else:
            relationship='downloaded_files'
            return

        url = "https://www.virustotal.com/api/v3/ip_addresses/" + ipAddress + '/' + relationship

        headers = {'x-apikey': apiKeyVT}
        params = {"limit":"2"}
        response = requests.get(url, headers=headers, params=params)
        json_response = response.json()
        if 'data' in json_response:
            print (json_response['data'] [0] ['attributes'] ['network_infrastructure'])
            print (json_response['data'] [1] ['attributes'] ['network_infrastructure'])
        return
