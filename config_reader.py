#!/usr/bin/env python3
#
__author__ = "Vishal Thakur"
__copyright__ = "Copyright 2020, Vishal Thakur"
__license__ = "Apache2"
__version__ = "1.0"
__email__ = "vishal@mailfence.com"
__status__ = "Prod"

import time
import requests
try:
    import ConfigParser
except:
    import configparser as ConfigParser

class ReadConfig:

    def read_api_keys():
        global apiKeyVT
        config = ConfigParser.RawConfigParser()
        config.read("./ragno.conf")
        try:
            api_key_vt = config.get('virustotal', 'api_key_vt')
            apiKeyVT = api_key_vt
            return
        except ConfigParser.NoOptionError:
            print('Could not read configuration file.')
            exit(1)

ReadConfig.read_api_keys()
global apiKeyVT
class ValidateAPI:
    def chk_api_keys_vt():
        #Check VT API key
        print('\n Validating VirusTotal API Key --->')
        headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent": "gzip,  Fneicken request for malware information"
        }
        # Import the API key that is saved as a variable from the config file and the file hash into a new function.
        params = {'apikey': apiKeyVT, 'resource': 'https://virustotal.com'}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
        if 200 <= response.status_code <= 299:
            print('\n   API Key is Valid!\n')
        else:
            print("VT API Key is not valid, please fix this issue and retry.\n")
            print('Thanks for using Ragno. Exiting...')
            time.sleep(1)
            exit()
