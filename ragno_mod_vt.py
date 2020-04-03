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
import time
class ExecuteVT:
    from config_reader import apiKeyVT
    global apiKeyVT
    def ioc_ip_single():
        ipAddress=input('Please provide IP for lookup: \n\n')
        relationship = input('Please select one option: \n\n'
                             ' Press 1 for Communicating Files: \n'
                             ' Press 2 for Downloaded Files: \n')

        if relationship == '1':
            # Create the ioc-list file
            from ragno_ops_file import ExecuteFileOpsComm
            ExecuteFileOpsComm.createList()

            relationship='communicating_files'
            url = "https://www.virustotal.com/api/v3/ip_addresses/" + ipAddress + '/' + relationship
            headers = {'x-apikey': apiKeyVT}
            params = {"limit": "10"}
            response = requests.get(url, headers=headers, params=params)
            json_response = response.json()

            # Start launching the webs
            print("Ragno is now casting 10 webs...\n")
            print("...wait for results.\n")
            time.sleep(1)

            print('Casting Web 1...\n')
            try:
                if 'network_infrastructure' in json_response['data'][0]['attributes']:
                    web = json_response['data'][0]['attributes']['network_infrastructure']
                    print('Web 1 results: \n')
                    print(json_response['data'][0]['attributes']['network_infrastructure'])
                    with open('IOC-list-communicating.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            print('Casting Web 2...\n')
            try:
                if 'network_infrastructure' in json_response['data'][1]['attributes']:
                    web = json_response['data'][1]['attributes']['network_infrastructure']
                    print('Web 2 results: \n')
                    print(json_response['data'][1]['attributes']['network_infrastructure'])
                    with open('IOC-list-communicating.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            print('Casting Web 3...\n')
            try:
                if 'network_infrastructure' in json_response['data'][2]['attributes']:
                    web = json_response['data'][2]['attributes']['network_infrastructure']
                    print('Web 3 results: \n')
                    print(json_response['data'][2]['attributes']['network_infrastructure'])
                    with open('IOC-list-communicating.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            print('Casting Web 4...\n')
            try:
                if 'network_infrastructure' in json_response['data'][3]['attributes']:
                    web = json_response['data'][3]['attributes']['network_infrastructure']
                    print('Web 4 results: \n')
                    print(json_response['data'][3]['attributes']['network_infrastructure'])
                    with open('IOC-list-communicating.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            print('Casting Web 5...\n')
            try:
                if 'network_infrastructure' in json_response['data'][4]['attributes']:
                    web = json_response['data'][4]['attributes']['network_infrastructure']
                    print('Web 5 results: \n')
                    print(json_response['data'][4]['attributes']['network_infrastructure'])
                    with open('IOC-list-communicating.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            print('Casting Web 6...\n')
            try:
                if 'network_infrastructure' in json_response['data'][5]['attributes']:
                    web = json_response['data'][5]['attributes']['network_infrastructure']
                    print('Web 6 results: \n')
                    print(json_response['data'][5]['attributes']['network_infrastructure'])
                    with open('IOC-list-communicating.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            print('Casting Web 7...\n')
            try:
                if 'network_infrastructure' in json_response['data'][6]['attributes']:
                    web = json_response['data'][6]['attributes']['network_infrastructure']
                    print('Web 7 results: \n')
                    print(json_response['data'][6]['attributes']['network_infrastructure'])
                    with open('IOC-list-communicating.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            print('Casting Web 8...\n')
            try:
                if 'network_infrastructure' in json_response['data'][7]['attributes']:
                    web = json_response['data'][7]['attributes']['network_infrastructure']
                    print('Web 8 results: \n')
                    print(json_response['data'][7]['attributes']['network_infrastructure'])
                    with open('IOC-list-communicating.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            print('Casting Web 9...\n')
            try:
                if 'network_infrastructure' in json_response['data'][8]['attributes']:
                    web = json_response['data'][8]['attributes']['network_infrastructure']
                    print('Web 9 results: \n')
                    print(json_response['data'][8]['attributes']['network_infrastructure'])
                    with open('IOC-list-communicating.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            print('Casting Web 10...\n')
            try:
                if 'network_infrastructure' in json_response['data'][9]['attributes']:
                    web = json_response['data'][9]['attributes']['network_infrastructure']
                    print('Web 10 results: \n')
                    print(json_response['data'][9]['attributes']['network_infrastructure'])
                    with open('IOC-list-communicating.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            # Fix the output file - re-format for easy-reading
            from ragno_ops_file import ExecuteFileOpsComm
            ExecuteFileOpsComm.formatList_1()
            ExecuteFileOpsComm.formatList_2()
            ExecuteFileOpsComm.formatList_3()

            output_results = input(
                'Results from all webs have been writen to IOC-list-communicating.txt in working directory.\n Press 1 to print the results to console: \n Press 2 to return to Main Menu: \n\n')
            if output_results == '1':
                with open('IOC-list-communicating.txt', 'r') as IOC:
                    print(IOC.read())
                    from ragno import Main
                    Main.main_menu()
            elif output_results == '2':
                from ragno import Main
                Main.main_menu()
            else:
                print('Invalid selection, exiting...')
                exit()
            return
        elif relationship =='2':
            relationship='downloaded_files'
            url = "https://www.virustotal.com/api/v3/ip_addresses/" + ipAddress + '/' + relationship

            headers = {'x-apikey': apiKeyVT}
            params = {"limit": "10"}
            response = requests.get(url, headers=headers, params=params)
            json_response = response.json()

            # Create the ioc-list file
            from ragno_ops_file import ExecuteFileOpsDownld
            ExecuteFileOpsDownld.createList()
            # Start the function
            print("Ragno is now casting 10 webs...\n")
            print("...wait for results.\n")
            time.sleep(1)

            print('Casting Web 1...\n')
            try:
                if 'names' in json_response['data'][0]['attributes']:
                    web = json_response['data'][0]['attributes']['names']
                    print('Web 1 results: \n')
                    print(json_response['data'][0]['attributes']['names'])
                    with open('IOC-list-downloaded.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            print('Casting Web 2...\n')
            try:
                if 'network_infrastructure' in json_response['data'][1]['attributes']:
                    web = json_response['data'][1]['attributes']['network_infrastructure']
                    print('Web 2 results: \n')
                    print(json_response['data'][1]['attributes']['network_infrastructure'])
                    with open('IOC-list-downloaded.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            print('Casting Web 3...\n')
            try:
                if 'network_infrastructure' in json_response['data'][2]['attributes']:
                    web = json_response['data'][2]['attributes']['network_infrastructure']
                    print('Web 3 results: \n')
                    print(json_response['data'][2]['attributes']['network_infrastructure'])
                    with open('IOC-list-downloaded.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            print('Casting Web 4...\n')
            try:
                if 'network_infrastructure' in json_response['data'][3]['attributes']:
                    web = json_response['data'][3]['attributes']['network_infrastructure']
                    print('Web 4 results: \n')
                    print(json_response['data'][3]['attributes']['network_infrastructure'])
                    with open('IOC-list-downloaded.txt', 'a+') as file:
                        json.dump(web_2, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            print('Casting Web 5...\n')
            try:
                if 'network_infrastructure' in json_response['data'][4]['attributes']:
                    web = json_response['data'][4]['attributes']['network_infrastructure']
                    print('Web 5 results: \n')
                    print(json_response['data'][4]['attributes']['network_infrastructure'])
                    with open('IOC-list-downloaded.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            print('Casting Web 6...\n')
            try:
                if 'network_infrastructure' in json_response['data'][5]['attributes']:
                    web = json_response['data'][5]['attributes']['network_infrastructure']
                    print('Web 6 results: \n')
                    print(json_response['data'][5]['attributes']['network_infrastructure'])
                    with open('IOC-list-downloaded.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            print('Casting Web 7...\n')
            try:
                if 'network_infrastructure' in json_response['data'][6]['attributes']:
                    web = json_response['data'][6]['attributes']['network_infrastructure']
                    print('Web 7 results: \n')
                    print(json_response['data'][6]['attributes']['network_infrastructure'])
                    with open('IOC-list-downloaded.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            print('Casting Web 8...\n')
            try:
                if 'network_infrastructure' in json_response['data'][7]['attributes']:
                    web = json_response['data'][7]['attributes']['network_infrastructure']
                    print('Web 8 results: \n')
                    print(json_response['data'][7]['attributes']['network_infrastructure'])
                    with open('IOC-list-downloaded.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            print('Casting Web 9...\n')
            try:
                if 'network_infrastructure' in json_response['data'][8]['attributes']:
                    web = json_response['data'][8]['attributes']['network_infrastructure']
                    print('Web 9 results: \n')
                    print(json_response['data'][8]['attributes']['network_infrastructure'])
                    with open('IOC-list-downloaded.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            print('Casting Web 10...\n')
            try:
                if 'network_infrastructure' in json_response['data'][9]['attributes']:
                    web = json_response['data'][9]['attributes']['network_infrastructure']
                    print('Web 7 results: \n')
                    print(json_response['data'][9]['attributes']['network_infrastructure'])
                    with open('IOC-list-downloaded.txt', 'a+') as file:
                        json.dump(web, file)
                else:
                    print('Web did not find any Network-specific IOC.\n')
            except IndexError:
                print("Web didn't return any results. \n")

            # Fix the output file - re-format for easy-reading
            from ragno_ops_file import ExecuteFileOpsDownld
            ExecuteFileOpsDownld.formatList_1()
            ExecuteFileOpsDownld.formatList_2()
            ExecuteFileOpsDownld.formatList_3()

            output_results = input(
                'Results from all webs have been writen to IOC-list-downloaded.txt in working directory.\n Press 1 to print the results to console: \n Press 2 to return to Main Menu: \n\n')
            if output_results == '1':
                with open('IOC-list-downloaded.txt', 'r') as IOC:
                    print(IOC.read())
            elif output_results == '2':
                from ragno import Main
                Main.main_menu()
            else:
                print('Invalid selection, exiting...')
                exit()
            return
        else:
            print('Invalid selection, please try again: \n')
            from ragno import Main
            Main.main_menu()
            return






