#!/usr/bin/env python3
#
__author__ = "Vishal Thakur"
__copyright__ = "Copyright 2020, Vishal Thakur"
__license__ = "Apache2"
__version__ = "1.0"
__email__ = "vt@hack.sydney"
__status__ = "Prod"

import requests
import json

class ExecuteIP:
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

            relationship = 'communicating_files'
            url = "https://www.virustotal.com/api/v3/ip_addresses/" + ipAddress + '/' + relationship
            headers = {'x-apikey': apiKeyVT}
            params = {"limit": "10"}
            response = requests.get(url, headers=headers, params=params)
            json_response = response.json()

            # Start launching the webs
            print("Ragno is now casting 10 webs...\n")
            print("...wait for results.\n")

            for i in range(10):
                try:
                    if 'network_infrastructure' in json_response['data'][i]['attributes']:
                        web = json_response['data'][i]['attributes']['network_infrastructure']
                        print('Web ', i, ' : Success')
                        with open('IOC-list-communicating.txt', 'a+') as file:
                            json.dump(web, file)
                    else:
                        print('Web ', i, ' : No Results')
                except IndexError:
                    print('Web ', i, ' : No Results')
            # Fix the output file - re-format for easy-reading
            from ragno_ops_file import ExecuteFileOpsComm
            ExecuteFileOpsComm.formatList_1()
            ExecuteFileOpsComm.formatList_2()
            ExecuteFileOpsComm.formatList_3()
            # Menu options
            output_results = input(
                'Results from all webs have been writen to IOC-list-communicating.txt in working directory.\n Press 1 to print the results to console: \n Press 2 to return to Main Menu: \n Press 3 to Exit: \n\n')
            if output_results == '1':
                with open('IOC-list-communicating.txt', 'r') as IOC:
                    print(IOC.read())
                    from ragno import Main
                    Main.main_menu()
            elif output_results == '2':
                from ragno import Main
                Main.main_menu()
            elif output_results == '3':
                exit()
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
            print('Casting Webs...\n')
            for i in range(10):
                try:
                    if 'names' in json_response['data'][i]['attributes']:
                        web = json_response['data'][i]['attributes']['names']
                        print('Web ', i, ' : Success')
                        with open('IOC-list-downloaded.txt', 'a+') as file:
                            json.dump(web, file)
                    else:
                        print('Web ', i, ' : No Results')
                except IndexError:
                    print('Web ', i, ' : No Results')

            # Fix the output file - re-format for easy-reading
            from ragno_ops_file import ExecuteFileOpsDownld
            ExecuteFileOpsDownld.formatList_1()
            ExecuteFileOpsDownld.formatList_2()
            ExecuteFileOpsDownld.formatList_3()
            #Menu options
            output_results = input(
                'Results from all webs have been writen to IOC-list-downloaded.txt in working directory.\n Press 1 to print the results to console: \n Press 2 to return to Main Menu: \n Press 3 to Exit: \n\n')
            if output_results == '1':
                with open('IOC-list-downloaded.txt', 'r') as IOC:
                    print(IOC.read())
                    from ragno import Main
                    Main.main_menu()
            elif output_results == '2':
                from ragno import Main
                Main.main_menu()
            elif output_results == '3':
                exit()
            else:
                print('Invalid selection, exiting...')
                exit()
            return
        else:
            print('Invalid selection, please try again: \n')
            from ragno import Main
            Main.main_menu()
            return