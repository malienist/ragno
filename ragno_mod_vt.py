#!/usr/bin/env python3
#
__author__ = "Vishal Thakur"
__copyright__ = "Copyright 2020, Vishal Thakur"
__license__ = "Apache2"
__version__ = "1.0"
__email__ = "vishal@mailfence.com"
__status__ = "Prod"

import vt

class ExecuteVT:
    from config_reader import apiKeyVT
    global apiKeyVT
    def ioc_ip_single():
        ipAddress=input('Please provide IP for lookup: \n\n')
        choice = input('Please select one option: \n\n'
                             ' Press 1 for Communicating Files: \n'
                             ' Press 2 for Downloaded Files: \n')

        if choice is '1':
            print("Ragno is now casting webs, please wait for results...")
            # Create the ioc-list file
            from ragno_ops_file import ExecuteFileOpsComm
            ExecuteFileOpsComm.createList()

            # Get all malware binaries that were observed communicating with this IP
            response = {}
            try:
                with vt.Client(apiKeyVT) as client:
                    response = client.get_json('/ip_addresses/{}/communicating_files', ipAddress)

            except vt.APIError as e:
                print ("ERROR: Problem contacting VT API: {}".format(e))

            # Iterate other hosts that those binaries communicated with
            # note that each binary may be associated with 0..n hosts

            if response:
                related_hosts = set()
                try:
                    for item in response['data']:
                        # add and dedupe the set of related hosts
                        host_list = item['attributes'].get('network_infrastructure')
                        if host_list:
                            related_hosts.update( host_list )

                except KeyError as e:
                    print ("ERROR: Malformed JSON response from VT")

                with open('IOC-list-communicating.txt', 'a+') as file:
                    file.write("\n".join(related_hosts) )


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

        elif choice is '2':
            # Create the ioc-list file
            from ragno_ops_file import ExecuteFileOpsDownld
            ExecuteFileOpsDownld.createList()

            print("Ragno is now casting webs, please wait for results...")

            # iterate over each malware binary that was observed downloaded from this IP
            response = {}
            try:
                with vt.Client(apiKeyVT) as client:
                    response = client.get_json('/ip_addresses/{}/downloaded_files', ipAddress)

            except vt.APIError as e:
                print ("ERROR: Problem contacting VT API: {}".format(e))


            # dedupe the set of malware binary filenames
            if response:
                related_filenames = set()
                try:
                    for item in response['data']:

                        filename_list = item['attributes'].get('names')
                        if filename_list:
                            related_filenames.update( filename_list )

                except KeyError as e:
                    print ("ERROR: Malformed JSON response from VT")

                with open('IOC-list-downloaded.txt', 'a+') as file:
                    file.write("\n".join(related_filenames) )

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
