#!/usr/bin/env python3
#
__author__ = "Vishal Thakur"
__copyright__ = "Copyright 2020, Vishal Thakur"
__license__ = "Apache2"
__version__ = "1.0"
__email__ = "vishal@mailfence.com"
__status__ = "Prod"

def main_menu():
    ragno_start=input(' Please select from the following options: \n\n'
                      ' Press 1 to look up a single IOC: \n'
                      ' Press 2 for bulk lookup: \n')
    if ragno_start=='1':
        from config_reader import ReadConfig
        ReadConfig.read_api_keys()
        from config_reader import apiKeyVT
        global apiKeyVT
        from config_reader import ValidateAPI
        ValidateAPI.chk_api_keys_vt()

        ragno_single=input(' Please select from the following options: \n\n'
                           ' Press 1 for IP: \n'
                           ' Press 2 for Domain: \n'
                           ' Press 3 for Hash (md5, sha1, sha256): \n')
        if ragno_single=='1':
            from ragno_mod_vt import ExecuteVT
            ExecuteVT.ioc_ip_single()

        else:
            print("Invalid selection, starting again.")
        main_menu()

main_menu()
