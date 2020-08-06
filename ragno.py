#!/usr/bin/env python3
#
__author__ = "Vishal Thakur"
__copyright__ = "Copyright 2020, Vishal Thakur"
__license__ = "Apache2"
__version__ = "1.0"
__email__ = "vt@hack.sydney"
__status__ = "Prod"
class Main():
    def main_menu():
        execute_attr = input('Please select an option: \n\n'
                             'Press x to validate API Key: \n'
                             'Press 1 for IP lookup: \n'
                             'Press 2 for File Hash lookup: \n'
                             'Press 3 to Exit: \n')
        if execute_attr == '1':
            from ragno_mod_vt_ip import ExecuteIP
            ExecuteIP.ioc_ip_single()
            return
        elif execute_attr == '2':
            execute_attr_file = input('Please select an option: \n\n'
                                      'For C2 Information for the campaign (based on files similar to the one submitted), press 1: \n'
                                      'For Dynamic IOC from the file submitted, press 2: \n')
            if execute_attr_file == '1':
                from ragno_mod_vt_hash import ExecuteFileC2Infra
                ExecuteFileC2Infra.ioc_file_C2()
                return
            elif execute_attr_file == '2':
                from ragno_mod_vt_hash import ExecuteFileMultiAttr
                ExecuteFileMultiAttr.ioc_file()
                return
        elif execute_attr == '3':
            exit()
        elif execute_attr == 'x':
            from config_reader import ReadConfig
            ReadConfig.read_api_keys()
            from config_reader import apiKeyVT
            global apiKeyVT
            from config_reader import ValidateAPI
            ValidateAPI.chk_api_keys_vt()
            Main.main_menu()
        else:
            print("Invalid Selection, try again.")
            return
Main.main_menu()
