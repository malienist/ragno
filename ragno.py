#!/usr/bin/env python3
#
__author__ = "Vishal Thakur"
__copyright__ = "Copyright 2020, Vishal Thakur"
__license__ = "Apache2"
__version__ = "1.0"
__email__ = "vishal@mailfence.com"
__status__ = "Prod"
class Main():
    def main_menu():
        from ragno_mod_vt import ExecuteVT
        ExecuteVT.ioc_ip_single()
        return
print('Welcome to Ragno IOC multiplier!\n\n')
from config_reader import ReadConfig
ReadConfig.read_api_keys()
from config_reader import apiKeyVT
global apiKeyVT
from config_reader import ValidateAPI
ValidateAPI.chk_api_keys_vt()

Main.main_menu()
