#!/usr/bin/env python3
#
__author__ = "Vishal Thakur"
__copyright__ = "Copyright 2020, Vishal Thakur"
__license__ = "Apache2"
__version__ = "1.0"
__email__ = "vishal@mailfence.com"
__status__ = "Prod"

class ExecuteFileOpsComm():
    def createList():
        f = open("IOC-list-communicating.txt", "w")
        f.write('Ragno: Network IOC List. \n')
        f.close()
    def formatList_1():
        f1 = open("IOC-list-communicating.txt", "r+")
        input = f1.read()
        input = input.replace(',', '\n')
        f2 = open("IOC-list-communicating.txt", "w+")
        f2.write(input)
        f1.close()
        f2.close()
    def formatList_2():
        f1 = open("IOC-list-communicating.txt", "r+")
        input = f1.read()
        input = input.replace('[', ' ')
        f2 = open("IOC-list-communicating.txt", "w+")
        f2.write(input)
        f1.close()
        f2.close()
    def formatList_3():
        f1 = open("IOC-list-communicating.txt", "r+")
        input = f1.read()
        input = input.replace(']', '\n')
        f2 = open("IOC-list-communicating.txt", "w+")
        f2.write(input)
        f1.close()
        f2.close()
class ExecuteFileOpsDownld():
    def createList():
        f = open("IOC-list-downloaded.txt", "w")
        f.write('Ragno: Network IOC List. \n')
        f.close()
    def formatList_1():
        f1 = open("IOC-list-downloaded.txt", "r+")
        input = f1.read()
        input = input.replace(',', '\n')
        f2 = open("IOC-list-downloaded.txt", "w+")
        f2.write(input)
        f1.close()
        f2.close()
    def formatList_2():
        f1 = open("IOC-list-downloaded.txt", "r+")
        input = f1.read()
        input = input.replace('[', ' ')
        f2 = open("IOC-list-downloaded.txt", "w+")
        f2.write(input)
        f1.close()
        f2.close()
    def formatList_3():
        f1 = open("IOC-list-downloaded.txt", "r+")
        input = f1.read()
        input = input.replace(']', '\n')
        f2 = open("IOC-list-downloaded.txt", "w+")
        f2.write(input)
        f1.close()
        f2.close()