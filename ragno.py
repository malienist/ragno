#!/usr/bin/env python3

import argparse
import configparser

import os
import json

import providers

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description = 'Look up indicators related to an IP address. Emits JSON')
    parser.add_argument('--apitoken', help='Virustotal API Key (alternatively, you can set $VT_API_KEY)')
    parser.add_argument('-f','--infile', help='Input file with newline delimited IP addresses')
    parser.add_argument('-o','--outfile', default = "results.json", help='Output file to write')
    parser.add_argument('-c','--config', default = "ragno.conf", help='Configuration file to use')
    parser.add_argument('ip_address_list', metavar = "ip_address", nargs = "*", default = [], help='An IP address to enrich')
    args = parser.parse_args()

    # obtain our apikey
    # note that the VT client library handles apikey validation so we don't do that here
    if os.path.isfile(args.config):
        myconf = configparser.ConfigParser()
        myconf.read(args.config)
        apitoken = myconf.get('virustotal', 'api_key_vt', fallback = "not_provided")
    else:
        apitoken = args.apitoken or os.environ.get('VT_API_KEY', "not_provided")

    # read input from cmdline or infile
    if not args.infile:
        ip_address_list = args.ip_address_list
    else:
        try:
            with open (args.infile) as fp:
                ip_address_list = fp.read().splitlines()
        except IOError:
            print ("ERROR: Could not read input file {}:".format(e))
            sys.exit(1)

    # enrich IPs with useful info
    full_results = []

    for ip_address in ip_address_list:
        print("Processing IP {}:".format(ip_address))
        full_results.append(providers.vt_iplookup(ip_address, apitoken) )

    # write out the results as json
    if full_results:
        try:
            with open(args.outfile, 'w+') as fp:
                json.dump(full_results, fp)
                print ("Wrote results to: {}".format(args.outfile))
        except IOError:
            print ("ERROR: Could not write input file {}:".format(outfile))
            sys.exit(1)
