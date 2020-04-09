import vt
import sys

def vt_iplookup( ip_address, api_key_vt):

    # we use a set object to de-duplicate results
    enriched_results = {
        'ip_address': ip_address,
        'related_hosts': set(),
        'related_filenames': set()
    }

    print("Getting related network hosts...")

    # Get all malware binaries that were observed communicating with this IP
    response = {}
    try:
        with vt.Client(api_key_vt) as client:
            response = client.get_json('/ip_addresses/{}/communicating_files', ip_address)

    except vt.APIError as e:
        error_type, _ = e.args

        if error_type == 'ClientError':
            print ("ERROR: Item does not appear to be an IP address: {}".format(ip_address))
            sys.exit(1)
        elif error_type == 'WrongCredentialsError':
            print ("ERROR: Provided VT apikey is invalid: {}".format(api_key_vt))
            sys.exit(1)


    # Iterate other hosts that those binaries communicated with
    # note that each binary may be associated with 0..n hosts

    if response:
        try:
            for item in response['data']:

                host_list = item['attributes'].get('network_infrastructure')
                if host_list:
                    enriched_results['related_hosts'].update( host_list )

        except KeyError as e:
            print ("WARN: Malformed JSON response from VT: {}".format(e))

    print("Getting related malware binary filenames...")

    # iterate over each malware binary that was observed downloaded from this IP
    response = {}
    try:
        with vt.Client(api_key_vt) as client:
            response = client.get_json('/ip_addresses/{}/downloaded_files', ip_address)

    except vt.APIError as e:
        error_type, _ = e.args

        if error_type == 'ClientError':
            print ("ERROR: Item does not appear to be an IP address: {}".format(ip_address))
            sys.exit(1)
        elif error_type == 'WrongCredentialsError':
            print ("ERROR: Provided VT apikey is invalid: {}".format(api_key_vt))
            sys.exit(1)

    if response:
        try:
            for item in response['data']:
                # add and dedupe the set of malware binary filenames
                filename_list = item['attributes'].get('names')
                if filename_list:
                    enriched_results['related_filenames'].update( filename_list )
        except KeyError as e:
            print ("WARN: Malformed JSON response from VT: {}".format(e))

    # convert set objects to lists so we can serialize them to json
    for item in ['related_hosts', 'related_filenames']:
        enriched_results[item] = list(enriched_results[item])

    return enriched_results
