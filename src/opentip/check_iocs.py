#!/usr/bin/env python3

from opentip.client import OpenTIP
import os, sys, argparse, logging, concurrent.futures, threading, json

def check_ioc(client,ioc_type:str,ioc:str):
    url = f'https://opentip.kaspersky.com/api/v1/search/{ioc_type.lower()}?request={ioc.lower()}'
    res = { 'IOC' : ioc, 'Type' : ioc_type, 'URL': url }
    try:
        v = client.get_verdict_by_ioc(ioc_type, ioc)
        if v is not None:
            parsed = json.loads(v)
            res['Data'] = parsed
    except:
        res['Error'] = True
    return res

def main():
    parser = argparse.ArgumentParser(description='Check IOCS (file hashes, IP addresses, domain names, URLs using the service OpenTIP.kaspersky.com')
    parser.add_argument('type', default='', type=str, help='hash, ip, domain, url')
    parser.add_argument('value', default='', type=str, help='Value of the IOC (hash, ip, domain, url, filename with the iocs)')
    parser.add_argument('--apikey', help='OpenTIP API key, received from https://opentip.kaspersky.com/token',type=str,default='')
    parser.add_argument('--out', '-o', type=str, help="Write output as JSON to this filename")

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()
    APIKEY = os.getenv('OPENTIP_APIKEY', args.apikey)

    if APIKEY == '':
        print(_('Please set the OPENTIP_APIKEY env variable or use --apikey. You can get a key at https://opentip.kaspersky.com/token'))
        sys.exit(2)

    fname = os.path.join(os.getcwd(), args.value)
    if os.path.isfile(fname):
        with open(fname, 'rt') as f:
            iocs = f.read().splitlines()
    else:
        iocs = [args.value]

    client = OpenTIP(APIKEY)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        stopping = threading.Event()
        for ioc in iocs:
            futures.append(executor.submit(check_ioc, client, args.type, ioc))
        results = []
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())
        if args.out:
            with open(args.out, 'wt') as f:
                json.dump(results, f, indent=4)
        else:
            for res in results:
                if 'Error' in res:
                    print(f'[ERROR]: {res["IOC"]}')
                elif 'Data' in res:
                    print(f'[IOC]: {res["IOC"]} : {res["Data"]}')
                else:
                    print(f'[IOC]: {res["IOC"]} : Unknown')
if __name__ == '__main__':
    main()
