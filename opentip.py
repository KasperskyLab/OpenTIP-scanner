#!/usr/bin/env python3
# © 2022 AO Kaspersky Lab. All Rights Reserved.
import hashlib, argparse, fnmatch, gettext, sys, os, time, urllib.request, urllib.error, asyncio, concurrent.futures, threading, json, logging
#from opentip import linux

version = 2
gettext.install('messages', os.path.dirname(os.path.realpath(__file__)) + '/locale')

# Provide the root directory, for remounted or remote system volumes
rootdir = os.getenv('OPENTIP_ROOTDIR', '/')

scanners = []
MAX_UPLOAD_SIZE = 10 * 1024*1024
upload_queue = []
frontend_url = 'https://opentip.kaspersky.com/api/v1/'

parser = argparse.ArgumentParser(description=_('Check files and directories with OpenTIP.kaspersky.com, optionally upload and scan unknown files'))
parser.add_argument('--no-upload', help=_('DO NOT upload unknown files to scan with the Sandbox, default behaviour is to upload'),action='store_true')
parser.add_argument('--exclude', help=_('Do not scan or upload the files matching the pattern'),type=str,action='append')
parser.add_argument('--log', help=_('Write results to the log file'),type=str)
parser.add_argument('--apikey', help=_('OpenTIP API key, received from https://opentip.kaspersky.com/token'),type=str,default='')
parser.add_argument('--quiet', help=_('Do not log clean files'),action='store_true')
parser.add_argument('path', help=_('File or directory location to scan'),nargs='+')

if len(sys.argv) < 2:
    parser.print_help()
    sys.exit(0)

args = parser.parse_args()

# Get your own API key at https://opentip.kaspersky.com/token
# It is required to get access to the service
APIKEY = os.getenv('OPENTIP_APIKEY', args.apikey)

if (args.path is None) or (len(args.path) == 0):
    parser.print_help()
    sys.exit(0)

if APIKEY == '':
    print(_('Please set the OPENTIP_APIKEY env variable or use --apikey. You can get a key at https://opentip.kaspersky.com/token'))
    sys.exit(2)

# Logging should be configured *before* threads are started
log_format='%(asctime)s %(message)s'
if args.log:
    logging.basicConfig(filename=args.log,format=log_format)
else:
    logging.basicConfig(stream=sys.stdout,format=log_format)

executor = concurrent.futures.ThreadPoolExecutor()
futures = []
stopping = threading.Event()

#if sys.platform.startswith('linux'):
#    scanners.append(linux.LinuxScanner(rootdir))
#elif sys.platform.startswith('darwin'):
#    raise RuntimeError('Mac is not supported')
#elif sys.platform.startswith('win32'):
#    raise RuntimeError('Windows is not supported')
#else:
#    raise RuntimeError(f'{sys.platform} is not supported')

def opentip_get(req:str):
    url = frontend_url + req
    req = urllib.request.Request(url)
    req.add_header('x-api-key', APIKEY)
    with urllib.request.urlopen(req) as f:
        data = f.read().decode('utf-8')
    return data

def opentip_post(req:str,data):
    url = frontend_url + req
    req = urllib.request.Request(url,method='POST',data=data)
    req.add_header('x-api-key', APIKEY)
    req.add_header('Content-Type', 'application/octet-stream')
    with urllib.request.urlopen(req) as f:
        data = f.read().decode('utf-8')
    return data

def scan_file(filename):
    if stopping.is_set():
        return
    # print(f'{filename}')
    # First, check for exclusions
    if args.exclude is not None:
        for pattern in args.exclude:
            if fnmatch.fnmatch(filename, pattern):
                return (filename, 'excluded')

    # Now, hash the contents of the file
    h = hashlib.new('sha256')
    buf = b''
    try:
        with open(filename, 'rb') as f:
            while True:
                new_buf = f.read(MAX_UPLOAD_SIZE)
                if len(new_buf) == 0:
                    break
                buf = new_buf
                h.update(buf)
    except PermissionError as e:
        return (filename, 'denied')
    except OSError as e:
        return (filename, 'OS error')

    sha = h.hexdigest()
    # Search by hash
    try:
        res = opentip_get('search/hash?request=' + sha)
    except urllib.error.HTTPError as e:
        if e.code == 400: # Unknown file
            # Upload the file for analysis
            file_size = os.path.getsize(filename)
            if args.no_upload or ( file_size > MAX_UPLOAD_SIZE or file_size == 0 ):
                return (filename, None)
            else:
                try:
                    res = opentip_post('scan/file?filename=' + sha, buf)
                    if len(res) == 0:
                        stopping.set()
                        raise RuntimeError(filename)
                    else:
                        return (filename, res)

                except urllib.error.HTTPError as e:
                    logging.error(_('Error uploading %s') % filename)
                    stopping.set()
                    raise e
        else:
            stopping.set()
            raise e
    return (filename, res)
    
def scan_file_wrapper(filename):
    futures.append(executor.submit(scan_file, filename))

def scan_dir(path):
    result = []
    for dirpath, dirnames, filenames in os.walk(path):
        for fname in filenames:
            if stopping.is_set():
                return
            scan_file_wrapper(os.path.join(dirpath, fname))

def scan_path_async(path):
    if os.path.isdir(path):
        scan_dir(path)
    elif os.path.isfile(path):
        scan_file_wrapper(path)

def main():
    ret = 0

    try:
        for path in args.path:
            scan_path_async(path)

        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            if not res is None:
                filename = res[0]
                loud_verdict = None
                if res[1] is None:
                    verdict = 'skipped'
                else:
                    try:
                        data = json.loads(res[1])
                        verdict = data['FileGeneralInfo']['FileStatus']
                        if verdict != 'Clean' and verdict != 'NotCategorized' and verdict != 'NoThreats':
                            loud_verdict = True
                            ret = 3
                            if 'DetectionsInfo' in data:
                                verdict += ': ' + ','.join(item['DetectionName'] for item in data['DetectionsInfo'])
                    except json.decoder.JSONDecodeError as e:
                        verdict = res[1]
                        loud_verdict = True
                if not args.quiet or loud_verdict:
                    logging.warning(f'{filename}: {verdict}')
    except urllib.error.HTTPError as e:
        if e.code == 403:
            logging.error(_('Received "Forbidden", please use another API key or try again later'))
            ret = 2
        else:
            raise 

    stopping.set()
    executor.shutdown()
    sys.exit(ret)

if __name__ == '__main__':
    main()

