## OpenTIP scanner

The script is a Python 3 client to the [OpenTIP service](https://opentip.kaspersky.com).

It can scan files and directories and provide the verdict (clean, malware, adware). For unknown files, it will also upload them to the service for scanning and Sandbox processing (optional).

To run the script, you need to obtain a valid API key from [OpenTIP](https://opentip.kaspersky.com/token) and set it with the --apikey command line switch or the OPENTIP\_APIKEY environment variable.

## Installation

The script uses only the standard Python 3 library, so just copy all the files and run opentip.py.

## Command line switches

```
usage: opentip.py [-h] [--no-upload] [--exclude EXCLUDE] [--log LOG] [--apikey APIKEY] [--quiet] path [path ...]

Check files and directories with OpenTIP.kaspersky.com, optionally upload and scan unknown files

positional arguments:
  path               File or directory location to scan

optional arguments:
  -h, --help         show this help message and exit
  --no-upload        DO NOT upload unknown files to scan with the Sandbox, default behaviour is to upload
  --exclude EXCLUDE  Do not scan or upload the files matching the pattern
  --log LOG          Write results to the log file
  --apikey APIKEY    OpenTIP API key, received from https://opentip.kaspersky.com/token
  --quiet            Do not log clean files
```
