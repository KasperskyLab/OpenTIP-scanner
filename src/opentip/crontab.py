#!/usr/bin/env python3

# /etc/crontab

class CrontabScanner:
    def __init__(self, rootdir='/'):
        self.rootdir = rootdir

    def traverse(self):
        with open(self.rootdir + '/etc/crontab', 'rt') as f:
            for line in f:
                line = line.strip().rstrip()
                items = line.split('\t')
                print(f'{items}')

