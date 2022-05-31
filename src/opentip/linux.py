#!/usr/bin/env python3

# Linux startup enumerator

from . import crontab

class LinuxScanner:
    def __init__(self, rootdir='/'):
        self.rootdir = rootdir
        self.scanners = [ crontab.CrontabScanner(rootdir) ]

    def traverse(self):
        for scanner in self.scanners:
            scanner.traverse()


