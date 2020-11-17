#!/usr/bin/python
from __future__ import print_function

from time import gmtime, strftime, sleep
from bluepy.btle import Scanner, DefaultDelegate, BTLEException
import sys


class ScanDelegate(DefaultDelegate):

    def handle_discovery(self, dev, is_new_dev, is_new_data):
        print(strftime("%Y-%m-%d %H:%M:%S", gmtime()), dev.addr, dev.get_scan_data())
        sys.stdout.flush()

scanner = Scanner().with_delegate(ScanDelegate())

# listen for ADV_IND packages for 10s, then exit
scanner.scan(10.0, passive=True)
