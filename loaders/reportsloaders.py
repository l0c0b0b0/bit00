import os
import time


class DoReports:
    def __init__(self, module):
        self.module = module
        _path = Path(__file__).resolve().parent.parent
        self.path = _path / 'modules' / module / 'patterns.py'

    def do_osint_report():
        ...
    def do_netscan_report():
        ...


