#!/usr/bin/python3
import nmap
from pprint import pprint

class NmapError(nmap.PortScannerError):
    pass

class scanner(object):
    def __init__(self, hosts):
        self.nm = nmap.PortScanner()
        self._hosts_to_scan = hosts
    def check_all(self):
        results = self.nm.scan(hosts=self._hosts_to_scan, arguments='--initial-rtt-timeout=5 --max-rtt-timeout=10 -sn -n')
	# Timeout changes are required because Android has some funcky battery saving techniques that make it really slow with responding to ping.
        # -sn tells Nmap to ping without a port scan
        # -n tells Nmap not to reverse resolve the hostname
        #    We've already forward resolved it and it was causing confusion in cases of "music->192.168.10.97->media.lan"
        if 'error' in results['nmap']['scaninfo']:
            errors = '\n'.join(results['nmap']['scaninfo']['error']).split('\n')
            # The Nmap library seems to try and split errors by line into a list,
            # but it also seems to be failing some times, so I'm undoing that and doing it myself.
            for err in errors:
                if not err.startswith('Failed to resolve') and not '' == err:
                     raise NmapError(errors)
        self.last_results = results
        return int(results['nmap']['scanstats']['uphosts'])
    def active_hosts(self):
        return [host['hostname'] if host['hostname'] else host['addresses']['ipv4'] for host in self.last_results['scan'].values()]

if '__main__' == __name__:
    import time
    import sys
    s = scanner(sys.argv[1])
    with open('output.log', 'w') as f:
        while True:
            string = ' '.join([time.asctime(), 'found', str(s.check_all()), 'active hosts:', str(s.active_hosts())])
            f.write(string+'\n')
            print(string)
            time.sleep(300) # 5 minutes
