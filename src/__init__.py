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
            errors = set('\n'.join(results['nmap']['scaninfo']['error']).split('\n'))
            # The Nmap library seems to try and split errors by line into a list,
            # but it also seems to be failing some times, so I'm undoing that and doing it myself.
            print(' '.join(errors),end=': ')
            for err in errors:
                if err.startswith('Failed to resolve') or '' == err:
                     pass
                elif "WARNING: No targets were specified, so 0 hosts scanned." == err:
                     # Nmap gives this response when it fails to resolve all the supplied DNS names.
                     # This is not a problem and really just means none of the devices are on the network.
                     return []
                else:
                     raise NmapError(err)
        return [host['hostname'] if host['hostname'] else host['addresses']['ipv4'] for host in self.last_results['scan'].values()]

if '__main__' == __name__:
    import time
    import sys
    s = scanner(sys.argv[1])
    with open('output.log', 'w') as f:
        while True:
            result = s.check_all()
            string = ' '.join([time.asctime(), 'found', str(len(result)), 'active hosts:', str(result)])
            f.write(string+'\n')
            print(string)
            if not result:
                time.sleep(60)
            else:
                time.sleep(300) # 5 minutes
