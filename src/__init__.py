#!/usr/bin/python3
import nmap
import sys
import time
from pprint import pprint

class NmapError(nmap.PortScannerError):
    pass

class scanner(object):
    def __init__(self, hosts):
        self.nm = nmap.PortScanner()
        self._hosts_to_scan = hosts
    def check_all(self):
        nohosts = False
        results = self.nm.scan(hosts=self._hosts_to_scan, arguments='--initial-rtt-timeout=9000ms --max-rtt-timeout=10000ms -sn -n')
	# Timeout changes are required because Android has some funcky battery saving techniques that make it really slow with responding to ping.
        # Mike's phone (santo) seems to have the strongest battery saving of upwards of 5000ms, max from any other device is ~3500
        # I don't care about the max being higher than the initial as the logic nmap uses to figure what in that range to use is how congested the network is,
        # whereas the slowdown in this case has nothing to do with network congestion and is in fact so slow network congestion won't slow it down significantly
        # -sn tells Nmap to ping without a port scan
        # -n tells Nmap not to reverse resolve the hostname
        #    We've already forward resolved it and it was causing confusion in cases of "music->192.168.10.97->media.lan"
        if 'error' in results['nmap']['scaninfo']:
            errors = set('\n'.join(results['nmap']['scaninfo']['error']).split('\n'))
            # The Nmap library seems to try and split errors by line into a list,
            # but it also seems to be failing some times, so I'm undoing that and doing it myself.
            for err in errors:
                if err.startswith('Failed to resolve') or '' == err:
                    # Failing to resolve a hostname should count as an inactive host.
                    # We could avoid this workaround if we hardcode the hostnames in our DNS server,
                    # but instead I'm relying on dnsmasq automatically configuring DNS from DHCP info
                    pass
                elif "WARNING: No targets were specified, so 0 hosts scanned." == err:
                    # Nmap gives this response when it fails to resolve all the supplied DNS names.
                    # This is not a problem and really just means none of the devices are on the network.
                    nohosts = True
                else:
                    sys.stderr.write(err+'\n')
                    sys.stderr.flush()
                # FIXME: Handle "RTTVAR has grown to over 2.3 seconds, decreasing to 2.0" ?
        if nohosts == True:
            return []
        assert 'scan' in results
        return [host['hostname'] if host['hostname'] else host['addresses']['ipv4'] for host in results['scan'].values()]

if '__main__' == __name__:
    prev_result = []
    s = scanner(' '.join(sys.argv[1:]))
    with open('output.log', 'w') as f:
        while True:
            result = s.check_all()
            string = ' '.join([time.asctime(), 'found', str(len(result)), 'active hosts:', str(result)])
            f.write(string+'\n')
            print(string)

            if 'santo' not in prev_result and 'santo' in result:
                print("Welcome home!")
            elif 'santo' in prev_result and 'santo' not in result:
                print("OK, bye.")

            prev_result = result
            if not result:
                time.sleep(60)
            else:
                time.sleep(300) # 5 minutes
