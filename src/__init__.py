#!/usr/bin/python3
import nmap

class scanner(object):
    def __init__(self, hosts):
        self.nm = nmap.PortScanner()
        self._hosts_to_scan = hosts
    def check_all(self):
        results = self.nm.scan(hosts=self._hosts_to_scan, arguments='-sn -n')
        # -sn tells Nmap to ping without a port scan
        # -n tells Nmap not to reverse resolve the hostname
        #    We've already forward resolved it and it was causing confusion in cases of "music->192.168.10.97->media.lan"
        assert not 'error' in results['nmap']['scaninfo']
        self.last_results = results
        return int(results['nmap']['scanstats']['uphosts'])
    def active_hosts(self):
        return [host['hostname'] if host['hostname'] else host['addresses']['ipv4'] for host in self.last_results['scan'].values()]

if '__main__' == __name__:
    s = scanner('bellerophon persephone music 192.168.10.1')
    print('Number of active hosts:',s.check_all())
    print('Names:',s.active_hosts())
