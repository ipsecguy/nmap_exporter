#!/usr/bin/env python
# -*- coding: utf-8 -*-

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException


# start a new nmap scan on localhost with some specific options
def do_scan(targets, options):
    parsed = None
    nmproc = NmapProcess(targets, options)

    rc = nmproc.run()
    if rc != 0:
        print("nmap scan failed: {0}".format(nmproc.stderr))

    print("nmap_process_command{{version=\"{0}\",targets=\"{1}\",cmdline=\"{2}\"}} {3}".format(
        nmproc.version,
        nmproc.targets,
        format(nmproc.command.strip()),
        nmproc.starttime))

    try:
        parsed = NmapParser.parse(nmproc.stdout)
    except NmapParserException as e:
        print("Exception raised while parsing scan: {0}".format(e.msg))

    return parsed

# print scan results from a nmap report
def print_scan(nmap_report):
    print("nmap_report_starttime{{version=\"{0}\"}} {1}".format(nmap_report.version,nmap_report.started))

    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address

        print("nmap_host{{hostname=\"{0}\",ipv4address=\"{1}\",ipv6address=\"{2}\",macaddress=\"{3}\",macvendor=\"{4}\",status=\"{5}\",distance=\"{6}\"}} {7}".format(
            tmp_host,
            host.ipv4, host.ipv6, host.mac, host.vendor,
            host.status,
            host.distance,
            1 if host.status == "up" else 0))

        for serv in host.services:
            print("nmap_service{{hostname=\"{0}\",ipv4address=\"{1}\",port=\"{2}\",service=\"{3}\",protocol=\"{4}\",state=\"{5}\"}} {6}".format(
                tmp_host,
                host.address,
                serv.port,
                serv.service,
                serv.protocol,
                serv.state,
                1 if serv.state == "open" else 0))

#    print("nmap_report_endtime(summary=\"{0}\") {1}".format(nmap_report.summary,nmap_report.endtime))
    print("nmap_report_endtime {0}".format(nmap_report.endtime))
    print("nmap_report_hosts_total_count {0}".format(nmap_report.hosts_total))
    print("nmap_report_hosts_up_count {0}".format(nmap_report.hosts_up))
    print("nmap_report_hosts_down_count {0}".format(nmap_report.hosts_down))
    print("nmap_report_elapsed_seconds {0}".format(nmap_report.elapsed))

if __name__ == "__main__":
#    report = do_scan("127.0.0.1", "-sV")
#    report = do_scan("192.168.0.0/24", "-PR -v -p22,80,443")
#    report = do_scan("192.168.0.0/30", "-PR -v -p22,80,443")
#    report = do_scan("192.168.0.1", "-PR -v")
#    report = do_scan("192.168.0.0/24, 172.16.251.0/24", "-sP -PR -v")
    report = do_scan("192.168.0.0/24", "-sP -PR -v")
    if report:
        print_scan(report)
    else:
        print("No results returned")
