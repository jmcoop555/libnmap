#!/usr/bin/env python
# -*- coding: utf-8 -*-
from datetime import datetime
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException


# start a new nmap scan on localhost with some specific options
def do_scan(targets, options):
    parsed = None
    nmproc = NmapProcess(targets, options)
    rc = nmproc.run()
    if rc != 0:
        print("nmap scan failed: {0}".format(nmproc.stderr))
        file.write("nmap scan failed: {0}".format(nmproc.stderr))
    print('******************')
    file.write('******************\n')

    try:
        parsed = NmapParser.parse(nmproc.stdout)
    except NmapParserException as e:
        print("Exception raised while parsing scan: {0}".format(e.msg))

    return parsed


# print scan results from a nmap report
def print_scan(nmap_report):
    print("Starting Nmap {0} ( http://nmap.org ) at {1}".format(nmap_report.version,nmap_report.started))
    file.write("Starting Nmap {0} ( http://nmap.org ) at {1}\n".format(nmap_report.version,nmap_report.started))

    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address

        print("Nmap scan report for {0} ({1})".format(tmp_host,host.address))
        file.write("Nmap scan report for {0} ({1})\n".format(tmp_host,host.address))
        print("Host is {0}.".format(host.status))
        file.write("Host is {0}.\n".format(host.status))
        print("  PORT     STATE         SERVICE")
        file.write("  PORT     STATE         SERVICE\n")

        for serv in host.services:
            pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(str(serv.port),
                    serv.protocol,
                    serv.state,
                    serv.service)
            if len(serv.banner):
                pserv += " ({0})".format(serv.banner)
            print(pserv)
            file.write(pserv+'\n')
    print(nmap_report.summary)
    file.write(nmap_report.summary+'\n')


if __name__ == "__main__":
    file = open('nmapScan_'+datetime.now().strftime('%Y-%m-%d_%H-%M-%S')+'.txt','w') 
    with open('allHosts.txt') as f:
	   for ip in f.read().splitlines():
		  report = do_scan(ip, "-sV")
		  if report:
		      print_scan(report)
    file.close()


