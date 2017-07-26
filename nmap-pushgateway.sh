#!/bin/bash
curl -X DELETE --connect-timeout 5 --max-time 60 http://localhost:9091/metrics/job/smartmon/instance/homelan
python /root/nmap/nmap_exporter.py | curl --connect-timeout 5 --max-time 60 --data-binary @- http://localhost:9091/metrics/job/nmap/instance/homelan
