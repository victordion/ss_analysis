#!/usr/bin/python
from collections import defaultdict
import operator
import commands

with open("shadowsocks.log") as f:
    content = f.readlines()

stats_by_client = defaultdict(lambda:defaultdict(int))

for line in content:
    if "connecting" in line:
        tokens = line.split()
        
        # requesting client IP address
        colon_index = tokens[6].index(':')
        client_ip = tokens[6][0 : colon_index]

        last_dot_index = tokens[4].rfind('.')
        second_last_dot_index = tokens[4].rfind('.', 0, last_dot_index)
        colon_index = tokens[4].index(':')

        #" invalid visited_host format
        if last_dot_index == -1 or colon_index == -1:
            continue

        visited_host = tokens[4][second_last_dot_index + 1 : colon_index]

        stats_by_client[client_ip][visited_host] += 1

for client_ip in stats_by_client.keys():
    
    whois_info = commands.getstatusoutput('whois ' + client_ip)[1].split('\n')
    
    for line in whois_info:
        if "netname" in line.lower():
            netname = line.split()[1]
            break

    print "Client IP: %s --> %s" % (client_ip, netname)
    
    sorted_visits = sorted(stats_by_client[client_ip].items(), key=operator.itemgetter(1), reverse=True)
    for e in sorted_visits:
        print "    %s : %d" % e
