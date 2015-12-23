#!/usr/bin/python
from collections import defaultdict
import operator
import commands
import matplotlib.pyplot as plt
from world import *

with open("shadowsocks.log") as f:
    content = f.readlines()

stats_by_client = defaultdict(lambda:defaultdict(int))

super_suffix = ['net', 'com', 'org', 'co', 'edu', 'mil', 'gov', 'info']
country_suffix = ['cn', 'io', 'tv', 'us', 'tw', 'uk', 'jp', 'hk', 'de', 'li']

for line in content:
    if "connecting" in line:
        tokens = line.split()
        
        # requesting client IP address
        colon_index = tokens[6].index(':')
        client_ip = tokens[6][0 : colon_index]

        colon_index = tokens[4].index(':')
        comps = tokens[4][0:colon_index].split('.')

        if len(comps) <= 1:
            continue
        
        start = -1
        for i in range(len(comps) - 1, -1, -1):
            if comps[i] in countries.keys():
                if comps[i - 1] in nameorgs.keys():
                    start = i - 2
                    break
                else:
                    start = i - 1
                    break
            elif comps[i] in nameorgs.keys():
                start = i - 1
                break
            

        visited_host = ""
        for i in range(start, len(comps)):
            visited_host += comps[i]
            if i != len(comps) - 1:
                visited_host += '.'

        stats_by_client[client_ip][visited_host] += 1

fig_num = 1

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

    fig = plt.figure(fig_num)
    fig_num += 1    

    bar_width = 0.35
    
    show_len = min(20, len(sorted_visits))
    # specify the length of interest, we only care these top ***show_len*** visited hosts
    num_visits = [x[1] for x in sorted_visits][0:show_len]
    hostname_visits = [x[0] for x in sorted_visits][0:show_len]
    index = range(0, show_len)
    rects = plt.bar(index, num_visits, bar_width, color='b')

    plt.xlabel("Target host")
    plt.ylabel("Times")
    plt.title("Visits by" + client_ip + "@" +  netname)
    plt.xticks(index, hostname_visits, rotation=15)
    fig.show()

# prevent figures from auto closing
raw_input()
