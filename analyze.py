#!/usr/bin/python
from collections import defaultdict
import operator
import commands
import matplotlib.pyplot as plt
from world import *
import argparse
from ip_lookup import *

# returned value will look like "2015-12-21-00:03:11"
def getDateTimeStringFromLogLine(line):
    tokens = line.split()
    return tokens[0] + '|' + tokens[1]

# Yeah I know it is buggy
def correctTimeStamp(Y, M, D, h, m, s):
    if s >= 60:
        s = 0
        m += 1
    
    if m >= 60:
        m = 0
        h += 1
    
    if h >= 24:
        h = 0
        D += 1

    if D >= 32:
        D = 1
        M += 1

    if M >= 13:
        M = 1
        Y += 1

    return Y, M, D, h, m, s

# return integers
# format like "2015-12-21-00:03:11"
def parseTimeStamp(ts_str):
    [Y, M, D, h, m, s] = [0, 0, 0, 0, 0, 0]

    if len(ts_str) >= 4:
        Y = int(ts_str[0:4])

    if len(ts_str) >= 7:
        M = int(ts_str[5:7])

    if len(ts_str) >= 10:
        D = int(ts_str[8:10])

    if len(ts_str) >= 13:
        h = int(ts_str[11:13])

    if len(ts_str) >= 16:
        m = int(ts_str[14:16])

    if len(ts_str) >= 19:
        s = int(ts_str[17:19])

    return [Y, M, D, h, m, s]

# format like "2015-12-21-00:03:11"
def getNextTimeStampByGranularity(ts_str, granularity):
    Y, M, D, h, m, s = parseTimeStamp(ts_str)
    
    #print "Input: " + ts_str

    if granularity == 's':
        s += 1
    elif granularity == 'm':
        m += 1
    elif granularity =='h':
        h += 1
    elif granularity == 'D':
        D += 1
    elif granularity == 'M':
        M += 1
    elif granulariry == 'Y':
        Y += 1
    else:
        s += 1
    
    Y, M, D, h, m, s = correctTimeStamp(Y, M, D, h, m, s)
    next_ts_str = "%04d-%02d-%02d|%02d:%02d:%02d" % (Y, M, D, h, m, s)
   
    #print "Output:" + next_ts_str
    #raw_input()

    if granularity == 's':
        return next_ts_str[:19]
    elif granularity == 'm':
        return next_ts_str[:16]
    elif granularity =='h':
        return next_ts_str[:13]
    elif granularity == 'D':
        return next_ts_str[:10]
    elif granularity == 'M':
        return next_ts_str[:7]
    elif granulariry == 'Y':
        return next_ts_str[:4]
    else:
        return next_ts_str[:19]
    

def compareTimeStampStrings(ts1_str, ts2_str, granularity):
    tks1 = [Y1, M1, D1, h1, m1, s1] = parseTimeStamp(ts1_str)
    tks2 = [Y2, M2, D2, h2, m2, s2] = parseTimeStamp(ts2_str)
    
    if granularity == 's':
        end_idx = 6
    elif granularity == 'm':
        end_idx = 5
    elif granularity =='h':
        end_idx = 4
    elif granularity == 'D':
        end_idx = 3
    elif granularity == 'M':
        end_idx = 2
    elif granularity == 'Y':
        end_idx = 1
    else:
        end_idx = 6

    for i in range(0, end_idx):
        if tks1[i] > tks2[i]:
            return 1
        elif tks1[i] < tks2[i]:
            return -1

    return 0

def reduceTimeStampStringToGranularity(ts_str, granularity):
    if granularity == 's':
        return ts_str
    elif granularity == 'm':
        return ts_str[:16]
    elif granularity =='h':
        return ts_str[:13]
    elif granularity == 'D':
        return ts_str[:10]
    elif granularity == 'M':
        return ts_str[:7]
    elif granularity == 'Y':
        return ts_str[:4]
    else:
        return ts_str

def getClientIPFromLogLine(line):
    # requesting client IP address
    tokens = line.split()
    colon_index = tokens[6].index(':')
    return tokens[6][0 : colon_index]


def getVisitedHostFromLogLine(line):
    tokens = line.split()
    colon_index = tokens[4].index(':')
    comps = tokens[4][0:colon_index].split('.')

    if len(comps) <= 1:
        return None
    
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

    return visited_host


def ipMatched(ip, parsed_ip):
    if "*" not in ip:
        return ip == parsed_ip
    else:
        parsed_ip_tokens = parsed_ip.split(".")
        ip_tokens = ip.split(".")
	if len(parsed_ip_tokens) != 4:
            return False
        for i in range(0, 4):
	    if ip_tokens[i] != "*" and ip_tokens[i] != parsed_ip_tokens[i]:
                return False
        return True


def getStatsByClientIP(client_ip):
    stats = defaultdict(int)
    
    with open("shadowsocks.log") as f:
        content = f.readlines()
    
    for line in content:
        if "connecting" in line:
            try:
                parsed_client_ip = getClientIPFromLogLine(line)
                visited_host = getVisitedHostFromLogLine(line) 
                if visited_host is not None and ipMatched(client_ip, parsed_client_ip):
                    stats[visited_host] += 1
            except:
                continue
    return stats

def getSortedStats(stats):
    sorted_stats = sorted(stats.items(), key=operator.itemgetter(1), reverse=True)
    return sorted_stats

def plotTimeSeries(stats):
    fig = plt.figure()
    bar_width = 1

    show_len = len(stats)
    
    num_visits = [tp[1] for tp in stats]
    index = range(0, show_len)
    rects = plt.bar(index, num_visits, bar_width, color='b')

    plt.xlabel("Time")
    plt.ylabel("Number of Visits")
    plt.title("Visiting Distribution " + stats[0][0] + "--" + stats[-1][0])

    x_tick_num = 15
    x_tick_step = max(int(len(index)/x_tick_num), 1)

    plt.xticks(index[0::x_tick_step], [tp[0] for tp in stats[0::x_tick_step]], rotation=15)
    fig.show()
    raw_input()


def plotSortedStats(sorted_stats, client_ip="*.*.*.*"):
    fig = plt.figure()
    bar_width = 0.35

    show_len = min(30, len(sorted_stats))
    # specify the length of interest, we only care these top ***show_len*** visited hosts
    num_visits = [x[1] for x in sorted_stats][0:show_len]
    index = range(0, show_len)
    rects = plt.bar(index, num_visits, bar_width, color='b')

    plt.xlabel("Target host")
    plt.ylabel("Times")
    plt.title("Visiting Stats of " + client_ip)
    plt.xticks(index, [tp[0] for tp in sorted_stats], rotation=45)
    fig.show()
    raw_input()

def getWhoisInfo(ip):
    whois_info = commands.getstatusoutput('whois ' + ip)[1].split('\n')
    for line in whois_info:
        if "netname" in line.lower():
            netname = line.split()[1]
            return netname
    return ""

def showIPs():
    stats_occur = defaultdict(int)
    stats_first_connect_time = defaultdict(str)
    stats_last_connect_time = defaultdict(str)

    with open("shadowsocks.log") as f:
        content = f.readlines()
    
    for line in content:
        if "connecting" in line:
            try:
                parsed_client_ip = getClientIPFromLogLine(line)
                if parsed_client_ip not in stats_occur:
                    stats_first_connect_time[parsed_client_ip] = getDateTimeStringFromLogLine(line)
                else:
                    stats_last_connect_time[parsed_client_ip] = getDateTimeStringFromLogLine(line)
                stats_occur[parsed_client_ip] += 1
            except:
                continue

    print "%15s (%15s) %6s %35s %35s" % ("Client IP", "NetName", "#", "First Appear Time", "Last Appear Time")
    for ip, occurance in stats_occur.items():
        print "%15s (%15s) %6d %35s %35s" % (ip, getWhoisInfo(ip), occurance, stats_first_connect_time[ip], stats_last_connect_time[ip])
        checkip(ip)
        print


def getStatsByTime(client_ip, granularity, start_time_str, end_time_str):
    # A list of tuples, first element being time, second element being number of visits
    stats = []
    
    last_ts_str = ""

    with open("shadowsocks.log") as f:
        content = f.readlines()
    
    for line in content:
        if "connecting" in line:
            ts_str = getDateTimeStringFromLogLine(line)
            ts_str_reduced = reduceTimeStampStringToGranularity(ts_str, granularity)
            
            # if current time is earlier than needed
            if compareTimeStampStrings(ts_str, start_time_str, granularity) == -1:
                continue
            # if current time is later than needed
            elif compareTimeStampStrings(ts_str, end_time_str, granularity) == 1:
                break
            else:
                if last_ts_str != ts_str_reduced:
                    stats.append((ts_str_reduced, 1))
                    last_ts_str = ts_str_reduced
                else:
                    (ts_str, num) = stats[-1]
                    stats[-1] = (ts_str, num + 1)

            #print ts_str_reduced
    
    stats_padded = [stats[0]]
    for tp in stats[1:]:
        expected_next_ts_str = getNextTimeStampByGranularity(stats_padded[-1][0], granularity)
        while expected_next_ts_str != tp[0]:
            stats_padded.append((expected_next_ts_str, 0))
            expected_next_ts_str = getNextTimeStampByGranularity(stats_padded[-1][0], granularity)
        stats_padded.append(tp)

    #if isVerbose:
    #    for tp in stats_padded:
    #        print tp
    return stats_padded

def analyzeByClientIP(client_ip):
    stats = getStatsByClientIP(client_ip)
    sorted_stats = getSortedStats(stats)
    if isVerbose:
        for e in sorted_stats:
            print "    %s : %d" % e
    plotSortedStats(sorted_stats, client_ip)


def analyzeByTime(start_time_str, end_time_str, granularity, client_ip):
    if start_time_str is None:
        start_time_str = "1900-01-01-01:01:01"
    if end_time_str is None:
        end_time_str = "2100-01-01-01:01:01"

    stats = getStatsByTime(client_ip, granularity, start_time_str, end_time_str)
    if isVerbose:
        for e in stats:
            print "%s --> %d" % e
    plotTimeSeries(stats)

isVerbose = False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Analyze the log file generated by shadowsocks.')
    parser.add_argument("verb", help="verb can be [show_ips] or [get_stats_by_ip] or [get_stats_by_time]")
    parser.add_argument("--client_ip", help="specify client ip")
    parser.add_argument("-s", "--start_time", help="specify start time")
    parser.add_argument("-e", "--end_time", help="specify end time")
    parser.add_argument("-g", "--granularity", help="granularity used in time analysis, can be [m], [h], [d]")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")


    args = parser.parse_args()

    if args.verbose:
        isVerbose = True

    if args.verb == "show_ips":
        showIPs()
    elif args.verb == "get_stats_by_ip":
        analyzeByClientIP(args.client_ip)
    elif args.verb == "get_stats_by_time":
        analyzeByTime(args.start_time, args.end_time, args.granularity, args.client_ip)
    else:
        print "Valid positional argument!!!"


