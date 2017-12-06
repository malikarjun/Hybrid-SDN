#!/usr/bin/python
from scapy.all import *
import argparse,csv,os, shutil, time

# hosts = [ [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, ],
#             [33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64]]

hosts = [[1],
        [2]]

def countUDPTraffic(file):
    index_list = []
    index = 0
    cnt = 0
    # Loop for packet filter : frame.len == 554
    for pkt, (sec, usec, wirelen) in RawPcapReader(file):
        if wirelen == 554:
            index_list.append(index)
        index += 1
    # Loop for packet filter : udp
    i = 0
    with PcapReader(file) as pcap_reader:
        for pkt in pcap_reader:
            if i == 0:
                start_time = pkt.time
            end_time = pkt.time
            if pkt.haslayer('UDP') and i in index_list:
                cnt += 1
            i += 1
    return cnt, i, (end_time - start_time)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run a packet sniffer')

    parser.add_argument('-s', '--switches', help='''Names of switches to have
                            SDN. Switches are numbered in level-order of a tree
                            starting from 1. Enter a space seperated list''',
                        nargs='*', default={}, type=str)
    parser.add_argument('-f', '--timeperiod', default=0, type=int)
    args = parser.parse_args()

    base_path = os.environ['HOME'] + '/prabodh/hybrid-sdn-thesis/'
    print(base_path)

    cnt = 0
    udp_packets = 0
    overhead = 0
    start = 0
    end = 0
    flag = 0

    # iterate over all the host pcap file to calculate the actual UDP traffic generated
    for i in range(len(hosts[0])):
        flag ^= 1
        cli = ('h' + str(hosts[flag ^ 1][i]))
        file = base_path + 'stat/{}'.format(cli)
        (rudp_packets , rtotal_packets, time) = countUDPTraffic(file)
        udp_packets += rudp_packets

    # iterate over each of the SDN switches
    for sw in args.switches:
        # iterate over each of the interfaces
        for intf in range(1,4):
            file = base_path + 'stat/{}-eth{}'.format(sw,intf)
            (rcnt, rtotal, x) = countUDPTraffic(file)
            cnt += rcnt

    # Create backup of all pcap files
    path = base_path + 'backup/' + ','.join(args.switches) + '/'
    if not os.path.exists(path):
        os.makedirs(path)
    path += str(args.timeperiod) + '/'
    if not os.path.exists(path):
        os.makedirs(path)
    for file in os.listdir(base_path + 'stat'):
        shutil.copy(base_path+'stat/' + file, path)

    # write the results into a csv file
    # rudp_packets = recorded udp packets for h1 host pcap file
    # udp_packets = total udp packets generated using DITG
    file = base_path + 'analysis/sdn_reach_{0}.csv'.format(','.join(args.switches))

    if not os.path.exists(file):
        with open(file, 'a+') as fd:
            wr = csv.writer(fd, dialect='excel')
            wr.writerows([['Timeperiod','Total Packets (for single host)', 'UDP Packets (for single host)' ,'UDP Packets (for entire network)',
                           'UDP packets reaching SDN (for entire network)', 'SDN reachability percentage',  'Overhead (in percentage)', 'Overhead (in bandwidth, Kbits/sec)']])

    result = [[args.timeperiod, rtotal_packets, rudp_packets, udp_packets, cnt, ((float(cnt)/udp_packets)*100),

               ((rtotal_packets - rudp_packets)/float(rtotal_packets) )*100, ((((rtotal_packets - rudp_packets)*46*8))/1000)/float(time) ]]
    with open(file,'a+') as fd:
        wr = csv.writer(fd, dialect='excel')
        wr.writerows(result)

