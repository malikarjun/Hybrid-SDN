#!/usr/bin/python
from scapy.all import *
import argparse,csv,os

# hosts = [ [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, ],
#             [33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64]]

hosts = [[1],
         [2]]

def countUDPTraffic(file):


    cnt = 0
    udp_packet_dict = {}

    # populate the udp_packet_dict in the first iteration of the for loop
    with PcapReader(file) as pcap_reader:
        for pkt in pcap_reader:

            if not pkt.haslayer('IP'):
                continue

            key = pkt['IP'].id

            if pkt.haslayer('UDP') :

                udp_packet_dict[key] = 1

                if pkt['IP'].len == 4124:
                    print('Key = {0}, Flag = {1}'.format(key, pkt['IP'].flags))
                    cnt += 1

                    # if cnt == 10:
                    #     exit(0)

    print('After first iteraton {0}'.format(cnt))
    # # In the second iteration count the fragmented packets as well
    with PcapReader(file) as pcap_reader:
        for pkt in pcap_reader:

            if not pkt.haslayer('IP'):
                continue

            key = pkt['IP'].id

            if (not pkt.haslayer('UDP')) and key in udp_packet_dict:
                udp_packet_dict[key] += 1
                if udp_packet_dict[key] == 3:
                    cnt += 1



    return cnt




if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run a packet sniffer')

    parser.add_argument('-s', '--switches', help='''Names of switches to have
                            SDN. Switches are numbered in level-order of a tree
                            starting from 1. Enter a space seperated list''',
                        nargs='*', default={}, type=str)
    parser.add_argument('-f', '--frequency', default=0, type=int)
    args = parser.parse_args()

    base_path = os.environ['HOME'] + '/prabodh/hybrid-sdn-thesis/'
    print(base_path)



    total = 0
    overhead = 0


    start = 0
    end = 0

    flag = 0

    for i in range(len(hosts[0])):
        flag ^= 1

        serv = ('h' + str(hosts[flag][i]))
        cli = ('h' + str(hosts[flag ^ 1][i]))
        print(cli)

        file = base_path + 'stat/{}'.format(cli)


        # total += countUDPTraffic(file)

        index = 0
        with PcapReader(file) as pcap_reader:
            for pkt in pcap_reader:

                if index == 0:
                    start = pkt.time
                end = pkt.time

                if pkt.haslayer('UDP'):
                    total += 1

                index += 1

        if overhead == 0:
            overhead = index

    print(total)

    time = float(end - start)


    cnt = 0
    for sw in args.switches:
        for intf in range(1,4):

            file = base_path + 'stat/{}-eth{}'.format(sw,intf)
            cnt += countUDPTraffic(file)




    file = base_path + 'analysis/sdn_reach_{0}.csv'.format(','.join(args.switches))

    if not os.path.exists(file):
        with open(file, 'a+') as fd:
            wr = csv.writer(fd, dialect='excel')
            wr.writerows([['Timeperiod', 'SDN reachability percentage', 'Total packets reaching SDN', 'Overhead']])

    # Subtract DITG traffic from overhead
    overhead -= total

    result = [[args.frequency,((float(cnt)/total)*100), cnt, overhead/time]]
    with open(file,'a+') as fd:
        wr = csv.writer(fd, dialect='excel')
        wr.writerows(result)




