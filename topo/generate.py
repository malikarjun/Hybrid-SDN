#!/usr/bin/python
import os,re,csv,argparse


parser = argparse.ArgumentParser(description='Generate csv files from pcap files')
parser.add_argument('-s', '--switches', help='''Names of switches to have SDN. Switches are numbered in level-order of a tree starting from 1. Enter a space seperated list''',
                    nargs='*', default={}, type=str)

args = parser.parse_args()

directory = os.environ['HOME'] + '/prabodh/hybrid-sdn-thesis/analysis/{0}/'



hosts = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
         41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64]

delay = "Average delay += +([0-9.]+) s"
bitrate = "Average bitrate += +([0-9.]+) Kbit"


bandwidth = {}
latency = {}

for i in range(len(hosts)):


    k = 'h'+str(i)
    try:
        ITG = os.popen('ITGDec $HOME/prabodh/hybrid-sdn-thesis/stat/recv{0}.log|tail -15|grep -i "average\|drop"'.format(k)).read()
        print(ITG)
        delay_s = float(re.search(delay, ITG).group(1))*1000
        bitrate_mBps = float(re.search(bitrate, ITG).group(1))/(8*1024)

        bandwidth[k] = bitrate_mBps
        latency[k] = delay_s
    except:
        print(k + ' not required')



data = [bandwidth, latency]
file_name = ['bandwidth.csv', 'latency.csv']
fieldnames = [['host', 'bandwidth (in MBps)'],['host', 'delay (in ms)'] ]


for i in range(0,2):
    path = directory.format(','.join(args.switches))

    if not os.path.exists(path):
        os.makedirs(path)

    writer = csv.DictWriter(open(path + file_name[i] , 'wb'), fieldnames=fieldnames[i])
    writer.writeheader()
    for h in data[i]:

        a = {fieldnames[i][0] : h, fieldnames[i][1]: data[i][h]}
        writer.writerow(a)

os.system('chmod -R 777 $HOME/prabodh/hybrid-sdn-thesis/analysis')