import sys, os, re, pprint, json, pdb
from math import ceil

def min(a, b):
    return a if a < b else b

pattern = "([0-9:.]+).*IP.* ([0-9.]+) > ([0-9.]+):.*length ([0-9.]+)"

flag = -1
vlan = 0

src = ''
seconds = 0
min_seconds = 86400000
packet = ''
header = sys.argv[1]

d = {}
files = os.popen('ls -1 $HOME/prabodh/hybrid-sdn-thesis/stat | grep "vlan\|s[0-9]\+-"').read()[:-1]
files = files.split('\n')

hosts = [[1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40],
        [41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80]]
flag = 0
delay = "Average delay += +([0-9.]+) s"
bitrate = "Average bitrate += +([0-9.]+) Kbit"
drop = "Packets dropped += +([0-9]+) "
host_ee = {}

for i in range(len(hosts[0])):
    flag ^= 1
    cli = hosts[flag^1][i]
    serv = hosts[flag][i]

    k = 'h'+str(serv)
    try:
        ITG = os.popen('ITGDec $HOME/prabodh/hybrid-sdn-thesis/stat/recv{0}.log|tail -15|grep -i "average\|drop"'.format(k)).read()
        delay_s = float(re.search(delay, ITG).group(1))*1000
        bitrate_mBps = float(re.search(bitrate, ITG).group(1))/(8*1024)
        _drop = re.search(drop, ITG).group(1)
        host_ee[k] = {'delay':delay_s,'bitrate':bitrate_mBps, 'drop': _drop}
    except:
        print k

drop_file = open(os.path.expanduser('~')+'/prabodh/hybrid-sdn-thesis/stat/drop','a')
stdout = sys.stdout
sys.stdout = drop_file
print header
pprint.pprint(host_ee)
sys.stdout = stdout

print >>sys.stderr, files

size = 0
for tcp_file in files:
    f = open(os.path.expanduser('~')+'/prabodh/hybrid-sdn-thesis/stat/'+tcp_file, 'r')
    print >>sys.stderr, tcp_file
    tcp_file = tcp_file[1:]

    for line in f:

        if 'UDP' in line:
            m = re.search('vlan ([0-9]+)', line)
            if m != None:
                vlan = int(m.group(1))
            flag = 2
            m = re.search(pattern,line)
            t = re.split('[:.]',m.group(1))
            t = map(float,t)

            src = '.'.join(m.group(2).split('.')[2:4])
            size = int(m.group(4))

            #milli
            seconds = t[0]*60*60*1000 + t[1]*60*1000 + t[2]*1000 + t[3]/1000.0
            min_seconds = min(min_seconds,seconds)
            # print m.group(1),seconds,src
            continue

        if flag:
            flag -= 1
            continue

        if flag == 0:
            flag -= 1
            if vlan:
                packet = line[20:24]+line[25:29]
            else:
                packet = line[10:14]+line[15:19]

            if vlan == 5 and re.search('s[1-4]-eth[56]',tcp_file) is not None:
                continue

            if packet not in d:
                d[packet] = {src:{tcp_file:[(seconds,size)]}}
            else:
                if src not in d[packet]:
                     d[packet][src] = {tcp_file:[(seconds,size)]}
                else:
                    d[packet][src][tcp_file] = d[packet][src].get(tcp_file,[]) + [(seconds,size)]
            vlan = 0

for packet in d: # go through every recorded packet
    for host in d[packet]: # for every packet, go through every host
        for intf in d[packet][host]:
            z = []
            for i in d[packet][host][intf]:
                z += [(i[0]-min_seconds,i[1])]
            d[packet][host][intf] = z

print header
#pprint.pprint(d)
print(d)
TOPO_FILE = 'topo_tree_adj_list'
FLOW_FILE = 'flows'

f = open(TOPO_FILE)
topo = json.load(f)

traversal = {}

f_t = open('traversal','r')
traversal = json.load(f_t)
print >> sys.stderr, pprint.pformat(traversal)

totalDrop = 0
link_speed = {}
link_util  = {}
link_bw = {}
link_latency = {}

i = 0
for packet in d: # go through every recorded packet
    for host in d[packet]: # for every packet, go through every host
        if host == '':
            break
        i = 0
        if host == '':
            break
        while i < len(traversal[host])-1: # for a host, go through all interfaces in order
            intf = traversal[host][i]
            eth1 = traversal[host][i+1]

            if intf in d[packet][host] and eth1 in d[packet][host]:
                p1 = 0
                p2 = 0
                try:
                    p1 = d[packet][host][intf].pop(0)
                    p2 = d[packet][host][eth1][0]

                    if p2[0] < p1[0]:
                        d[packet][host][intf].insert(p1, 0)
                        i+=1
                        continue
                except:
                    i+=1
                    continue

                link = intf+":"+eth1

                if link not in link_speed:
                    link_speed[link] = {}
                second = str(int(ceil(p2[0]/1000)))

                if second not in link_speed[link]:
                    link_speed[link][second] = []
                link_speed[link][second] += [(p2[0] - p1[0],p1[1])]
            i+=1

for link in link_speed:
    link_util[link] = 0
    link_bw[link] = {}
    link_latency[link] = 0
    bw = 0
    for second in link_speed[link]:
        link_util[link] += (len(link_speed[link][second]))
        link_bw[link][second] = 0
        for t in link_speed[link][second]:
            link_latency[link] += t[0]
            link_bw[link][second] += t[1]
        link_bw[link][second] /= (1024*1024.)
        bw += link_bw[link][second]
    link_latency[link] /= link_util[link]
    # link_bw[link] = bw/len(link_speed[link])

for link in link_speed:
    link_speed[link] = (link_util[link],link_latency[link],link_bw[link])

stdout = sys.stdout
sys.stdout = drop_file
# pprint.pprint(link_util)
# pprint.pprint(link_bw)
pprint.pprint(link_speed)
sys.stdout = stdout

#for packet in d: # go through every recorded packet
#    for host in d[packet]: # for every packet, go through every host
#        for k in d[packet][host]:
#            if k not in traversal[host]:
#                d[packet][host][k] = 0
