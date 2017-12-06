#!/usr/bin/python

"""
Taken from examples/tree1024.py
Create a 64-host network on legacy switch, and run the CLI on it.
"""

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import OVSSwitch, Host, Node
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel, info
from mininet.link import TCLink
from math import ceil
import os,sys,argparse,re,time,json,pdb, threading, random,  csv



range1 = lambda start, end: range(start, end+1)
# hosts = [[1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,],
#          [33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64]]

hosts = [[1],
        [2]]



def back(topo):
    topo_back = {}
    for k in topo:
        for i in range1(*topo[k]):
            topo_back[i] = k
    return topo_back

topo_vlan = {1:[6,10,14,18,22],2:[7,11,15,19,23],3:[8,12,16,20,24],4:[9,13,17,21,25]}

topo_vlan_back = {}
for vlan in topo_vlan:
    for i in topo_vlan[vlan]:
        topo_vlan_back[i] = topo_vlan_back.get(i,[]) + [vlan]

topo_core = {1:[6,9],2:[10,13],3:[14,17],4:[18,21],5:[22,25]}
topo_distro = {6:[26,27],7:[28,29],8:[30,31],9:[32,33],
                10:[34,35],11:[36,37],12:[38,39],13:[40,41],
                14:[42,43],15:[44,45],16:[46,47],17:[48,49],
                18:[50,51],19:[52,53],20:[54,55],21:[56,57],
                22:[58,59],23:[60,61],24:[62,63],25:[64,65]}
topo_access = {26: [1, 2], 27: [3, 4], 28: [5, 6], 29: [7, 8], 30: [9, 10], 31:
        [11, 12], 32: [13, 14], 33: [15, 16], 34: [17, 18], 35: [19, 20], 36:
        [21, 22], 37: [23, 24], 38: [25, 26], 39: [27, 28], 40: [29, 30], 41:
        [31, 32], 42: [33, 34], 43: [35, 36], 44: [37, 38], 45: [39, 40], 46:
        [41, 42], 47: [43, 44], 48: [45, 46], 49: [47, 48], 50: [49, 50], 51:
        [51, 52], 52: [53, 54], 53: [55, 56], 54: [57, 58], 55: [59, 60], 56:
        [61, 62], 57: [63, 64], 58: [65, 66], 59: [67, 68], 60: [69, 70], 61:
        [71, 72], 62: [73, 74], 63: [75, 76], 64: [77, 78], 65: [79, 80]}
topo_subnet = {1:[[1,4],[17,20],[33,36],[49,52],[65,68]],
                2:[[5,8],[21,24],[37,40],[53,56],[69,72]],
                3:[[9,12],[25,28],[41,44],[57,60],[73,76]],
                4:[[13,16],[29,32],[45,48],[61,64],[77,80]]}

# Parent pointers are initialized using back function
topo_core_back = back(topo_core)
topo_distro_back = back(topo_distro)
topo_access_back = back(topo_access)
topo_subnet_back = {}

   
for k in topo_subnet:
    for l in topo_subnet[k]:
        for i in range1(*l):
            topo_subnet_back[i] = k

class LinuxRouter( Node ):
    "A Node with IP forwarding enabled."
    def config( self, **params ):
        print(params)
        super( LinuxRouter, self).config( **params )
        # Enable forwarding on the router
        self.cmd( 'sysctl net.ipv4.ip_forward=1' )

    def terminate( self ):
        self.cmd( 'sysctl net.ipv4.ip_forward=0' )
        super( LinuxRouter, self ).terminate()

def accessSwitchForHH(switches):

    ac_dict = {}
    for sub in topo_vlan:
        for ds in topo_vlan[sub]:
            if ds not in switches:
                ac_dict[sub] = topo_distro[ds][0]
    # print(ac_dict)
    return ac_dict



def randomGarp( net, vlan_dict, cs, timeperiod):
    """ Method that runs forever """

    # Refer to the garp function in case of any doubts, since both functions are quite similar

    # Setup arp rules to drop gratuitous arp packets to avoid arp table poisoning of core switches
    for sub in topo_subnet:
        for val in range1(1,20):
            os.system('arptables -A INPUT -s 10.0.{0}.{1} -d 10.0.{0}.{1} -j DROP'.format(sub,val))
    os.system('arptables -P INPUT ACCEPT')


    hh = net.get('h0')
    # time.sleep(10)

    flag = False
    while True:
        # Do something
        print('Started')
        start_time  = time.time()

        # Randomly sample half of the number of hosts. Only these hosts will be impersonated instead of all.
        # This is supposed to reduce the congestion in the network.
        allhosts = (hosts[0] + hosts[1])
        randset = random.sample(allhosts, 32)


        for i in randset:

            hi = net.get('h' + str(i))
            core_switch = cs[topo_core_back[topo_distro_back[topo_access_back[i]]] - 1]

            for j in range1(1,4):
                interface = 'h0-eth{}'.format(j - 1)
                key = 'vlan{}{}'.format(core_switch, j)
                hh.cmd('python ../util/garp.py {0} {1} {2}'.format(vlan_dict[key], hi.IP(), interface))

        ps = os.popen('ps -a').read()
        if flag:
            if 'ITGSend' not in ps:
                os.system('sleep 2 && pkill ITGRecv')
            if 'ITG' not in ps:
                break

        if'ITG' in ps:
            flag = True


        print('Time taken to poison the ARP cache = {0} seconds'.format(time.time() - start_time))
        print('Stopped for {}'.format(timeperiod))
        # time.sleep(timeperiod)
        time.sleep(0)


def garp( net, vlan_dict, cs, timeperiod):
    """ Method that runs forever """
    """
    Variables explanation
    net        : Mininet class instance variable used to emulate the tree topology
    vlan_dict  : This contains the mac addresses of all the vlan internal ports present at core switch. For instance, an
                 element in this dict referring to "vlan21=8e:5b:e9:ee:41:f0" will be vlan_dict['vlan21'] = '8e:5b:e9:ee:41:f0'
                 where, 'vlan21' is the key and '8e:5b:e9:ee:41:f0' the value
                 Refer to the macs file in the topo folder for more details.
    cs         : This variable contains four/five elements (depending upon the number of core switches in the tree topology).
                 If the i th element is j, then it means that i th core switch's nearest neighbouring core switch which has
                 SDN enabled switch as its descendant.
    timeperiod : Every run of a infinite while loop (written below) represents a cycle of gratuitous arp packet broadcast.
                 This variable specifies the time period for which the thread sleeps between successive cycles.

    """

    # Setup arp rules to drop gratuitous arp packets to avoid arp table poisoning of core switches
    for sub in topo_subnet:
        for val in range1(1,20):
            os.system('arptables -A INPUT -s 10.0.{0}.{1} -d 10.0.{0}.{1} -j DROP'.format(sub,val))
    os.system('arptables -P INPUT ACCEPT')


    hh = net.get('h0')
    # time.sleep(10)

    flag = False
    # infinite while loop to keep generating gratuitous ARP packets
    while True:

        start_time = time.time()
        print('Started')

        # iterate across all the hosts
        for i in topo_subnet_back:

            hi = net.get('h' + str(i))
            # nearest core switch which has SDN switch as its descendant
            core_switch = cs[topo_core_back[topo_distro_back[topo_access_back[i]]] - 1]

            # send gARP packets across each of the subnets
            for j in range1(1,4):
                interface = 'h0-eth{}'.format(j - 1)
                key = 'vlan{}{}'.format(core_switch, j)
                hh.cmd('python ../util/garp.py {0} {1} {2}'.format(vlan_dict[key], hi.IP(), interface))


        # Keep checking if DITG traffic generation has ended. If yes, then kill this thread to end the program
        ps = os.popen('ps -a').read()
        if flag:
            if 'ITGSend' not in ps:
                os.system('sleep 2 && pkill ITGRecv')
            if 'ITG' not in ps:
                break
        if'ITG' in ps:
            flag = True

        print('Time taken to poison the ARP cache = {0} seconds'.format(time.time() - start_time))
        print('Stopped for {}'.format(timeperiod))
        time.sleep(timeperiod)


        # Uncomment the next two lines for random time intervals between successive cycles
        # print('Running randomised time experiments')
        # tp = random.randint(0,10)
        # time.sleep(tp)

def close(switch, switches):
    for s in switches:
        if s>=switch:
            return s
    return switches[-1]

def printTopoDS(net):
    topo = {}
    pattern = "eth([0-9]+)"
    for l in net.links:

        if 'mirror' in str(l):
            continue
        i1 = str(l.intf1.node)
        i2 = str(l.intf2.node)
        topo[i1] = (i2,re.search(pattern,str(l.intf2)).group(1),l.intf1.IP())

    stdout = sys.stdout
    sys.stdout = open(TOPO_FILE, 'w+')
    print json.dumps(topo)
    sys.stdout = stdout
    return topo

def treeNet(net, switches):
    '''
    @param net
        The Mininetnet network reference
    @param switches
        A list of switches which should be SDN enabled. Default is standalone
    '''

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
            controller=RemoteController,
            protocol='tcp',
            port=6633)

    info( '*** Add switches\n')

    hs100 = {'bw':100,'delay':'10ms'} #Mbit/s
    hs1000 = {'bw':1000,'delay':'10ms'} #Mbit/s

    info( '*** Add core and distribution\n')
    for sw in topo_core:
        s_core = net.addSwitch('s'+str(sw), cls=OVSSwitch, failMode='standalone')

        for i in range1(*topo_core[sw]):
            switchName = 's'+str(i)
            s = None
            try:
                s = net.get(switchName)
            except KeyError:
                s = net.addSwitch(switchName, cls=OVSSwitch,
                        failMode='secure' if switchName in switches else
                        'standalone')
            link = net.addLink(s, s_core, cls=TCLink, **hs1000)

    info( '*** Add access\n')
    for sw in topo_distro:
        for i in range1(*topo_distro[sw]):
            switchName = 's'+str(i)
            s = None
            try:
                s = net.get(switchName)
            except KeyError:
                s = net.addSwitch(switchName, cls=OVSSwitch,
                        failMode='standalone')
            link = net.addLink(s, net.get('s'+str(sw)), cls=TCLink, **hs1000)

    info( '*** Add hosts\n')
    for sw in topo_access:
        for i in range1(*topo_access[sw]):
            hostName = 'h'+str(i)
            h = None
            try:
                h = net.get(hostName)
            except KeyError:
                h = net.addHost(hostName, defaultRoute=None, ip='10.0.{0}.2/24'.format(topo_subnet_back[i]))
            link = net.addLink(h, net.get('s'+str(sw)), cls=TCLink, **hs100)

    core_switches = topo_core.keys()
    core_switches.sort()

    # Add links between core switches
    i = 0
    while i < len(core_switches)-1:
        net.addLink(net.get('s'+str(core_switches[i])), net.get('s'+str(core_switches[i+1])), cls=TCLink, **hs1000)
        i += 1


    # Add the helper host
    hostName = 'h0'
    h = net.addHost(hostName, defaultRoute=None, ip='10.0.1.21/24')
    ac_dict = accessSwitchForHH(switches)

    for sub in ac_dict:
        net.addLink(h, net.get('s' + str(ac_dict[sub])), cls=TCLink, **hs100)
        h.setIP('10.0.{0}.21/24'.format(sub), intf='h0-eth{0}'.format(sub-1))




    info( '*** Starting network\n')
    net.build()

    # Set IP Addresses to each of the hosts using subnet tag and host number
    for sub in topo_subnet:
        count = 1
        for l in topo_subnet[sub]:
            for i in range1(*l):
                hostName = 'h'+str(i)
                h = net.get(hostName)
                h.setIP('10.0.{0}.{1}/24'.format(sub, count))
                count += 1

    topo = printTopoDS(net)
    # Set MAC Addresses to each of the host by converting the host number to hexadecimal notation
    # Ask
    for host in net.hosts:
        if 'mirror' in str(host) or 's1' in str(host):
            continue
        mac = '00:00:00:00:00:'+hex(int(str(host)[1:]))[2:].zfill(2)
        host.setMAC(mac)

    info( '*** Starting switches\n')
    # Start switches and connect the SDN enabled ones to the controller c0 before starting
    for switch in net.switches:
        if str(switch) in switches:
            info('*** switch connected to controller ',switch,'\n')
            switch.start([c0])
            os.system('sudo ovs-vsctl set bridge \"'+str(switch)+'\" protocols=OpenFlow13')
        else:
            switch.start([])

    info( '*** Post configure switches and hosts\n')

    subs, cs = generateFlows(net,topo,list(switches))

    os.system('sh vlan.sh')
    os.system('bash clear.sh')

    if len(args.switches) != 0:
        os.system('bash conff')


    for sub in topo_subnet:
        c = -1
        for l in topo_subnet[sub]:
            c += 1
            for i in range1(*l):
                hostName = 'h'+str(i)
                h = net.get(hostName)
                # h.cmd('sudo route add default gw 10.0.{0}.{1} h{2}-eth0'.format(sub,subs[c],i))
                # if len(switches) != 0:
                #     h.cmd('sudo ip route del 10.0.{0}.0/24 table main'.format(sub))

    #configure VLANs
    vlans = [1,1,2,2,3,3,4,4]
    c = 0

    #configure access ports & distibution switch VLANs
    for i in range1(26,65):
        sw = net.get('s'+str(i))
        for inf in sw.intfs:
            intf = sw.intfs[inf]
            if 'lo' in str(intf):
                continue
            os.system('sudo ovs-vsctl del-port {0} {1}'.format(str(sw),intf))
            os.system('sudo ovs-vsctl add-port {0} {1} tag={2}'.format(str(sw),intf,vlans[c]))
            if str(sw) in str(intf.link.intf1):
                sw1 = str(intf.link.intf2).split('-')[0]
                os.system('sudo ovs-vsctl del-port {0} {1}'.format(sw1,intf.link.intf2))
                os.system('sudo ovs-vsctl add-port {0} {1} tag={2}'.format(sw1,intf.link.intf2,vlans[c]))
        c = (c+1)%8

    #configure VLANs between distibution switch and core switch
    for s in topo_vlan_back:
        sw = net.get('s'+str(s))
        for inf in sw.intfs:
            intf = sw.intfs[inf]
            if 'lo' in str(intf):
                continue
            if str(sw) in str(intf.link.intf1):
                os.system('sudo ovs-vsctl del-port {0} {1}'.format(str(sw),intf))
                os.system('sudo ovs-vsctl add-port {0} {1} trunks={2}'.format(str(sw),intf,','.join(map(str,topo_vlan_back[s]))))
                sw1 = str(intf.link.intf2).split('-')[0]
                os.system('sudo ovs-vsctl del-port {0} {1}'.format(sw1,intf.link.intf2))
                os.system('sudo ovs-vsctl add-port {0} {1} trunks={2}'.format(sw1,intf.link.intf2,','.join(map(str,topo_vlan_back[s]))))

    #configure VLANs between core switches
    for s in topo_core:
        sw = net.get('s'+str(s))
        for inf in sw.intfs:
            intf = sw.intfs[inf]
            if 'lo' in str(intf):
                continue
            if str(sw) in str(intf.link.intf1):
                os.system('sudo ovs-vsctl del-port {0} {1}'.format(str(sw),intf))
                os.system('sudo ovs-vsctl add-port {0} {1} trunks={2}'.format(str(sw),intf,'1,2,3,4'))
                sw1 = str(intf.link.intf2).split('-')[0]
                os.system('sudo ovs-vsctl del-port {0} {1}'.format(sw1,intf.link.intf2))
                os.system('sudo ovs-vsctl add-port {0} {1} trunks={2}'.format(sw1,intf.link.intf2,'1,2,3,4'))

    #configure VLANs between core switch and SDN-distribution switch
    for s in switches:
        sw = net.get(s)
        for inf in sw.intfs:
            intf = sw.intfs[inf]
            if 'lo' in str(intf):
                continue
            if str(sw) in str(intf.link.intf1):
                os.system('sudo ovs-vsctl del-port {0} {1}'.format(str(sw),intf))
                os.system('sudo ovs-vsctl add-port {0} {1} trunks={2}'.format(str(sw),intf,'1,2,3,4'))
                sw1 = str(intf.link.intf2).split('-')[0]
                os.system('sudo ovs-vsctl del-port {0} {1}'.format(sw1,intf.link.intf2))
                os.system('sudo ovs-vsctl add-port {0} {1} trunks={2}'.format(sw1,intf.link.intf2,'1,2,3,4'))

    # configure helper host
    sw = net.get('h0')
    c = 0
    for inf in sw.intfs:
        intf = sw.intfs[inf]
        if 'lo' in str(intf):
            continue


        sw1 = str(intf.link.intf2).split('-')[0]
        os.system('sudo ovs-vsctl del-port {0} {1}'.format(sw1, intf.link.intf2))
        os.system('sudo ovs-vsctl add-port {0} {1} tag={2}'.format(sw1, intf.link.intf2, vlans[c]))

        c += 2

    return cs


def generateFlows(net,topo,switches):

    switches = [int(s[1:]) for s in switches]
    switches.sort()
    switches = ['s'+str(s) for s in switches]

    conff = open('conff','w')
    vlan_sh = open('vlan.sh','w')
    route_sh = open('route.sh','w')
    trav = open('traversal','w')

    core_switches = set()
    # ask: Why are we working with one sdn switch(the first one) when there can be multiple sdn enabled switches
    # Answer: The variable sdn_switch keeps track of the nearest sdn switch that can be reached from a legacy switch 
    sdn_switch = switches[0]
    core_switch = topo[sdn_switch][0]
    core_switches.add(core_switch)
    sdn_vlans = {sdn_switch:set()} # list of subnets being diverted to given SDN switch

    traversal = {} 

    for i in range1(0,1):
        j = i #select only clients
        while j < len(hosts[i]):
            h = hosts[i][j]
            h = 'h'+str(h)
            s_dst = topo[topo[h][0]][0] #distribution switch
            if s_dst in switches and s_dst is not sdn_switch:
                sdn_switch = s_dst
                sdn_vlans[sdn_switch] = set()
                core_switch = topo[sdn_switch][0]
                core_switches.add(core_switch)
            sdn_vlans[sdn_switch].add(*topo_vlan_back[int(s_dst[1:])])
            ip = net.get(h).IP()
            ip = '.'.join(ip.split('.')[2:])

            k = h

            traversal[ip] = [topo[k][0]+"-eth"+topo[k][1]]
            k = topo[k][0]
            while 1:
                traversal[ip] += [k+"-eth1",topo[k][0]+"-eth"+topo[k][1]]
                k = topo[k][0]
                if int(k[1:]) in topo_core:
                    break

            s_1 = k
            s_1 = int(s_1[1:])
            k = 'h'+str(hosts[i^1][j])

            if s_dst != sdn_switch and topo[topo[k][0]][0] != sdn_switch:
                s_2 = int(topo[sdn_switch][0][1:])
                l = 0

                if s_1 < s_2:
                    while s_1 < s_2:
                        traversal[ip] += ['s'+str(s_1)+'-eth'+ ('5' if s_1 == 1 else '6'),'s'+str(s_1+1)+'-eth5']
                        s_1 += 1
                else:
                    while s_1 > s_2:
                        traversal[ip] += ['s'+str(s_1)+'-eth5','s'+str(s_1-1)+'-eth'+ ('5' if s_1-1 == 1 else '6')]
                        s_1 -= 1

                traversal[ip] += [topo[sdn_switch][0]+"-eth"+topo[sdn_switch][1],sdn_switch+"-eth1",sdn_switch+"-eth1",topo[sdn_switch][0]+"-eth"+topo[sdn_switch][1]]
                s_1 = s_2

            temp_traversal = [topo[k][0]+"-eth"+topo[k][1]]
            k = topo[k][0]
            while 1:
                temp_traversal += [k+"-eth1",topo[k][0]+"-eth"+topo[k][1]]
                k = topo[k][0]
                if int(k[1:]) in topo_core:
                    break

            s_2 = k
            s_2 = int(s_2[1:])

            if s_1 < s_2:
                while s_1 < s_2:
                    traversal[ip] += ['s'+str(s_1)+'-eth'+ ('5' if s_1 == 1 else '6'),'s'+str(s_1+1)+'-eth5']
                    s_1 += 1
            else:
                while s_1 > s_2:
                    traversal[ip] += ['s'+str(s_1)+'-eth5','s'+str(s_1-1)+'-eth'+ ('5' if s_1-1 == 1 else '6')]
                    s_1 -= 1

            temp_traversal.reverse()
            traversal[ip] += temp_traversal
            j += 2

    json.dump(traversal, trav, indent = 4, sort_keys=True)

    rule_1_route = "\nip route add 10.0.{0}.0/24 dev {1}-eth{2} table {3} proto static scope link"
    # Ex: ip route add 10.0.1.0/24 dev s1-eth4 table 2 proto static scope link
    # Explanation: All the packets arriving at core switch 1 in search of sdn swith are routed to s1-eth4 interface because sdn switch in this example is 9.

    # sdn_vlans: list of subnets being diverted to given SDN switch
    for sw in sdn_vlans:
        for v in sdn_vlans[sw]:
            route_sh.write(rule_1_route.format(v,topo[sw][0],topo[sw][1],int(topo[sw][0][1:])+1))
    # Ask: Why don't we name the routing tables starting from 1?


    for sw in core_switches:


        # Add ip rule lists, which would help us choose the appropriate routing table depending upon packet header
        rule_0 = "\nip rule add to 10.0.{0}.25{1} lookup local pref 0"
        rule_1 = "\nip rule add from 10.0.{0}.0/24 iif vlan{1}{0} lookup {2} pref 1"
        rule_2 = "\nip rule add iif vlan{0}{1} lookup {2} pref 2"

        # Add route for vlan in respective routing tables
        rule_2_route= "\nip route add 10.0.{0}.0/24 dev vlan{1}{0} table {2} proto static scope link"

        # Add an ``internal port'' vlan{0}{1} to switch s{0} as a VLAN access port for VLAN {0}{1}, and configure it with an IP address
        vlan_conf_add = "\nsudo ovs-vsctl add-port s{0} vlan{0}{1} tag={1} -- set interface vlan{0}{1} type=internal"
        vlan_conf_ip = "\nsudo ifconfig vlan{0}{1} 10.0.{1}.25{2}/24"

        s = int(sw[1:])

        for i in range1(1,4):
            conff.write(rule_0.format(i,s-1))
            vlan_sh.write(vlan_conf_add.format(s,i))
        conff.write('\n')
        for i in range1(1,4):
            conff.write(rule_1.format(i,s,s+1))
            vlan_sh.write(vlan_conf_ip.format(s,i,s-1))
        conff.write('\n')
        for i in range1(1,4):
            conff.write(rule_2.format(s,i,s+6))
            route_sh.write(rule_2_route.format(i,s,s+6))
        conff.write('\n')

    conff.write('\nbash route.sh')

    route_sh.write('''\nifconfig | grep "s[1-5]-eth[1-6]\|vlan.[12345]"|sed "s/-//"|sed "s/   Link encap:Ethernet  HWaddr//"|sed "s/  */=/" > macs
. $PWD/macs
for i in {1..4}; do for j in {1..20}; do for k in {1..5}; do for l in {1..4}; do
    sudo arp -s 10.0.$i.$j 10:00:00:00:00:01 -i s$k-eth$l; done; done; done;
done;\n''')

    f1 = "\nsudo ovs-ofctl -OOpenFlow13 add-flow {0} ip,priority={1},nw_dst={2}{3},actions=strip_vlan,set_field:{4}\"->\"eth_dst,set_field:$vlan{5}{6}\"->\"eth_src,{7}"
    f2 = "\nsudo ovs-ofctl -OOpenFlow13 add-flow {0} ip,priority={1},nw_src=10.0.{2}.0/24{3},actions=mod_vlan_vid:{4},set_field:$vlan{5}{4}\"->\"eth_dst,set_field:$s{5}eth{6}\"->\"eth_src,{7}"

    '''
                     Explaination of set_field:
                     Loads  a  literal  value into a field or part of a field.
                     With set_field, value and the optional mask are given  in
                     the customary syntax for field dst, which is expressed as
                     a        field        name.          For         example,
                     set_field:00:11:22:33:44:55->eth_src  sets  the  Ethernet
                     source address to 00:11:22:33:44:55.
    '''
    ports=[2,2,3,3]
    vlans=[4,1,2,3]
    ports = [str(x) for x in ports]
    for sw in sdn_vlans:
        route_sh.write('\n')
        s = int(sw[1:])
        hh = []
        for a in range1(*topo_distro[s]):
            hh += topo_access[a]
        j = 0
        for h in hh:
            route_sh.write(f1.format(sw,4,net.get('h'+str(h)).IP(),",in_port="+ports[j],net.get('h'+str(h)).MAC(),topo[sw][0][1:],topo_vlan_back[s][0],"IN_PORT"))
            route_sh.write(f1.format(sw,3,net.get('h'+str(h)).IP(),"",net.get('h'+str(h)).MAC(),topo[sw][0][1:],topo_vlan_back[s][0],"output:"+ports[j]))
            j+=1

        for i in range1(1,4):
            route_sh.write(f2.format(sw,2,i,",in_port=5",vlans[i-1],topo[sw][0][1:],topo[sw][1],"IN_PORT"))
            route_sh.write(f2.format(sw,2,i,"",vlans[i-1],topo[sw][0][1:],topo[sw][1],"output:5"))


    conff.close()
    vlan_sh.close()
    route_sh.close()
    trav.close()

    core_switches = [int(s[1:]) for s in core_switches]
    core_switches.sort()
    c = core_switches[0]

    subs = []

    for sw in topo_core:
        subs += [nearestCoreSwitch(core_switches, sw)]
        # if sw in core_switches:
        #     c = sw
        # subs+=[c]


    cs = subs

    subs = [249+s for s in subs]

    return subs,cs

def nearestCoreSwitch(core_switches, sw):

    c = core_switches[0]
    diff = abs(c - sw)
    for i in core_switches:
        if diff > abs(i - sw):
            diff = abs(i - sw)
            c = i
    return c

def startTG(net):
    'Traffic generation'

    flag = 0

    for i in range(len(hosts[0])):
        flag ^= 1

        serv = net.get('h'+str(hosts[flag][i]))
        cli  = net.get('h'+str(hosts[flag^1][i]))

        print cli,cli.IP(),'->',serv,serv.IP()

        # serv.cmd('ping -c1 {0}'.format(cli.IP()))

        serv.cmd('ITGRecv &'.format(str(serv)))

        # cli.cmd('route &> $HOME/prabodh/hybrid-sdn-thesis/stat/route{0}'.format(str(serv)))

        # cli.cmd('sleep 2 && ITGSend -T UDP -a '+serv.IP()+' -t 120000 -C 2560 -c 4096 -l $HOME/prabodh/hybrid-sdn-thesis/stat/send{0}.log -x $HOME/prabodh/hybrid-sdn-thesis/stat/recv{0}.log &'.format(str(serv)))
        cli.cmd('sleep 2 && ITGSend -T UDP -a '+serv.IP()+' -t 420000 -C 2560*8 -c 512 -l $HOME/prabodh/hybrid-sdn-thesis/stat/send{0}.log -x $HOME/prabodh/hybrid-sdn-thesis/stat/recv{0}.log &'.format(str(serv)))
        # cli.cmd('sleep 2 && ITGSend -T UDP -a ' + serv.IP() + ' -t 10000 -C 1 -c 512 -l $HOME/prabodh/hybrid-sdn-thesis/stat/send{0}.log -x $HOME/prabodh/hybrid-sdn-thesis/stat/recv{0}.log &'.format(str(serv)))
        # cli.cmd('sleep 2 && ITGSend -T UDP -a '+serv.IP()+' -z 12648 -Fs ps -Ft idts -l $HOME/prabodh/hybrid-sdn-thesis/stat/send{0}.log -x $HOME/prabodh/hybrid-sdn-thesis/stat/recv{0}.log &'.format(str(serv)))



def startRandomTG(net):
    'Random Traffic generation'

    subnet_device = {1: [], 2: [], 3: [], 4: []}
    for k in topo_subnet:
        for l in topo_subnet[k]:
            for i in range1(*l):
                subnet_device[k].append(i)

    for i in range(0, 160):
        subnet = random.randint(1, 4)

        x = random.sample(subnet_device[subnet], 2)
        serv = net.get('h' + str(x[0]))
        cli = net.get('h' + str(x[1]))

        print cli, cli.IP(), '->', serv, serv.IP()

        # serv.cmd('ping -c1 {0}'.format(cli.IP()))

        serv.cmd('ITGRecv &')

        # Sending 10 packets over the period of 10 seconds. The size of each packet is 512 bytes.
        cli.cmd('sleep 2 && ITGSend -T UDP -a ' + serv.IP() + ' -t 10000 -C 1 -c 512 -l $HOME/prabodh/hybrid-sdn-thesis/stat/send{0}.log -x $HOME/prabodh/hybrid-sdn-thesis/stat/recv{0}.log &'.format(str(serv)))




if __name__ == '__main__':
    os.system('sudo mn -c')
    os.system('sudo stop network-manager')
    TOPO_FILE = 'topo_tree_adj_list'

    parser = argparse.ArgumentParser(description='Run a mininet simulation for tree topology')
    parser.add_argument('-c', '--cli', help='Display CLI on given topology.', action='store_true')
    parser.add_argument('-s', '--switches', help='''Names of switches to have
                        SDN. Switches are numbered in level-order of a tree
                        starting from 1. Enter a space seperated list''',
                        nargs='*', default={}, type=str)
    parser.add_argument('-t', '--stats', help='Start TCPdump on all switch interfaces for stats collection purpose', action='store_true')
    parser.add_argument('-f', '--timeperiod', default=0, type=int)

    args = parser.parse_args()

    if args.cli:
        setLogLevel( 'info' )

    net = Mininet( topo=None, build=False, ipBase='10.0.0.0/8')
    cs = treeNet(net, set(args.switches))



    switch_list = []
    monitor = []
    for sw in switch_list:
        monitor.append(net.get(sw))
    for sw in args.switches:
        monitor.append(net.get(sw))


    if args.stats:
        for switch in monitor:
            for i in switch.intfs:
                if str(switch.intfs[i]) == 'lo':
                    continue

                switch.cmd('sudo tcpdump -s 58 -B 65536 -nS -XX -i {0} net 10.0.0.0/16 -w $HOME/prabodh/hybrid-sdn-thesis/stat/{0} &'.format(str(switch.intfs[i])))

        for h in net.hosts:
            h.cmd('sudo tcpdump -s 58 -B 65536 -nS -XX -i {0}-eth0 net 10.0.0.0/16 -w $HOME/prabodh/hybrid-sdn-thesis/stat/{0} &'.format(str(h)))




    if args.cli:
        CLI(net)
        net.stop()
        exit(0)

    print "Testing",','.join(args.switches)

    print net.get('s1').cmdPrint('ip rule list')

    setLogLevel( 'warning' )
    k = ','.join([] if args.switches == {} else args.switches)

    CLI(net, script= 'xterms.sh')
    file = open('macs', 'r')
    
    vlan_dict = {}
    for line in file:
        if line[:4] in 'vlan':
            vlan_dict[line[:6]] = line[7:24]

    thread = threading.Thread(target=garp, args=(net, vlan_dict, cs, args.timeperiod))
    thread.setDaemon(True)
    thread.start()  # Start the execution

    startTG(net)
    # startRandomTG(net)

    # poll for iperfs to die
    time.sleep(10)

    while True:
        ps = os.popen('ps -a').read()
        if 'ITGSend' not in ps:
            os.system('sleep 2 && pkill ITGRecv')
        if 'ITG' not in ps:
            break


    # ------------------------------------------------------------------------------------------------------------------
    # n_packets = 'n_packets=(\d+)'
    #
    # sdn = 0
    # overhead = 0
    #
    # for sw in args.switches:
    #     flows = os.popen('ovs-ofctl -OOpenFlow13 dump-flows {}'.format(sw)).read()
    #     lst = map(int, re.findall(n_packets, flows))
    #
    #     overhead += lst[0]
    #
    #     for i in range(1,len(lst)):
    #         sdn += lst[i]
    #
    # file = os.environ['HOME'] + '/prabodh/hybrid-sdn-thesis/analysis/sdn_reach.csv'
    # result = [[','.join(args.switches),9830400, sdn, overhead]]
    # with open(file,'a+') as fd:
    #     wr = csv.writer(fd, dialect='excel')
    #     wr.writerows(result)
    # ------------------------------------------------------------------------------------------------------------------

    net.stop()


    exit(0)
