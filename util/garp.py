from socket import *
from sys import *
import pdb
import fcntl, struct

def convertToHex(string):
    addr = []
    i = 0
    while i < len(string):
        addr += [(int('0x'+string[i:i+2],16))]
        i += 3
    return addr

def sendeth(arp_frame, interface):
    """Send raw Ethernet packet on interface."""
    s = socket(AF_PACKET, SOCK_RAW)

    # From the docs: "For raw packet
    # sockets the address is a tuple (ifname, proto [,pkttype [,hatype]])"
    s.bind((interface, 0))
    return s.send(arp_frame)



def getHwAddr(ifname):
    s = socket(AF_INET, SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])


def pack(byte_sequence):
    """Convert list of bytes to byte string."""
    print byte_sequence
    return b"".join(map(chr, byte_sequence))

if __name__ == "__main__":
    # Formulate a Gratuitous ARP
    # https://en.wikipedia.org/wiki/EtherType
    # eth_dst = [0x00,0x00,0x00,0x00,0x00,17]
    eth_dst = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]


    eth_src = convertToHex(argv[1])
    eth_dst1 = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    eth_src1 = convertToHex(getHwAddr(argv[3]))


    eth_type = [0x08, 0x06]
    arp_type = [0x00, 0x01, 0x08, 0x00, 0x06, 0x04]
    # arp_reply = [0x00, 0x02]
    arp_req = [0x00, 0x01]
    ip_src = [0x0a,0x00,int(argv[2][5]), int(argv[2][7:])]
    # ip_dst = [0x0a,0x00,int(argv[3][5]), int(argv[3][7:])]
    # ip_dst = [0x0a,0x00,0x01,2]
    ip_dst = ip_src


    # arpframe
        ## ETHERNET
        # destination MAC addr
        # source MAC addr
        # ETHERNET_PROTOCOL_TYPE_ARP,
        ## ARP
        # ARP_PROTOCOL_TYPE_ETHERNET_IP,
        # operation type request/reply
        # sender MAC addr
        # sender IP addr
        # target hardware addr
        # target IP addr


    arp_frame = eth_dst+eth_src1+eth_type+arp_type+arp_req+eth_src+ip_src+eth_dst1+ip_dst

    # Construct Ethernet packet with an IPv4 ICMP PING request as payload

    r = sendeth(pack(arp_frame), argv[3])
    print("Sent GARP payload of length %d bytes" % r)
