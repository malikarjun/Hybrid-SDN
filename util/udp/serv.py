
import socket
import sys

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to the port
server_address = (sys.argv[1], 10000)
print >>sys.stderr, 'starting up on %s port %s' % server_address
sock.bind(server_address)

while True:
    # Wait for a connection
    print >>sys.stderr, 'waiting for a connection'

    # Receive the data in small chunks and retransmit it
    data, addr = sock.recvfrom(4)
    print >> sys.stderr, 'connection from', addr 
    print >> sys.stderr, 'received "%s"' % data
