sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:01,dl_dst=10:00:00:00:00:02,actions=set_field:00:00:00:00:00:02"->"eth_dst,set_field:10:00:00:00:00:01"->"eth_src,IN_PORT
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:01,dl_dst=10:00:00:00:00:03,actions=set_field:00:00:00:00:00:03"->"eth_dst,set_field:10:00:00:00:00:01"->"eth_src,output:3
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:01,dl_dst=10:00:00:00:00:04,actions=set_field:00:00:00:00:00:04"->"eth_dst,set_field:10:00:00:00:00:01"->"eth_src,output:3
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:01,dl_dst=10:00:00:00:00:05,actions=set_field:00:00:00:00:00:05"->"eth_dst,set_field:10:00:00:00:00:01"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:01,dl_dst=10:00:00:00:00:06,actions=set_field:00:00:00:00:00:06"->"eth_dst,set_field:10:00:00:00:00:01"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:01,dl_dst=10:00:00:00:00:07,actions=set_field:00:00:00:00:00:07"->"eth_dst,set_field:10:00:00:00:00:01"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:01,dl_dst=10:00:00:00:00:08,actions=set_field:00:00:00:00:00:08"->"eth_dst,set_field:10:00:00:00:00:01"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:01,dl_dst=10:00:00:00:00:09,actions=set_field:00:00:00:00:00:09"->"eth_dst,set_field:10:00:00:00:00:01"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:01,dl_dst=10:00:00:00:00:0a,actions=set_field:00:00:00:00:00:0a"->"eth_dst,set_field:10:00:00:00:00:01"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:01,dl_dst=10:00:00:00:00:0b,actions=set_field:00:00:00:00:00:0b"->"eth_dst,set_field:10:00:00:00:00:01"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:01,dl_dst=10:00:00:00:00:0c,actions=set_field:00:00:00:00:00:0c"->"eth_dst,set_field:10:00:00:00:00:01"->"eth_src,output:1

sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:02,dl_dst=10:00:00:00:00:01,actions=set_field:00:00:00:00:00:01"->"eth_dst,set_field:10:00:00:00:00:02"->"eth_src,IN_PORT
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:02,dl_dst=10:00:00:00:00:03,actions=set_field:00:00:00:00:00:03"->"eth_dst,set_field:10:00:00:00:00:02"->"eth_src,output:3
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:02,dl_dst=10:00:00:00:00:04,actions=set_field:00:00:00:00:00:04"->"eth_dst,set_field:10:00:00:00:00:02"->"eth_src,output:3
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:02,dl_dst=10:00:00:00:00:05,actions=set_field:00:00:00:00:00:05"->"eth_dst,set_field:10:00:00:00:00:02"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:02,dl_dst=10:00:00:00:00:06,actions=set_field:00:00:00:00:00:06"->"eth_dst,set_field:10:00:00:00:00:02"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:02,dl_dst=10:00:00:00:00:07,actions=set_field:00:00:00:00:00:07"->"eth_dst,set_field:10:00:00:00:00:02"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:02,dl_dst=10:00:00:00:00:08,actions=set_field:00:00:00:00:00:08"->"eth_dst,set_field:10:00:00:00:00:02"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:02,dl_dst=10:00:00:00:00:09,actions=set_field:00:00:00:00:00:09"->"eth_dst,set_field:10:00:00:00:00:02"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:02,dl_dst=10:00:00:00:00:0a,actions=set_field:00:00:00:00:00:0a"->"eth_dst,set_field:10:00:00:00:00:02"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:02,dl_dst=10:00:00:00:00:0b,actions=set_field:00:00:00:00:00:0b"->"eth_dst,set_field:10:00:00:00:00:02"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:02,dl_dst=10:00:00:00:00:0c,actions=set_field:00:00:00:00:00:0c"->"eth_dst,set_field:10:00:00:00:00:02"->"eth_src,output:1

sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:03,dl_dst=10:00:00:00:00:01,actions=set_field:00:00:00:00:00:01"->"eth_dst,set_field:10:00:00:00:00:03"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:03,dl_dst=10:00:00:00:00:02,actions=set_field:00:00:00:00:00:02"->"eth_dst,set_field:10:00:00:00:00:03"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:03,dl_dst=10:00:00:00:00:04,actions=set_field:00:00:00:00:00:04"->"eth_dst,set_field:10:00:00:00:00:03"->"eth_src,IN_PORT
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:03,dl_dst=10:00:00:00:00:05,actions=set_field:00:00:00:00:00:05"->"eth_dst,set_field:10:00:00:00:00:03"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:03,dl_dst=10:00:00:00:00:06,actions=set_field:00:00:00:00:00:06"->"eth_dst,set_field:10:00:00:00:00:03"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:03,dl_dst=10:00:00:00:00:07,actions=set_field:00:00:00:00:00:07"->"eth_dst,set_field:10:00:00:00:00:03"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:03,dl_dst=10:00:00:00:00:08,actions=set_field:00:00:00:00:00:08"->"eth_dst,set_field:10:00:00:00:00:03"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:03,dl_dst=10:00:00:00:00:09,actions=set_field:00:00:00:00:00:09"->"eth_dst,set_field:10:00:00:00:00:03"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:03,dl_dst=10:00:00:00:00:0a,actions=set_field:00:00:00:00:00:0a"->"eth_dst,set_field:10:00:00:00:00:03"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:03,dl_dst=10:00:00:00:00:0b,actions=set_field:00:00:00:00:00:0b"->"eth_dst,set_field:10:00:00:00:00:03"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:03,dl_dst=10:00:00:00:00:0c,actions=set_field:00:00:00:00:00:0c"->"eth_dst,set_field:10:00:00:00:00:03"->"eth_src,output:1

sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:04,dl_dst=10:00:00:00:00:01,actions=set_field:00:00:00:00:00:01"->"eth_dst,set_field:10:00:00:00:00:04"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:04,dl_dst=10:00:00:00:00:02,actions=set_field:00:00:00:00:00:02"->"eth_dst,set_field:10:00:00:00:00:04"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:04,dl_dst=10:00:00:00:00:03,actions=set_field:00:00:00:00:00:03"->"eth_dst,set_field:10:00:00:00:00:04"->"eth_src,IN_PORT
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:04,dl_dst=10:00:00:00:00:05,actions=set_field:00:00:00:00:00:05"->"eth_dst,set_field:10:00:00:00:00:04"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:04,dl_dst=10:00:00:00:00:06,actions=set_field:00:00:00:00:00:06"->"eth_dst,set_field:10:00:00:00:00:04"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:04,dl_dst=10:00:00:00:00:07,actions=set_field:00:00:00:00:00:07"->"eth_dst,set_field:10:00:00:00:00:04"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:04,dl_dst=10:00:00:00:00:08,actions=set_field:00:00:00:00:00:08"->"eth_dst,set_field:10:00:00:00:00:04"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:04,dl_dst=10:00:00:00:00:09,actions=set_field:00:00:00:00:00:09"->"eth_dst,set_field:10:00:00:00:00:04"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:04,dl_dst=10:00:00:00:00:0a,actions=set_field:00:00:00:00:00:0a"->"eth_dst,set_field:10:00:00:00:00:04"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:04,dl_dst=10:00:00:00:00:0b,actions=set_field:00:00:00:00:00:0b"->"eth_dst,set_field:10:00:00:00:00:04"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:04,dl_dst=10:00:00:00:00:0c,actions=set_field:00:00:00:00:00:0c"->"eth_dst,set_field:10:00:00:00:00:04"->"eth_src,output:1

sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:05,dl_dst=10:00:00:00:00:01,actions=set_field:00:00:00:00:00:01"->"eth_dst,set_field:10:00:00:00:00:05"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:05,dl_dst=10:00:00:00:00:02,actions=set_field:00:00:00:00:00:02"->"eth_dst,set_field:10:00:00:00:00:05"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:05,dl_dst=10:00:00:00:00:03,actions=set_field:00:00:00:00:00:03"->"eth_dst,set_field:10:00:00:00:00:05"->"eth_src,output:3
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:05,dl_dst=10:00:00:00:00:04,actions=set_field:00:00:00:00:00:04"->"eth_dst,set_field:10:00:00:00:00:05"->"eth_src,output:3
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:05,dl_dst=10:00:00:00:00:06,actions=set_field:00:00:00:00:00:06"->"eth_dst,set_field:10:00:00:00:00:05"->"eth_src,IN_PORT
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:05,dl_dst=10:00:00:00:00:07,actions=set_field:00:00:00:00:00:07"->"eth_dst,set_field:10:00:00:00:00:05"->"eth_src,IN_PORT
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:05,dl_dst=10:00:00:00:00:08,actions=set_field:00:00:00:00:00:08"->"eth_dst,set_field:10:00:00:00:00:05"->"eth_src,IN_PORT
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:05,dl_dst=10:00:00:00:00:09,actions=set_field:00:00:00:00:00:09"->"eth_dst,set_field:10:00:00:00:00:05"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:05,dl_dst=10:00:00:00:00:0a,actions=set_field:00:00:00:00:00:0a"->"eth_dst,set_field:10:00:00:00:00:05"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:05,dl_dst=10:00:00:00:00:0b,actions=set_field:00:00:00:00:00:0b"->"eth_dst,set_field:10:00:00:00:00:05"->"eth_src,output:3
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:05,dl_dst=10:00:00:00:00:0c,actions=set_field:00:00:00:00:00:0c"->"eth_dst,set_field:10:00:00:00:00:05"->"eth_src,output:3

sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:06,dl_dst=10:00:00:00:00:01,actions=set_field:00:00:00:00:00:01"->"eth_dst,set_field:10:00:00:00:00:06"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:06,dl_dst=10:00:00:00:00:02,actions=set_field:00:00:00:00:00:02"->"eth_dst,set_field:10:00:00:00:00:06"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:06,dl_dst=10:00:00:00:00:03,actions=set_field:00:00:00:00:00:03"->"eth_dst,set_field:10:00:00:00:00:06"->"eth_src,output:3
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:06,dl_dst=10:00:00:00:00:04,actions=set_field:00:00:00:00:00:04"->"eth_dst,set_field:10:00:00:00:00:06"->"eth_src,output:3
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:06,dl_dst=10:00:00:00:00:05,actions=set_field:00:00:00:00:00:05"->"eth_dst,set_field:10:00:00:00:00:06"->"eth_src,IN_PORT
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:06,dl_dst=10:00:00:00:00:07,actions=set_field:00:00:00:00:00:07"->"eth_dst,set_field:10:00:00:00:00:06"->"eth_src,IN_PORT
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:06,dl_dst=10:00:00:00:00:08,actions=set_field:00:00:00:00:00:08"->"eth_dst,set_field:10:00:00:00:00:06"->"eth_src,IN_PORT
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:06,dl_dst=10:00:00:00:00:09,actions=set_field:00:00:00:00:00:09"->"eth_dst,set_field:10:00:00:00:00:06"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:06,dl_dst=10:00:00:00:00:0a,actions=set_field:00:00:00:00:00:0a"->"eth_dst,set_field:10:00:00:00:00:06"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:06,dl_dst=10:00:00:00:00:0b,actions=set_field:00:00:00:00:00:0b"->"eth_dst,set_field:10:00:00:00:00:06"->"eth_src,output:3
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:06,dl_dst=10:00:00:00:00:0c,actions=set_field:00:00:00:00:00:0c"->"eth_dst,set_field:10:00:00:00:00:06"->"eth_src,output:3

sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:07,dl_dst=10:00:00:00:00:01,actions=set_field:00:00:00:00:00:01"->"eth_dst,set_field:10:00:00:00:00:07"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:07,dl_dst=10:00:00:00:00:02,actions=set_field:00:00:00:00:00:02"->"eth_dst,set_field:10:00:00:00:00:07"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:07,dl_dst=10:00:00:00:00:03,actions=set_field:00:00:00:00:00:03"->"eth_dst,set_field:10:00:00:00:00:07"->"eth_src,output:3
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:07,dl_dst=10:00:00:00:00:04,actions=set_field:00:00:00:00:00:04"->"eth_dst,set_field:10:00:00:00:00:07"->"eth_src,output:3
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:07,dl_dst=10:00:00:00:00:05,actions=set_field:00:00:00:00:00:05"->"eth_dst,set_field:10:00:00:00:00:07"->"eth_src,IN_PORT
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:07,dl_dst=10:00:00:00:00:06,actions=set_field:00:00:00:00:00:06"->"eth_dst,set_field:10:00:00:00:00:07"->"eth_src,IN_PORT
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:07,dl_dst=10:00:00:00:00:08,actions=set_field:00:00:00:00:00:08"->"eth_dst,set_field:10:00:00:00:00:07"->"eth_src,IN_PORT
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:07,dl_dst=10:00:00:00:00:09,actions=set_field:00:00:00:00:00:09"->"eth_dst,set_field:10:00:00:00:00:07"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:07,dl_dst=10:00:00:00:00:0a,actions=set_field:00:00:00:00:00:0a"->"eth_dst,set_field:10:00:00:00:00:07"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:07,dl_dst=10:00:00:00:00:0b,actions=set_field:00:00:00:00:00:0b"->"eth_dst,set_field:10:00:00:00:00:07"->"eth_src,output:3
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:07,dl_dst=10:00:00:00:00:0c,actions=set_field:00:00:00:00:00:0c"->"eth_dst,set_field:10:00:00:00:00:07"->"eth_src,output:3

sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:08,dl_dst=10:00:00:00:00:01,actions=set_field:00:00:00:00:00:01"->"eth_dst,set_field:10:00:00:00:00:08"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:08,dl_dst=10:00:00:00:00:02,actions=set_field:00:00:00:00:00:02"->"eth_dst,set_field:10:00:00:00:00:08"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:08,dl_dst=10:00:00:00:00:03,actions=set_field:00:00:00:00:00:03"->"eth_dst,set_field:10:00:00:00:00:08"->"eth_src,output:3
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:08,dl_dst=10:00:00:00:00:04,actions=set_field:00:00:00:00:00:04"->"eth_dst,set_field:10:00:00:00:00:08"->"eth_src,output:3
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:08,dl_dst=10:00:00:00:00:05,actions=set_field:00:00:00:00:00:05"->"eth_dst,set_field:10:00:00:00:00:08"->"eth_src,IN_PORT
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:08,dl_dst=10:00:00:00:00:06,actions=set_field:00:00:00:00:00:06"->"eth_dst,set_field:10:00:00:00:00:08"->"eth_src,IN_PORT
sudo ovs-ofctl -O OpenFlow13 add-flow s2 dl_src=00:00:00:00:00:08,dl_dst=10:00:00:00:00:07,actions=set_field:00:00:00:00:00:07"->"eth_dst,set_field:10:00:00:00:00:08"->"eth_src,IN_PORT
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:08,dl_dst=10:00:00:00:00:09,actions=set_field:00:00:00:00:00:09"->"eth_dst,set_field:10:00:00:00:00:08"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:08,dl_dst=10:00:00:00:00:0a,actions=set_field:00:00:00:00:00:0a"->"eth_dst,set_field:10:00:00:00:00:08"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:08,dl_dst=10:00:00:00:00:0b,actions=set_field:00:00:00:00:00:0b"->"eth_dst,set_field:10:00:00:00:00:08"->"eth_src,output:3
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:08,dl_dst=10:00:00:00:00:0c,actions=set_field:00:00:00:00:00:0c"->"eth_dst,set_field:10:00:00:00:00:08"->"eth_src,output:3

sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:09,dl_dst=10:00:00:00:00:01,actions=set_field:00:00:00:00:00:01"->"eth_dst,set_field:10:00:00:00:00:09"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:09,dl_dst=10:00:00:00:00:02,actions=set_field:00:00:00:00:00:02"->"eth_dst,set_field:10:00:00:00:00:09"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:09,dl_dst=10:00:00:00:00:03,actions=set_field:00:00:00:00:00:03"->"eth_dst,set_field:10:00:00:00:00:09"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:09,dl_dst=10:00:00:00:00:04,actions=set_field:00:00:00:00:00:04"->"eth_dst,set_field:10:00:00:00:00:09"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:09,dl_dst=10:00:00:00:00:05,actions=set_field:00:00:00:00:00:05"->"eth_dst,set_field:10:00:00:00:00:09"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:09,dl_dst=10:00:00:00:00:06,actions=set_field:00:00:00:00:00:06"->"eth_dst,set_field:10:00:00:00:00:09"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:09,dl_dst=10:00:00:00:00:07,actions=set_field:00:00:00:00:00:07"->"eth_dst,set_field:10:00:00:00:00:09"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:09,dl_dst=10:00:00:00:00:08,actions=set_field:00:00:00:00:00:08"->"eth_dst,set_field:10:00:00:00:00:09"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:09,dl_dst=10:00:00:00:00:0a,actions=set_field:00:00:00:00:00:0a"->"eth_dst,set_field:10:00:00:00:00:09"->"eth_src,IN_PORT
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:09,dl_dst=10:00:00:00:00:0b,actions=set_field:00:00:00:00:00:0b"->"eth_dst,set_field:10:00:00:00:00:09"->"eth_src,output:3
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:09,dl_dst=10:00:00:00:00:0c,actions=set_field:00:00:00:00:00:0c"->"eth_dst,set_field:10:00:00:00:00:09"->"eth_src,output:3

sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0a,dl_dst=10:00:00:00:00:01,actions=set_field:00:00:00:00:00:01"->"eth_dst,set_field:10:00:00:00:00:0a"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0a,dl_dst=10:00:00:00:00:02,actions=set_field:00:00:00:00:00:02"->"eth_dst,set_field:10:00:00:00:00:0a"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0a,dl_dst=10:00:00:00:00:03,actions=set_field:00:00:00:00:00:03"->"eth_dst,set_field:10:00:00:00:00:0a"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0a,dl_dst=10:00:00:00:00:04,actions=set_field:00:00:00:00:00:04"->"eth_dst,set_field:10:00:00:00:00:0a"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0a,dl_dst=10:00:00:00:00:05,actions=set_field:00:00:00:00:00:05"->"eth_dst,set_field:10:00:00:00:00:0a"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0a,dl_dst=10:00:00:00:00:06,actions=set_field:00:00:00:00:00:06"->"eth_dst,set_field:10:00:00:00:00:0a"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0a,dl_dst=10:00:00:00:00:07,actions=set_field:00:00:00:00:00:07"->"eth_dst,set_field:10:00:00:00:00:0a"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0a,dl_dst=10:00:00:00:00:08,actions=set_field:00:00:00:00:00:08"->"eth_dst,set_field:10:00:00:00:00:0a"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0a,dl_dst=10:00:00:00:00:09,actions=set_field:00:00:00:00:00:09"->"eth_dst,set_field:10:00:00:00:00:0a"->"eth_src,IN_PORT
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0a,dl_dst=10:00:00:00:00:0b,actions=set_field:00:00:00:00:00:0b"->"eth_dst,set_field:10:00:00:00:00:0a"->"eth_src,output:3
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0a,dl_dst=10:00:00:00:00:0c,actions=set_field:00:00:00:00:00:0c"->"eth_dst,set_field:10:00:00:00:00:0a"->"eth_src,output:3

sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0b,dl_dst=10:00:00:00:00:01,actions=set_field:00:00:00:00:00:01"->"eth_dst,set_field:10:00:00:00:00:0b"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0b,dl_dst=10:00:00:00:00:02,actions=set_field:00:00:00:00:00:02"->"eth_dst,set_field:10:00:00:00:00:0b"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0b,dl_dst=10:00:00:00:00:03,actions=set_field:00:00:00:00:00:03"->"eth_dst,set_field:10:00:00:00:00:0b"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0b,dl_dst=10:00:00:00:00:04,actions=set_field:00:00:00:00:00:04"->"eth_dst,set_field:10:00:00:00:00:0b"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0b,dl_dst=10:00:00:00:00:05,actions=set_field:00:00:00:00:00:05"->"eth_dst,set_field:10:00:00:00:00:0b"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0b,dl_dst=10:00:00:00:00:06,actions=set_field:00:00:00:00:00:06"->"eth_dst,set_field:10:00:00:00:00:0b"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0b,dl_dst=10:00:00:00:00:07,actions=set_field:00:00:00:00:00:07"->"eth_dst,set_field:10:00:00:00:00:0b"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0b,dl_dst=10:00:00:00:00:08,actions=set_field:00:00:00:00:00:08"->"eth_dst,set_field:10:00:00:00:00:0b"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0b,dl_dst=10:00:00:00:00:09,actions=set_field:00:00:00:00:00:09"->"eth_dst,set_field:10:00:00:00:00:0b"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0b,dl_dst=10:00:00:00:00:0a,actions=set_field:00:00:00:00:00:0a"->"eth_dst,set_field:10:00:00:00:00:0b"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0b,dl_dst=10:00:00:00:00:0c,actions=set_field:00:00:00:00:00:0c"->"eth_dst,set_field:10:00:00:00:00:0b"->"eth_src,IN_PORT

sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0c,dl_dst=10:00:00:00:00:01,actions=set_field:00:00:00:00:00:01"->"eth_dst,set_field:10:00:00:00:00:0c"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0c,dl_dst=10:00:00:00:00:02,actions=set_field:00:00:00:00:00:02"->"eth_dst,set_field:10:00:00:00:00:0c"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0c,dl_dst=10:00:00:00:00:03,actions=set_field:00:00:00:00:00:03"->"eth_dst,set_field:10:00:00:00:00:0c"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0c,dl_dst=10:00:00:00:00:04,actions=set_field:00:00:00:00:00:04"->"eth_dst,set_field:10:00:00:00:00:0c"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0c,dl_dst=10:00:00:00:00:05,actions=set_field:00:00:00:00:00:05"->"eth_dst,set_field:10:00:00:00:00:0c"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0c,dl_dst=10:00:00:00:00:06,actions=set_field:00:00:00:00:00:06"->"eth_dst,set_field:10:00:00:00:00:0c"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0c,dl_dst=10:00:00:00:00:07,actions=set_field:00:00:00:00:00:07"->"eth_dst,set_field:10:00:00:00:00:0c"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0c,dl_dst=10:00:00:00:00:08,actions=set_field:00:00:00:00:00:08"->"eth_dst,set_field:10:00:00:00:00:0c"->"eth_src,output:1
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0c,dl_dst=10:00:00:00:00:09,actions=set_field:00:00:00:00:00:09"->"eth_dst,set_field:10:00:00:00:00:0c"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0c,dl_dst=10:00:00:00:00:0a,actions=set_field:00:00:00:00:00:0a"->"eth_dst,set_field:10:00:00:00:00:0c"->"eth_src,output:2
sudo ovs-ofctl -O OpenFlow13 add-flow s4 dl_src=00:00:00:00:00:0c,dl_dst=10:00:00:00:00:0b,actions=set_field:00:00:00:00:00:0b"->"eth_dst,set_field:10:00:00:00:00:0c"->"eth_src,IN_PORT
