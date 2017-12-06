
ip route add 10.0.1.0/24 dev s3-eth1 table 4 proto static scope link
ip route add 10.0.1.0/24 dev vlan31 table 9 proto static scope link
ip route add 10.0.2.0/24 dev vlan32 table 9 proto static scope link
ip route add 10.0.3.0/24 dev vlan33 table 9 proto static scope link
ip route add 10.0.4.0/24 dev vlan34 table 9 proto static scope link
ifconfig | grep "s[1-5]-eth[1-6]\|vlan.[12345]"|sed "s/-//"|sed "s/   Link encap:Ethernet  HWaddr//"|sed "s/  */=/" > macs
. $PWD/macs
for i in {1..4}; do for j in {1..20}; do for k in {1..5}; do for l in {1..4}; do
    sudo arp -s 10.0.$i.$j 10:00:00:00:00:01 -i s$k-eth$l; done; done; done;
done;


sudo ovs-ofctl -OOpenFlow13 add-flow s14 ip,priority=4,nw_dst=10.0.1.9,in_port=2,actions=strip_vlan,set_field:00:00:00:00:00:21"->"eth_dst,set_field:$vlan31"->"eth_src,IN_PORT
sudo ovs-ofctl -OOpenFlow13 add-flow s14 ip,priority=3,nw_dst=10.0.1.9,actions=strip_vlan,set_field:00:00:00:00:00:21"->"eth_dst,set_field:$vlan31"->"eth_src,output:2
sudo ovs-ofctl -OOpenFlow13 add-flow s14 ip,priority=4,nw_dst=10.0.1.10,in_port=2,actions=strip_vlan,set_field:00:00:00:00:00:22"->"eth_dst,set_field:$vlan31"->"eth_src,IN_PORT
sudo ovs-ofctl -OOpenFlow13 add-flow s14 ip,priority=3,nw_dst=10.0.1.10,actions=strip_vlan,set_field:00:00:00:00:00:22"->"eth_dst,set_field:$vlan31"->"eth_src,output:2
sudo ovs-ofctl -OOpenFlow13 add-flow s14 ip,priority=4,nw_dst=10.0.1.11,in_port=3,actions=strip_vlan,set_field:00:00:00:00:00:23"->"eth_dst,set_field:$vlan31"->"eth_src,IN_PORT
sudo ovs-ofctl -OOpenFlow13 add-flow s14 ip,priority=3,nw_dst=10.0.1.11,actions=strip_vlan,set_field:00:00:00:00:00:23"->"eth_dst,set_field:$vlan31"->"eth_src,output:3
sudo ovs-ofctl -OOpenFlow13 add-flow s14 ip,priority=4,nw_dst=10.0.1.12,in_port=3,actions=strip_vlan,set_field:00:00:00:00:00:24"->"eth_dst,set_field:$vlan31"->"eth_src,IN_PORT
sudo ovs-ofctl -OOpenFlow13 add-flow s14 ip,priority=3,nw_dst=10.0.1.12,actions=strip_vlan,set_field:00:00:00:00:00:24"->"eth_dst,set_field:$vlan31"->"eth_src,output:3
sudo ovs-ofctl -OOpenFlow13 add-flow s14 ip,priority=2,nw_src=10.0.1.0/24,in_port=5,actions=mod_vlan_vid:4,set_field:$vlan34"->"eth_dst,set_field:$s3eth1"->"eth_src,IN_PORT
sudo ovs-ofctl -OOpenFlow13 add-flow s14 ip,priority=2,nw_src=10.0.1.0/24,actions=mod_vlan_vid:4,set_field:$vlan34"->"eth_dst,set_field:$s3eth1"->"eth_src,output:5
sudo ovs-ofctl -OOpenFlow13 add-flow s14 ip,priority=2,nw_src=10.0.2.0/24,in_port=5,actions=mod_vlan_vid:1,set_field:$vlan31"->"eth_dst,set_field:$s3eth1"->"eth_src,IN_PORT
sudo ovs-ofctl -OOpenFlow13 add-flow s14 ip,priority=2,nw_src=10.0.2.0/24,actions=mod_vlan_vid:1,set_field:$vlan31"->"eth_dst,set_field:$s3eth1"->"eth_src,output:5
sudo ovs-ofctl -OOpenFlow13 add-flow s14 ip,priority=2,nw_src=10.0.3.0/24,in_port=5,actions=mod_vlan_vid:2,set_field:$vlan32"->"eth_dst,set_field:$s3eth1"->"eth_src,IN_PORT
sudo ovs-ofctl -OOpenFlow13 add-flow s14 ip,priority=2,nw_src=10.0.3.0/24,actions=mod_vlan_vid:2,set_field:$vlan32"->"eth_dst,set_field:$s3eth1"->"eth_src,output:5
sudo ovs-ofctl -OOpenFlow13 add-flow s14 ip,priority=2,nw_src=10.0.4.0/24,in_port=5,actions=mod_vlan_vid:3,set_field:$vlan33"->"eth_dst,set_field:$s3eth1"->"eth_src,IN_PORT
sudo ovs-ofctl -OOpenFlow13 add-flow s14 ip,priority=2,nw_src=10.0.4.0/24,actions=mod_vlan_vid:3,set_field:$vlan33"->"eth_dst,set_field:$s3eth1"->"eth_src,output:5