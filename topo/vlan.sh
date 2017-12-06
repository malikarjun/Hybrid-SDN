
sudo ovs-vsctl add-port s3 vlan31 tag=1 -- set interface vlan31 type=internal
sudo ovs-vsctl add-port s3 vlan32 tag=2 -- set interface vlan32 type=internal
sudo ovs-vsctl add-port s3 vlan33 tag=3 -- set interface vlan33 type=internal
sudo ovs-vsctl add-port s3 vlan34 tag=4 -- set interface vlan34 type=internal
sudo ifconfig vlan31 10.0.1.252/24
sudo ifconfig vlan32 10.0.2.252/24
sudo ifconfig vlan33 10.0.3.252/24
sudo ifconfig vlan34 10.0.4.252/24