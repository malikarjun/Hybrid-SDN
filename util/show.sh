#!/usr/bin/env bash

sudo ovs-appctl fdb/show s1
sudo ovs-appctl fdb/show s2
sudo ovs-appctl fdb/show s3
sudo ovs-appctl fdb/show s4
sudo ovs-appctl fdb/show s5
sudo ovs-appctl fdb/show s6
sudo ovs-appctl fdb/show s7
sudo ovs-appctl fdb/show s8
sudo ovs-appctl fdb/show s9
sudo ovs-ofctl dump-flows s2 -O OpenFlow13
sudo ovs-ofctl dump-flows s3 -O OpenFlow13
sudo ovs-ofctl dump-flows s4 -O OpenFlow13
sudo ovs-ofctl dump-flows s5 -O OpenFlow13
