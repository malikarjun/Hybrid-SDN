#!/usr/bin/python
import os

os.system('sudo mn -c')
os.system('sudo stop network-manager')

#combo = ['s14','s14 s18','s10 s14 s18','s6 s10 s14 s18','s6 s10 s14 s18 s22','s6 s10 s14 s16 s18 s22','s6 s10 s14 s16 s18 s20 s22','s6 s10 s12 s14 s16 s18 s20 s22','s6 s8 s10 s12 s14 s16 s18 s20 s22','s6 s8 s10 s12 s14 s16 s18 s20 s22 s24','s6 s8 s10 s12 s14 s15 s16 s18 s20 s22 s24','s6 s8 s10 s12 s14 s15 s16 s18 s19 s20 s22 s24','s6 s8 s10 s11 s12 s14 s15 s16 s18 s19 s20 s22 s24','s6 s7 s8 s10 s11 s12 s14 s15 s16 s18 s19 s20 s22 s24','s6 s7 s8 s10 s11 s12 s14 s15 s16 s18 s19 s20 s22 s23 s24','s6 s7 s8 s10 s11 s12 s14 s15 s16 s17 s18 s19 s20 s22 s23 s24','s6 s7 s8 s10 s11 s12 s14 s15 s16 s17 s18 s19 s20 s21 s22 s23 s24','s6 s7 s8 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19 s20 s21 s22 s23 s24','s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19 s20 s21 s22 s23 s24','s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19 s20 s21 s22 s23 s24 s25']

#random replacement of SDN switch
combo = ['s6']
combo = ['s9 s18']
# combo = ['s6 s10 s14 s18','s6 s10 s14 s18 s22','s6 s7 s10 s14 s18 s22','s6 s7 s10 s11 s14 s18 s22','s6 s7 s10 s11 s14 s15 s18 s22','s6 s7 s10 s11 s14 s15 s18 s19 s22','s6 s7 s10 s11 s14 s15 s18 s19 s22 s23','s6 s7 s8 s10 s11 s14 s15 s18 s19 s22 s23','s6 s7 s8 s10 s11 s12 s14 s15 s18 s19 s22 s23','s6 s7 s8 s10 s11 s12 s14 s15 s16 s18 s19 s22 s23','s6 s7 s8 s10 s11 s12 s14 s15 s16 s18 s19 s20 s22 s23','s6 s7 s8 s10 s11 s12 s14 s15 s16 s18 s19 s20 s22 s23 s24','s6 s7 s8 s9 s10 s11 s12 s14 s15 s16 s18 s19 s20 s22 s23 s24','s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s18 s19 s20 s22 s23 s24','s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19 s20 s22 s23 s24','s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19 s20 s21 s22 s23 s24','s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19 s20 s21 s22 s23 s24 s25']

#combo = ['s14','s6 s14','s6 s14 s22','s6 s10 s14 s22','s6 s10 s14 s18 s22','s6 s10 s14 s16 s18 s22','s6 s8 s10 s14 s16 s18 s22','s6 s8 s10 s14 s16 s18 s22 s24','s6 s8 s10 s12 s14 s16 s18 s22 s24','s6 s8 s10 s12 s14 s16 s18 s20 s22 s24','s6 s8 s10 s12 s14 s15 s16 s18 s20 s22 s24','s6 s7 s8 s10 s12 s14 s15 s16 s18 s20 s22 s24','s6 s7 s8 s10 s12 s14 s15 s16 s18 s20 s22 s23 s24','s6 s7 s8 s10 s11 s12 s14 s15 s16 s18 s20 s22 s23 s24','s6 s7 s8 s10 s11 s12 s14 s15 s16 s18 s19 s20 s22 s23 s24','s6 s7 s8 s10 s11 s12 s14 s15 s16 s17 s18 s19 s20 s22 s23 s24','s6 s7 s8 s9 s10 s11 s12 s14 s15 s16 s17 s18 s19 s20 s22 s23 s24','s6 s7 s8 s9 s10 s11 s12 s14 s15 s16 s17 s18 s19 s20 s22 s23 s24 s25','s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19 s20 s22 s23 s24 s25','s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19 s20 s22 s21 s23 s24 s25']

#according to updated algo after conext submission
#combo = ['s14','s10 s18','s6 s14 s22','s6 s10 s14 s22','s6 s10 s14 s18 s22','s6 s10 s14 s15 s18 s22','s10 s11 s14 s18 s19 s22','s6 s7 s10 s14 s15 s18 s22 s23','s6 s7 s10 s11 s14 s15 s18 s22 s23', 's6 s7 s10 s11 s14 s15 s18 s19 s22 s23','s6 s7 s10 s11 s14 s15 s16 s18 s19 s22 s23','s6 s7 s10 s11 s12 s14 s15 s18 s19 s20 s22 s23','s6 s7 s8 s10 s11 s14 s15 s16 s18 s19 s22 s23 s24','s6 s7 s8 s10 s11 s12 s14 s15 s16 s18 s19 s22 s23 s24','s6 s7 s8 s10 s11 s12 s14 s15 s16 s18 s19 s20 s22 s23 s24','s6 s7 s8 s10 s11 s12 s14 s15 s16 s17 s18 s19 s20 s22 s23 s24','s6 s7 s8 s10 s11 s12 s13 s14 s15 s16 s18 s19 s20 s21 s22 s23 s24','s6 s7 s8 s9 s10 s11 s12 s14 s15 s16 s17 s18 s19 s20 s22 s23 s24 s25','s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19 s20 s22 s23 s24 s25','s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19 s20 s21 s22 s23 s24 s25']

for s in combo:



    os.system('python tree64-legacy.py -t -s {0}'.format(s))
    os.system('cd $HOME/prabodh/hybrid-sdn-thesis/stat/ && ls -1 | grep "vlan\|s[0-9]\+-" | while read var; do sudo tcpdump -eqns 0 -X -r $var > s$var; rm -f $var; done')
    os.system('pwd')
    os.system('python parser.py {0} >> $HOME/prabodh/hybrid-sdn-thesis/stat/pack_info'.format(s.replace(' ',',')))
    os.system('cp -r $HOME/prabodh/hybrid-sdn-thesis/stat $HOME/prabodh/hybrid-sdn-thesis/stat'+s.replace(' ',','))
    os.system('pwd')
    # os.system('cd $HOME/prabodh/hybrid-sdn-thesis/stat/ && ls -1 | grep "log" | while read var; do rm -vf $var; done')
    # os.system('cd $HOME/prabodh/hybrid-sdn-thesis/stat/ && ls -1 | grep "vlan\|s[0-9]\+-" | while read var; do sudo rm $var; done')
