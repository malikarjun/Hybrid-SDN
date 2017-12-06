#!/usr/bin/python
import os, time


#random replacement of SDN switch
# combo = ['s9 s18']

#according to updated algo after conext submission
# combo = ['s14','s10 s18','s6 s14 s22','s6 s10 s14 s22','s6 s10 s14 s18 s22','s6 s10 s14 s15 s18 s22','s6 s10 s11 s14 s18 s19 s22','s6 s7 s10 s14 s15 s18 s22 s23','s6 s7 s10 s11 s14 s15 s18 s22 s23', 's6 s7 s10 s11 s14 s15 s18 s19 s22 s23','s6 s7 s10 s11 s14 s15 s16 s18 s19 s22 s23','s6 s7 s10 s11 s12 s14 s15 s18 s19 s20 s22 s23','s6 s7 s8 s10 s11 s14 s15 s16 s18 s19 s22 s23 s24','s6 s7 s8 s10 s11 s12 s14 s15 s16 s18 s19 s22 s23 s24','s6 s7 s8 s10 s11 s12 s14 s15 s16 s18 s19 s20 s22 s23 s24','s6 s7 s8 s10 s11 s12 s14 s15 s16 s17 s18 s19 s20 s22 s23 s24','s6 s7 s8 s10 s11 s12 s13 s14 s15 s16 s18 s19 s20 s21 s22 s23 s24','s6 s7 s8 s9 s10 s11 s12 s14 s15 s16 s17 s18 s19 s20 s22 s23 s24 s25','s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19 s20 s22 s23 s24 s25','s6 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19 s20 s21 s22 s23 s24 s25']
combo = [
    's14'
        ]


os.system('rm -r {}'.format(os.environ['HOME'] + '/prabodh/hybrid-sdn-thesis/analysis/*'))
for s in combo:
    for i in range(0,11):
        os.system('rm {}'.format(os.environ['HOME'] + '/prabodh/hybrid-sdn-thesis/stat/*'))

        os.system('python tree64-legacy.py -t -s {0} -f {1}'.format(s, i))
        try:
            os.system('python sniff.py -s {0} -f {1}'.format(s, i))
        except:
            print('sniff.py failed to execute')
            exit(0)



