ip rule add lookup local pref 32765
ip rule del pref 0

for i in {1..100}; do ip rule del pref 0; done;
for i in {1..100}; do ip rule del pref 1; done;
for i in {1..100}; do ip rule del pref 2; done;
