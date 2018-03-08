#!/bin/sh
#/home/naushada/build_root/Pi3B/buildroot-2017.02.1/output/host/usr/bin
export LD_LIBRARY_PATH="/usr/local/mysql-8.0.3-rc/lib;/usr/local/openssl-1.1.0e/lib"
#./DHCP 127.0.0.1 3306 dhcp_db dhcpc dhcpc123 
./ACC 127.0.0.1 3306 .acc_db dhcpc dhcpc123 
#./DHCP 192.168.1.5 3306 dhcp_db dhcpc dhcpc123 
