#!/bin/sh

INSTALL=$1
CFG=$INSTALL/etc/network/interfaces.d/60-ipv6dns.cfg

echo "iface eth0 inet6 auto" > $CFG
echo "        dns-nameservers 2001:4860:4860::8888 2001:4860:4860::8844" >> $CFG
