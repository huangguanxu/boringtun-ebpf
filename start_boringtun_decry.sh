#!/bin/bash -e

ip address add 192.0.0.1/24 dev wg0
wg set wg0 private-key ./privatekey
wg set wg0 listen-port 51820
wg set wg0 peer V9W3guTto/1nNsNZrvkxOTL08i74nWc0zYJbUnMrFQE= allowed-ips 192.0.0.2/32,8.0.0.0/24,192.168.0.0/16,4.0.0.0/24 endpoint 192.168.3.1:51820
ip link set wg0 up
route add -host 8.0.0.1 dev ens785f0
ip neigh add 8.0.0.1 lladdr b4:96:91:b7:6b:c9 dev ens785f0 nud perm
