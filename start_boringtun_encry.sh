#!/bin/bash -e

ip address add 192.0.0.2/24 dev wg0
wg set wg0 private-key ./privatekey
wg set wg0 listen-port 51820
wg set wg0 peer KPjuAHDTtk8UYC/6RCv68i0yFzidsdzRi7Yn2PbHtTo= allowed-ips 192.0.0.1/32,8.0.0.0/24,192.168.0.0/16,4.0.0.0/24 endpoint 192.168.3.2:51820
ip link set wg0 up
route add -host 8.0.0.1 dev wg0
