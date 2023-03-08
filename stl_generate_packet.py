# T-rex traffic generator.: stl_generate_packet.py
# Description:
# Support 2 nodes, maximum support 1000000 streams.
#  - 253 streams sent in directions 0 --> 1 and 1 --> 0 at the same time.
#  - Packet: ETH / IP /
#  - Direction 0 --> 1:
#    - Source IP address range:      4.0.0.2 - 4.0.0.254
#    - Destination IP address range: 8.0.0.1
#  - Direction 1 --> 0:
#    - Source IP address range:      8.0.0.2 - 8.0.0.254
#    - Destination IP address range: 4.0.0.1

import sys
import time
import json
import stl_path
import argparse
from ast import Raise
from struct import pack
from trex.stl.api import *

def get_streams (pkt_size, port_num):
    s = list()

    for i in range(port_num):
        stream = list()
        src_str = "4.0.0." + str(i + 1)
        dst_str = "8.0.0." + str(i + 1)
        pkt_hdr = Ether()/IP(src = src_str, dst = dst_str, proto = 61)
        pkt_hdr.show()
        padding = (pkt_size - len(pkt_hdr)) * 'x'
        pkt_full = STLPktBuilder(pkt = pkt_hdr/padding)
        s_cur = STLStream( packet = pkt_full, mode = STLTXCont())
        stream.append(s_cur)
        s.extend(stream)

    return s

def ipv4_continuous (pkt_size, duration, port_num):

    port = list()
    for i in range(port_num):
        port.extend([i])
    rate = "100%"
    c = STLClient()
    passed = True

    try:
        # create two bursts and link them
        s = get_streams(pkt_size, port_num)

        # connect to server
        c.connect()

        # prepare ports
        c.reset(ports = port)
        c.set_port_attr(ports = port, promiscuous=True)
        c.remove_all_streams(ports = port)
        c.clear_stats()

        # add streams to ports
        stream_len = int((len(s)) / port_num)
        for i in port:
            start_idx = i * stream_len
            end_idx = (i + 1) * stream_len
            c.add_streams(s[start_idx : end_idx], ports = port[i])
            print("stream %d is ready\n" %(i))

        # start to transmit streams
        # wait for <duration> seconds and stop
        c.start(ports = port, mult = rate, duration = duration)
        time.sleep(duration)
        c.stop

        # collect the statistics and process warnings
        stats = c.get_stats()
        if c.get_warnings():
            for warning in c.get_warnings():
                print(warning)

        # finish transmitting and reset
        c.reset()

        # process statistics
        print(json.dumps(stats, indent=4, separators=(u",", u": ")))
        total_send = 0
        total_recv = 0
        total_lost = 0
        for i in range(port_num):
            send = stats[port[i]][u"opackets"]
            recv = stats[port[i]][u"ipackets"]
            lost = send - recv
            total_send += send
            total_recv += recv
            total_lost += lost
            print(f"port {i} sent {send} packets and received {recv} packets, lost {lost} packets\n")

    except STLError as e:
        passed = False
        print(e)

    finally:
        if c:
            c.disconnect()
        print(
            f"total_received={total_recv}; "
            f"total_sent={total_send}; "
            f"frame_loss={total_lost}; "
            f"target_duration={duration!r}; "
        )

    if passed and not c.get_warnings():
        tx_pps = stats['total']['tx_pps']/1000/1000
        tx_bps = stats['total']['tx_bps']/1000/1000/1000
        tx_bps_L1 = stats['total']['tx_bps_L1']/1000/1000/1000
        rx_pps = stats['total']['rx_pps']/1000/1000
        rx_bps = stats['total']['rx_bps']/1000/1000/1000
        rx_bps_L1 = stats['total']['rx_bps_L1']/1000/1000/1000

        print("\nAll Ports TX Throughput (Mpps) for %d Bytes : %.2f" %(pkt_size, tx_pps))
        print("All Ports TX_L1 Throughput (Gbps) for %d Bytes: %.2f" %(pkt_size, tx_bps_L1))
        print("All Ports TX Throughput (Gbps) for %d Bytes: %.2f" %(pkt_size, tx_bps))
        print("All Ports RX Throughput (Mpps) for %d Bytes: %.2f" %(pkt_size, rx_pps))
        print("All Ports RX Throughput (Gbps) for %d Bytes: %.2f" %(pkt_size, rx_bps))
        print("All Ports RX_L1 Throughput (Gbps) for %d Bytes: %.2f" %(pkt_size, rx_bps_L1))


        print("\nTest has passed :-)\n")
    else:
        print(passed)
        print("\nTest has failed :-(\n")


def main():
    parser = argparse.ArgumentParser(usage="""
    connect to TRex and send continuous of packets for BORINGTUN-DPDK test.
    examples
    stl_2n_ip4.py -s 64 -d 30 -p 4
    """)

    parser.add_argument("-s",
                        dest = "pkt_size",
                        help = "Packet size in bytes",
                        default = 64,
                        type = int,
                        )

    parser.add_argument('-d',
                        dest = "duration",
                        help = "Duration in second",
                        default = 30,
                        type = int,
                        )

    parser.add_argument(
                        '-p',
                        dest = "port_num",
                        help = "Port numbers",
                        default = 1,
                        type = int,
                        )

    args = parser.parse_args()
    ipv4_continuous (pkt_size = args.pkt_size,  duration = args.duration, port_num = args.port_num)

if __name__ == "__main__":
    main()
