#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/if.h>
#include <bpf/bpf_helper_defs.h>
#include <bpf/bpf_endian.h>
#include <bpf/xsk.h>
#include <bpf/libbpf.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#define NUM_FRAMES (4 * 1024)
#define XSK_UMEM__DEFAULT_FRAME_SHIFT 12 /* 4k bytes */
#define XSK_UMEM__DEFAULT_FRAME_SIZE (1 << XSK_UMEM__DEFAULT_FRAME_SHIFT)

#ifndef XSK_RING_PROD__DEFAULT_NUM_DESCS
#define XSK_RING_PROD__DEFAULT_NUM_DESCS 2048
#endif

#ifndef XSK_RING_CONS__DEFAULT_NUM_DESCS
#define XSK_RING_CONS__DEFAULT_NUM_DESCS 2048
#endif

#ifndef XSK_UMEM__DEFAULT_FRAME_HEADROOM
#define XSK_UMEM__DEFAULT_FRAME_HEADROOM 0
#endif

#ifndef MAX_SOCKS
#define MAX_SOCKS 4
#endif

#define ETH_HDR_SIZE (sizeof(struct ethhdr))
#define IP_HDR_SIZE (sizeof(struct iphdr))
#define UDP_HDR_SIZE (sizeof(struct udphdr))
#define PACKET_HDR_SIZE (ETH_HDR_SIZE + IP_HDR_SIZE + UDP_HDR_SIZE)

#define DEFINE_XSK_RING(name) \
struct name { \
        __u32 cached_prod; \
        __u32 cached_cons; \
        __u32 mask; \
        __u32 size; \
        __u32 *producer; \
        __u32 *consumer; \
        void *ring; \
        __u32 *flags; \
}

// DEFINE_XSK_RING(xsk_ring_prod);
// DEFINE_XSK_RING(xsk_ring_cons);

//struct xsk_umem_config {
//        __u32 fill_size;
//        __u32 comp_size;
//        __u32 frame_size;
//        __u32 frame_headroom;
//        __u32 flags;
//};
struct xsk_umem {
        struct xsk_ring_prod *fill_save;
        struct xsk_ring_cons *comp_save;
        char *umem_area;
        struct xsk_umem_config config;
        int fd;
        int refcount;
        struct list_head *ctx_list;
        bool rx_ring_setup_done;
        bool tx_ring_setup_done;
};
struct xsk_umem_info {
        struct xsk_ring_prod fq;
        struct xsk_ring_cons cq;
        struct xsk_umem *umem;
        void *buffer;
};

//struct xsk_socket_config {
//        __u32 rx_size;
//        __u32 tx_size;
//       __u32 libbpf_flags;
//        __u32 xdp_flags;
//        __u16 bind_flags;
//};
struct xsk_socket_info {
        struct xsk_ring_cons rx;
        struct xsk_ring_prod tx;
        struct xsk_umem_info *umem;
        struct xsk_socket *xsk;
};

struct packet_info {
        void *data;
        unsigned int packet_len;
        unsigned char src_mac[ETH_ALEN];
        unsigned char dst_mac[ETH_ALEN];
        unsigned int src_ip;
        unsigned int dst_ip;
        unsigned int src_port;
        unsigned int dst_port;
};

struct xsk_socket_info *xsks[MAX_SOCKS];

static void *memset32_htonl(void *dest, __u32 val, __u32 size)
{
        __u32 *ptr = (__u32 *)dest;
        __u32 i;

        val = htonl(val);

        for (i = 0; i < (size & (~0x3)); i += 4)
                ptr[i >> 2] = val;

        for (; i < size; i++)
                ((char *)dest)[i] = ((char *)&val)[i & 3];

        return dest;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline unsigned short from32to16(unsigned int x)
{
        /* add up 16-bit and 16-bit for 16+c bit */
        x = (x & 0xffff) + (x >> 16);
        /* add up carry.. */
        x = (x & 0xffff) + (x >> 16);
        return x;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static unsigned int do_csum(const unsigned char *buff, int len)
{
        unsigned int result = 0;
        int odd;

        if (len <= 0)
                goto out;
        odd = 1 & (unsigned long)buff;
        if (odd) {
#ifdef __LITTLE_ENDIAN
                result += (*buff << 8);
#else
                result = *buff;
#endif
                len--;
                buff++;
        }
        if (len >= 2) {
                if (2 & (unsigned long)buff) {
                        result += *(unsigned short *)buff;
                        len -= 2;
                        buff += 2;
                }
                if (len >= 4) {
                        const unsigned char *end = buff +
                                                   ((unsigned int)len & ~3);
                        unsigned int carry = 0;

                        do {
                                unsigned int w = *(unsigned int *)buff;

                                buff += 4;
                                result += carry;
                                result += w;
                                carry = (w > result);
                        } while (buff < end);
                        result += carry;
                        result = (result & 0xffff) + (result >> 16);
                }
                if (len & 2) {
                        result += *(unsigned short *)buff;
                        buff += 2;
                }
        }
        if (len & 1)
#ifdef __LITTLE_ENDIAN
                result += *buff;
#else
                result += (*buff << 8);
#endif
        result = from32to16(result);
        if (odd)
                result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
        return result;
}

/*
 *      This is a version of ip_compute_csum() optimized for IP headers,
 *      which always checksum on 4 octet boundaries.
 *      This function code has been taken from
 *      Linux kernel lib/checksum.c
 */
static inline __sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
        return (__sum16)~do_csum(iph, ihl * 4);
}

/*
 * Fold a partial checksum
 * This function code has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
static inline __sum16 csum_fold(__wsum csum)
{
        __u32 sum = (__u32)csum;

        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        return (__sum16)~sum;
}

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
static inline __u32 from64to32(__u64 x)
{
        /* add up 32-bit and 32-bit for 32+c bit */
        x = (x & 0xffffffff) + (x >> 32);
        /* add up carry.. */
        x = (x & 0xffffffff) + (x >> 32);
        return (__u32)x;
}

__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
                          __u32 len, __u8 proto, __wsum sum);

/*
 * This function code has been taken from
 * Linux kernel lib/checksum.c
 */
__wsum csum_tcpudp_nofold(__be32 saddr, __be32 daddr,
                          __u32 len, __u8 proto, __wsum sum)
{
        unsigned long long s = (__u32)sum;

        s += (__u32)saddr;
        s += (__u32)daddr;
#ifdef __BIG_ENDIAN__
        s += proto + len;
#else
        s += (proto + len) << 8;
#endif
        return (__wsum)from64to32(s);
}

/*
 * This function has been taken from
 * Linux kernel include/asm-generic/checksum.h
 */
static inline __sum16
csum_tcpudp_magic(__be32 saddr, __be32 daddr, __u32 len,
                  __u8 proto, __wsum sum)
{
        return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

static inline __u16 udp_csum(__u32 saddr, __u32 daddr, __u32 len,
                           __u8 proto, __u16 *udp_pkt)
{
        __u32 csum = 0;
        __u32 cnt = 0;

        /* udp hdr and data */
        for (; cnt < len; cnt += 2)
                csum += udp_pkt[cnt >> 1];

        return csum_tcpudp_magic(saddr, daddr, len, proto, csum);
}

static void gen_eth_hdr_data(struct packet_info *packet)
{
        struct udphdr *udp_hdr = (struct udphdr *)(packet->data +
                                                   ETH_HDR_SIZE +
                                                   IP_HDR_SIZE);
        struct iphdr *ip_hdr = (struct iphdr *)(packet->data +
                                                ETH_HDR_SIZE);
        struct ethhdr *eth_hdr = (struct ethhdr *)packet->data;

        /* ethernet header */
        memcpy(eth_hdr->h_dest, packet->dst_mac, ETH_ALEN);
        memcpy(eth_hdr->h_source, packet->src_mac, ETH_ALEN);
        eth_hdr->h_proto = htons(ETH_P_IP);

        for (int i = 0; i < ETH_ALEN; i ++) {
                printf("eth_hdr->dest[%d] = %x, eth_hdr->src[%d] = %x\n", i, eth_hdr->h_dest[i], i, eth_hdr->h_source[i]);
        }

        /* IP header */
        ip_hdr->version = IPVERSION;
        ip_hdr->ihl = 0x5; /* 20 byte header */
        ip_hdr->tos = 0x0;
        ip_hdr->tot_len = htons(packet->packet_len + UDP_HDR_SIZE + IP_HDR_SIZE);
        ip_hdr->id = 0;
        ip_hdr->frag_off = 0;
        ip_hdr->ttl = IPDEFTTL;
        ip_hdr->protocol = IPPROTO_UDP;
        //ip_hdr->saddr = inet_addr("192.168.3.1");;
        //ip_hdr->daddr = inet_addr("192.168.3.2");;
        ip_hdr->saddr = htonl(packet->src_ip);
        ip_hdr->daddr = htonl(packet->dst_ip);

        /* IP header checksum */
        ip_hdr->check = 0;
        ip_hdr->check = ip_fast_csum((const void *)ip_hdr, ip_hdr->ihl);

        /* UDP header */
        udp_hdr->source = packet->src_port;
        udp_hdr->dest = packet->dst_port
        //udp_hdr->source = htons(packet->src_port);
        //udp_hdr->dest = htons(packet->dst_port);
        udp_hdr->len = htons(packet->packet_len + sizeof(struct udphdr));

        /* UDP header checksum */
        udp_hdr->check = 0;
        udp_hdr->check = udp_csum(ip_hdr->saddr, ip_hdr->daddr, packet->packet_len + UDP_HDR_SIZE,
                                  IPPROTO_UDP, (unsigned short *)udp_hdr);

        printf("src_mac = %x, dst_mac = %x\n", eth_hdr->h_source, eth_hdr->h_dest);
        printf("src_mac = %x, dst_mac = %x\n", packet->src_mac, packet->dst_mac);
        printf("src_ip = %d, dst_ip = %d\n", ip_hdr->saddr, ip_hdr->daddr);
        printf("src_port = %d, dst_port = %d\n", udp_hdr->source, udp_hdr->dest);
}

static void gen_eth_frame(struct xsk_umem_info *umem, unsigned long addr, struct packet_info *packet)
{
        memcpy(xsk_umem__get_data(umem->buffer, addr), packet->data,
               packet->packet_len + UDP_HDR_SIZE + IP_HDR_SIZE + ETH_HDR_SIZE);
}

static struct xsk_umem_info *xdp_configure_umem(void *buffer, unsigned long size)
{
        struct xsk_umem_info *umem;
        struct xsk_umem_config cfg = {
                /* We recommend that you set the fill ring size >= HW RX ring size +
                 * AF_XDP RX ring size. Make sure you fill up the fill ring
                 * with buffers at regular intervals, and you will with this setting
                 * avoid allocation failures in the driver. These are usually quite
                 * expensive since drivers have not been written to assume that
                 * allocation failures are common. For regular sockets, kernel
                 * allocated memory is used that only runs out in OOM situations
                 * that should be rare.
                 */
                .fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS * 2,
                .comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
                .frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE,
                .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
                .flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG
        };
        int ret;

        umem = calloc(1, sizeof(*umem));
        if (!umem) {
		printf("Error when allocate memory for umem.\n");
		exit(EXIT_FAILURE);
	}

        ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
                               &cfg);
        if (ret) {
		printf("Error when create umem.\n");
		exit(EXIT_FAILURE);
	} else {
                printf("Create umem successfully.\n");
        }

        umem->buffer = buffer;
        return umem;
}

/*
 * @fn int xdp_create_umem(
 *       int frame_size,
 *       int frame_cnt);
 * function: create buf for umem,
 *           configure umem
 */
static struct xsk_umem_info *xdp_create_umem(int frame_size, int frame_cnt) {
        void *bufs;
        struct xsk_umem_info *umem;

        /* Reserve memory for UMEM */
        bufs = mmap(NULL, frame_cnt * frame_size,
                PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (bufs == MAP_FAILED) {
                printf("ERROR: reserve umem failed, mmap failed\n");
                exit(EXIT_FAILURE);
        } else {
                printf("Create buf successfully.\n");
        }

        /* Configure UMEM */
        umem = xdp_configure_umem(bufs, frame_cnt * frame_size);

        return umem;
}

/*
 * @fn int xdp_configure_socket(
 *       const char iface_name,
 *       int queue_id,
 *       struct xsk_umem_info *umem,
 *       bool rx,
 *       bool tx);
 * function: create XDP socket
 */
static struct xsk_socket_info *xdp_configure_socket(const char *iface_name, int queue_id, struct xsk_umem_info *umem, bool rx, bool tx) {
        struct xsk_socket_config cfg;
        struct xsk_socket_info *xsk;
        struct xsk_ring_cons *rxr;
        struct xsk_ring_prod *txr;
        int ret;

        xsk = calloc(1, sizeof(*xsk));
        if (!xsk) {
                printf("Initialize xsk socket config failed!\n");
                exit(EXIT_FAILURE);
        }
        xsk->umem = umem;

        cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
        cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
        cfg.libbpf_flags = 0;
        cfg.xdp_flags = XDP_FLAGS_DRV_MODE; // or XDP_FLAGS_SKB_MODE
        cfg.bind_flags = XDP_COPY;

        rxr = rx ? &xsk->rx : NULL;
        txr = tx ? &xsk->tx : NULL;
        printf("Start to create socket.\n");
        printf("xsk_socket_config: rx_size = %d, tx_size = %d, libbpf_flags = %d, xdp_flags = %d, bind_flags = %d\n", cfg.rx_size, cfg.tx_size, cfg.libbpf_flags, cfg.xdp_flags, cfg.bind_flags);
        printf("interface = %s, queue_id = %d\n", iface_name, queue_id);
        ret = xsk_socket__create(&xsk->xsk, iface_name, queue_id, umem->umem,
                                 rxr, txr, &cfg);
        if (ret) {
		printf("Error when create xsk socket.\n");
		exit(EXIT_FAILURE);
	} else {
                printf("Create XDP socket successfully.\n");
        }
        
        return xsk;
}

/*
 * @fn int xdp_send_packet(
 *       struct xsk_socket_info *xsk,
 *       struct packet_info *packet,
 *       struct xsk_umem_info *umem);
 * function: send packet via XDP socket
 */
static void xdp_send_packet(struct xsk_socket_info *xsk, struct packet_info *packet, struct xsk_umem_info *umem) {
        unsigned int idx;

        while (xsk_ring_prod__reserve(&xsk->tx, 1, &idx) < 1) {
                continue;
        }
        struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, idx);
        tx_desc->addr = XSK_UMEM__DEFAULT_FRAME_SIZE * idx;
        tx_desc->len = packet->packet_len + UDP_HDR_SIZE + IP_HDR_SIZE + ETH_HDR_SIZE;

        gen_eth_hdr_data(packet);
        gen_eth_frame(umem, tx_desc->addr, packet);

        //xsk_ring_prod__submit(&xsk->tx, 1);
}

int main() {
	struct xsk_umem_info *umem;
	bool rx = false, tx = true;
	char bufs[1024];
	int i, ret;
	struct xsk_socket_info *xdp_sock;
	struct packet_info *packet;

	umem = xdp_create_umem(2048, 1024);
	xdp_sock = xdp_configure_socket("ens785f1", 23, umem, rx, tx);

	memset(bufs, 0, sizeof(bufs));
	packet->data = &bufs;
        packet->packet_len = 970;
	memcpy(packet->src_mac, "\xb4\x96\x91\xd9\xdb\x11", ETH_ALEN);
	memcpy(packet->dst_mac, "\xb4\x96\x91\xd5\xbf\x49", ETH_ALEN);
	packet->src_ip = 0xc0a80301;
	packet->dst_ip = 0xc0a80302;
	packet->src_port = 0x1f98;
	packet->dst_port = 0x1f98;

        printf("Start to send packet.\n");
	for (i = 0; i < 1; i ++) {
		xdp_send_packet(xdp_sock, packet, umem);
	}
	return 0;
}
