#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helper_defs.h>
#include <bpf/bpf_endian.h>

#define SEC(NAME) __attribute__((section(NAME), used))
static unsigned REDIRECT_IFACE_IDX = 21;

SEC("xdp_redirect")
int xdp_redirect_func(struct xdp_md *ctx)
{
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        struct ethhdr *eth_hdr = data;
        unsigned int ethhdr_off = sizeof(*eth_hdr);
        struct iphdr *ip_hdr = data + ethhdr_off;
        unsigned int iphdr_off = sizeof(*ip_hdr);

        if (data + ethhdr_off + iphdr_off > data_end) {
                return XDP_DROP;
        }

        //if ((eth_hdr->h_proto != bpf_htons(ETH_P_IP)) || (ip_hdr->protocol != bpf_htons(0x11))) 
	if (eth_hdr->h_proto != bpf_htons(ETH_P_IP)) {
                return XDP_PASS;
        } else {
                bpf_xdp_adjust_head(ctx, ethhdr_off);
        }

        return bpf_redirect(REDIRECT_IFACE_IDX, 0);
}

char _license[] SEC("license") = "GPL";
