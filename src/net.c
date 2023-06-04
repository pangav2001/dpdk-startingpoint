#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_arp.h>

#include <base.h>

#define XDP_TX 3

void eth_in(struct rte_mbuf *pkt_buf, ubpf_jit_fn fn)
{
	uint64_t ubpf_ret;

	ubpf_ret = fn((void *)rte_pktmbuf_mtod(pkt_buf, void *), pkt_buf->pkt_len);
	if (ubpf_ret == XDP_TX) {
		dpdk_out(pkt_buf);
	}
	rte_pktmbuf_free(pkt_buf);
}