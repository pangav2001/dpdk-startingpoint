#include <stdio.h>
#include <stdlib.h>

#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_timer.h>

#include <config.h>
#include <base.h>

void convertMacAddress(const char* readableMac, unsigned char* hSource) {
    char hex[3] = {0};
    int i;

    for (i = 0; i < 6; ++i) {
        hex[0] = readableMac[i * 3];
        hex[1] = readableMac[i * 3 + 1];
        hSource[i] = (unsigned char)strtol(hex, NULL, 16);
    }
}

struct rte_mempool *pktmbuf_pool;

bool t = true;

void dpdk_init(int *argc, char ***argv, struct rte_hash_names_params *params_names, struct rte_lpm **lpm)
{
	int ret, nb_ports, i;
	uint8_t port_id = 0;
	uint16_t nb_rx_q;
	uint16_t nb_tx_q;
	uint16_t nb_tx_desc = ETH_DEV_TX_QUEUE_SZ;
	uint16_t nb_rx_desc = ETH_DEV_RX_QUEUE_SZ;
	struct rte_eth_link link;

	const struct rte_eth_conf port_conf = {
    .rxmode =
    {
      /* Disable next 2 fields for debugging on the tap interface */
      //.mtu = RTE_ETHER_MAX_LEN,
      //.offloads = DEV_RX_OFFLOAD_IPV4_CKSUM | DEV_RX_OFFLOAD_KEEP_CRC,
      .mq_mode = RTE_ETH_MQ_RX_RSS,
    },
    .rx_adv_conf =
    {
      .rss_conf =
      {
        .rss_hf =
          RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV4_UDP,
      },
    },
    .txmode =
    {
      .mq_mode = RTE_ETH_MQ_TX_NONE,
    },
  };
  	
	
	ret = rte_eal_init(*argc, *argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	*argc -= ret;
	*argv += ret;

	/* init RTE timer library */
	rte_timer_subsystem_init();

	/* create the mbuf pool */
	pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", NB_MBUF,
					       MEMPOOL_CACHE_SIZE, 0,
					       RTE_MBUF_DEFAULT_BUF_SIZE,
					       rte_socket_id());
	if (pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	printf("I found %" PRIu8 " ports\n", nb_ports);

	nb_rx_q = rte_lcore_count();
	nb_tx_q = nb_rx_q;

	/* Configure the device */
	ret = rte_eth_dev_configure(port_id, nb_rx_q, nb_tx_q, &port_conf);

	for (i = 0; i < nb_rx_q; i++) {
		printf("setting up RX queues...\n");
		ret = rte_eth_rx_queue_setup(port_id, i, nb_rx_desc,
					     rte_eth_dev_socket_id(port_id),
					     NULL, pktmbuf_pool);

		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_rx_queue_setup:err=%d, port=%u\n",
				 ret, (unsigned)port_id);
	}

	for (i = 0; i < nb_tx_q; i++) {
		printf("setting up TX queues...\n");
		ret = rte_eth_tx_queue_setup(port_id, i, nb_tx_desc,
					     rte_eth_dev_socket_id(port_id),
					     NULL);

		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				 ret, (unsigned)port_id);
	}

	/* start the device */
	ret = rte_eth_dev_start(port_id);
	if (ret < 0)
		printf("ERROR starting device at port %d\n", port_id);
	else
		printf("started device at port %d\n", port_id);

	/* check the link */
	rte_eth_link_get(port_id, &link);

	if (!link.link_status)
		printf("eth:\tlink appears to be down, check connection.\n");
	else
		printf("eth:\tlink up - speed %u Mbps, %s\n",
		       (uint32_t)link.link_speed,
		       (link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ?
			       ("full-duplex") :
			       ("half-duplex\n"));
	for (int i = 0; i < NUM_OF_HASH_TABLES; i++)
	{
		*(params_names->hash_tables[i]) = rte_hash_create(&(params_names->params[i]));
		if ((*params_names->hash_tables[i])) {
			printf("Ela mou!\n");
		}
		else {
			printf("Error is %s\n", rte_strerror(rte_errno));
		}
	}
	struct rte_lpm_config lpm_config;
	lpm_config.max_rules = 1024;
	lpm_config.number_tbl8s = 256;
	lpm_config.flags = 0;
	char name[] = "lpm_table";
	*lpm = rte_lpm_create(name, rte_socket_id(), &lpm_config);
	if (*lpm == NULL) {
		printf("Cannot create LPM table\n");
	}
	else {
		printf("Successfully created LPM table!\n");
	}
	// *forbidden_src_ips = rte_hash_create(ipv6_hash_table_params);
	// if (*forbidden_src_ips) {
	// 		printf("Ela mou!\n");
	// }
	// else {
	// 	printf("Error is %s\n", rte_strerror(rte_errno));
	// }
	const char* readableMac = "de:ad:be:ef:7b:15"; // Replace with your MAC address
    unsigned char hSource[6];

    convertMacAddress(readableMac, hSource);

    // printf("ethhdr->h_source: %02x:%02x:%02x:%02x:%02x:%02x\n",
    //        hSource[0], hSource[1], hSource[2], hSource[3], hSource[4], hSource[5]);
	// int added;
	// added = rte_hash_add_key_data(*(params_names->hash_tables[2]), hSource, (void *) &t);
	// printf("Added is: %d\n", added);
}

void dpdk_terminate(void)
{
	int8_t portid = 0;

	printf("Closing port %d...", portid);
	rte_eth_dev_stop(portid);
	rte_eth_dev_close(portid);
}

void dpdk_poll(ubpf_jit_fn fn)
{
	int ret = 0;
	struct rte_mbuf *rx_pkts[BATCH_SIZE];

	ret = rte_eth_rx_burst(0, RTE_PER_LCORE(queue_id), rx_pkts, BATCH_SIZE);
	if (!ret)
		return;

  printf("I received %d packet(s) on port %d of length %d.\n", ret, rx_pkts[0]->port, rx_pkts[0]->pkt_len);
	void *data = rte_pktmbuf_mtod(rx_pkts[0], void *);
	// uint32_t tmp;
	// void *data = rte_pktmbuf_read(rx_pkts[0], src_reg + imm32, sizeof(tmp), &tmp);
// Execute the eBPF program
	uint64_t ubpf_ret;
	
	// int rv = ubpf_exec(vm, data, RTE_MBUF_DEFAULT_BUF_SIZE, &ubpf_ret);
	// int rv = ubpf_exec(vm, (uint32_t*) rx_pkts[0]->buf_addr, rx_pkts[0]->pkt_len, &ubpf_ret);
	// int rv = ubpf_exec(vm, data, rx_pkts[0]->pkt_len, &ubpf_ret);
	ubpf_ret = fn(data, rx_pkts[0]->pkt_len);

  /* FIXME: Start your logic from here */
  printf("eBPF return status: %lu\n", ubpf_ret);
}

void dpdk_out(struct rte_mbuf *pkt)
{
	int ret = 0;

	while (1) {
		ret = rte_eth_tx_burst(0, RTE_PER_LCORE(queue_id), &pkt, 1);
		if (ret == 1)
			break;
	}
}
