#pragma once

#include <rte_mbuf.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include "/home/pgavriil/git/ubpf/vm/inc/ubpf.h"

#define NUM_OF_HASH_TABLES 0
#define NUM_OF_LPM_TRIES 2
struct rte_hash_names_params
{
    struct rte_hash_parameters params[NUM_OF_HASH_TABLES];
    struct rte_hash **hash_tables[NUM_OF_HASH_TABLES];
};


/* DPDK functionality */
void dpdk_init(int *argc, char ***argv, struct rte_lpm **lpm4, struct rte_lpm6 **lpm6);
void dpdk_terminate(void);
// void dpdk_poll(ubpf_jit_fn fn);
void dpdk_poll(struct ubpf_vm *vm);
void dpdk_out(struct rte_mbuf *pkt);

RTE_DECLARE_PER_LCORE(int, queue_id);

/* net */
// void eth_in(struct rte_mbuf *pkt_buf, ubpf_jit_fn fn);
void eth_in(struct rte_mbuf *pkt_buf, struct ubpf_vm *vm);
