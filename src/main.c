#include <stdio.h>
#include <signal.h>

#include <rte_lcore.h>
#include <linux/if_ether.h>

#include <base.h>
#include <rte_malloc.h>

#define BUFFER_SIZE 1024
#define FILE_PATH "/home/pgavriil/git/ubpf/eBPF/standard_acl.o"
#define max(a,b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b;       \
})

struct rte_lpm *ipv4_rules_trie;
struct rte_lpm6 *ipv6_rules_trie;

static int read_binary_file(const char *filename, uint8_t **buf, size_t *len) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    off_t file_len = lseek(fd, 0, SEEK_END);
    if (file_len == (off_t) -1) {
        perror("lseek");
        close(fd);
        return -1;
    }

    *buf = malloc(file_len);
    if (!*buf) {
        perror("malloc");
        close(fd);
        return -1;
    }

    if (lseek(fd, 0, SEEK_SET) == (off_t) -1) {
        perror("lseek");
        free(*buf);
        close(fd);
        return -1;
    }

    ssize_t n = read(fd, *buf, file_len);
    if (n < 0 || n != file_len) {
        perror("read");
        free(*buf);
        close(fd);
        return -1;
    }

    close(fd);
    *len = n;

    return 0;
}

volatile bool force_quit;
RTE_DEFINE_PER_LCORE(int, queue_id);

static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
		       signum);
		force_quit = true;
	}
}

// static void* bpf_map_lookup_elem(void **map_name, void *key)
// {
// 	struct rte_hash *map = (struct rte_hash*) *map_name;
// 	if (map) {
// 		int lookup;
// 		void *looked_up;
// 		lookup = rte_hash_lookup_data(map, key, &looked_up);
// 		if (lookup >= 0)
// 			return looked_up;
// 	}
// 	return NULL;
// }
struct ipv4_lpm_key {
        __u32 prefixlen;
        __u32 data;
};
struct ipv6_lpm_key {
        __u32 prefixlen;
        struct in6_addr *data;
};
static void* bpf_map_lookup_elem(void **map_name, void *key)
{
	if ((struct rte_lpm*) *map_name == ipv4_rules_trie
		|| (struct rte_lpm6*) *map_name == ipv6_rules_trie) {
		int lookup;
		void *looked_up;
		if ((struct rte_lpm*) *map_name == ipv4_rules_trie)
		{
			struct ipv4_lpm_key *lpm_key = (struct ipv4_lpm_key*) key; 
			lookup = rte_lpm_lookup(*map_name, rte_be_to_cpu_32(lpm_key->data), &looked_up);
		}
		else if ((struct rte_lpm6*) *map_name == ipv6_rules_trie)
		{
			struct ipv6_lpm_key *lpm_key = (struct ipv6_lpm_key*) key; 
			lookup = rte_lpm6_lookup(*map_name, lpm_key->data->s6_addr, &looked_up);
		}
		if (lookup >= 0)
			return looked_up;
	}
	return NULL;
}

static void register_lpm_tries(void **tables[])
{
	*(tables[0]) = ipv4_rules_trie;
	*(tables[1]) = ipv6_rules_trie;
}

static int thread_main(void *arg)
{
	uint32_t thread_id = (int)(long)(arg);
  printf("Worker main\n");

  uint8_t *buf;
	size_t buf_len;

	if (read_binary_file(FILE_PATH, &buf, &buf_len
	) != 0) {
		fprintf(stderr, "Failed to read bytecode file\n");
		return 1;
	}

	struct ubpf_vm *vm = ubpf_create();
	if (!vm) {
		fprintf(stderr, "Failed to create uBPF VM\n");
		free(buf);
		return 1;
	}

	int reg = ubpf_register(vm, 0, "bpf_map_lookup_elem", bpf_map_lookup_elem);

	printf("Function registration returned: %d\n", reg);

	reg = ubpf_register(vm, 1, "register_lpm_tries", register_lpm_tries);

	printf("Function registration returned: %d\n", reg);

	char *errmsg;
	int rv = ubpf_load_elf(vm, buf, buf_len, &errmsg);
	if (rv < 0) {
		fprintf(stderr, "Failed to load eBPF bytecode: %s\n", errmsg);
		ubpf_destroy(vm);
		free(buf);
		return 1;
	}

	ubpf_jit_fn	fn = ubpf_compile(vm, &errmsg);

  /* Start plugging your logic here */
  while(!force_quit)
    dpdk_poll(fn);

	return 0;
}

int main(int argc, char **argv)
{
	int count, lcore_id, ret = 0;

	printf("Hello world\n");
	dpdk_init(&argc, &argv, &ipv4_rules_trie, &ipv6_rules_trie);
	struct in_addr buf;
	char addr[INET_ADDRSTRLEN] = "10.1.0.1";
	inet_pton(AF_INET, addr, &buf);
	uint32_t ip = ntohl(buf.s_addr);
	printf("IP is %u\n", ip);
	uint32_t next_hop = 1;
	ret = rte_lpm_add(ipv4_rules_trie, ip, 32, next_hop);
	if (ret < 0)
		printf("Failed to add rule to ipv4_rules_trie table\n");
	/* set signal handler for proper exiting */
	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Setup dispatcher workers communication rings */
	count = rte_lcore_count();
	printf("There are %d cores\n", count);

	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		rte_eal_remote_launch(thread_main, (void *)(long)count,
				      lcore_id);
		count++;
	}

	thread_main((void *)(long)0);

	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	dpdk_terminate();
	return ret;
}
