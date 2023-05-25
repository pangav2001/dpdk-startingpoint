#include <stdio.h>
#include <signal.h>

#include <rte_lcore.h>
#include <linux/if_ether.h>

#include <base.h>
#include <rte_malloc.h>

#define BUFFER_SIZE 1024
// #define FILE_PATH "/home/kali/Desktop/git/github/others/ubpf/eBPF/test_extern.o"
#define FILE_PATH "/home/kali/Desktop/git/github/others/ubpf/eBPF/firewall_test2.o"
#define max(a,b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b;       \
})

struct rte_hash_parameters ipv4_rules_params = {
	.name = "forbidden_src_ips",
	.entries = 10,
	.key_len = sizeof(struct in6_addr),
	.hash_func = rte_hash_crc,
	.hash_func_init_val = 0,
};
struct rte_hash_parameters dst_ips = {
	.name = "forbidden_dst_ips",
	.entries = 10,
	.key_len = sizeof(struct in6_addr),
	.hash_func = rte_hash_crc,
	.hash_func_init_val = 0,
};
struct rte_hash_parameters src_macs =
{
	.name = "forbidden_src_macs",
	.entries = 10,
	.key_len = sizeof(((struct ethhdr *)0)->h_source),
	.hash_func = rte_hash_crc,
	.hash_func_init_val = 0,
};
struct rte_hash_parameters dst_macs =
{
	.name = "forbidden_dst_macs",
	.entries = 10,
	.key_len = sizeof(((struct ethhdr *)0)->h_source),
	.hash_func = rte_hash_crc,
	.hash_func_init_val = 0,
};

struct rte_hash *forbidden_src_ips, *forbidden_dst_ips, *forbidden_src_macs, *forbidden_dst_macs;

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

static int my_external_function()
{
	// return ETH_P_ARP;
	return ETH_P_IPV6;
}

// static _Bool bpf_map_lookup_elem(const char* map_name, void* key)
// {
// 	if (strlen("forbidden_src_ips") == strlen(map_name) && strncmp("forbidden_src_ips", map_name, strlen("forbidden_src_ips")) == 0) {
// 		struct in6_addr *ip = (struct in6_addr*) key;
// 		int added;
// 		char to_add[] = "Interesting";
// 		if (forbidden_src_ips) {
// 			added = rte_hash_add_key_data(forbidden_src_ips, ip, &to_add);
// 			if (added >= 0)
// 			{
// 				int lookup;
// 				char *looked_up[15];
// 				lookup = rte_hash_lookup_data(forbidden_src_ips, ip, (void **) &looked_up);
// 				if (lookup >= 0) {
// 					printf("Found %s in hash table!\n", *looked_up);
// 				}
// 			}
// 		}
// 		char ipv6_addr[INET6_ADDRSTRLEN];
// 		inet_ntop(AF_INET6, ip, ipv6_addr, INET6_ADDRSTRLEN);
// 		printf("%s\n", ipv6_addr);
// 		return true;
// 	}
// 	if (strlen("forbidden_dst_ips") == strlen(map_name) && strncmp("forbidden_dst_ips", map_name, strlen("forbidden_dst_ips")) == 0) {
// 		struct in6_addr *ip = (struct in6_addr*) key;
// 		// int added;
// 		// int to_add = 69;
// 		// added = rte_hash_add_key_data(forbidden_src_ips, ip, &to_add);
// 		// if (added == 0)
// 		// {
// 		// 	int lookup;
// 		// 	int *looked_up;
// 		// 	lookup = rte_hash_lookup_data(forbidden_src_ips, ip, (void**) &looked_up);
// 		// 	if (lookup >= 0) {
// 		// 		printf("Found %d in hash table!\n", *looked_up);
// 		// 	}
// 		// }
// 		char ipv6_addr[INET6_ADDRSTRLEN];
// 		inet_ntop(AF_INET6, ip, ipv6_addr, INET6_ADDRSTRLEN);
// 		printf("%s\n", ipv6_addr);
// 		return true;
// 	}
// 	if (strlen("forbidden_src_macs") == strlen(map_name) && strncmp("forbidden_src_macs", map_name, strlen("forbidden_src_macs")) == 0) {
// 		unsigned char (*h_source)[] = (unsigned char(*)[]) key;
// 		printf("Source MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
//            (*h_source)[0], (*h_source)[1], (*h_source)[2],
//            (*h_source)[3], (*h_source)[4], (*h_source)[5]);
// 		return true;
// 	}
// 	if (strlen("forbidden_dst_macs") == strlen(map_name) && strncmp("forbidden_dst_macs", map_name, strlen("forbidden_dst_macs")) == 0) {
// 		unsigned char (*h_dest)[] = (unsigned char(*)[]) key;
// 		printf("Destination MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
//            (*h_dest)[0], (*h_dest)[1], (*h_dest)[2],
//            (*h_dest)[3], (*h_dest)[4], (*h_dest)[5]);
// 		return true;
// 	}
// 	return false;
// }

// static void* bpf_map_lookup_elem(void **map_name, void *key)
// {
// 	struct rte_hash *map = (struct rte_hash*) *map_name;
// 	int added;
// 	void *to_add = (void *) true;
// 	if (map) {
// 		added = rte_hash_add_key_data(map, key, &to_add);
// 		if (added >= 0)
// 		{
// 			int lookup;
// 			void *looked_up;
// 			lookup = rte_hash_lookup_data(map, key, &looked_up);
// 			return lookup >= 0 ? looked_up : NULL;
// 		}
// 	}
// 	return NULL;
// }

static void* bpf_map_lookup_elem(void **map_name, void *key)
{
		char ipv6_addr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, key, ipv6_addr, INET6_ADDRSTRLEN);
		printf("%s\n", ipv6_addr);
		// struct in6_addr *ip = (struct in6_addr*) key;
		struct rte_hash *map = (struct rte_hash*) *map_name;
		int added;
		char to_add[] = "Interesting";
		if (map) {
			added = rte_hash_add_key_data(map, key, &to_add);
			if (added >= 0)
			{
				int lookup;
				char *looked_up[15];
				lookup = rte_hash_lookup_data(map, key, (void **) &looked_up);
				if (lookup >= 0) {
					printf("Found %s in hash table!\n", *looked_up);
				}
			}
			return (void *) false;
		}
	return (void *) true;
}

const __be16 size = 3;
__be16 protocols[] = {size, ETH_P_IPV6, ETH_P_ARP};

static __be16* get_protocols()
{
	return protocols;
}

static void register_hash_tables(void **tables[])
{
	*(tables[0]) = forbidden_src_ips;
	*(tables[1]) = forbidden_dst_ips;
	*(tables[2]) = forbidden_src_macs;
	*(tables[3]) = forbidden_dst_macs;
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

	int reg = ubpf_register(vm, 0, "my_external_function", my_external_function);

	printf("Function registration returned: %d\n", reg);

	reg = ubpf_register(vm, 1, "bpf_map_lookup_elem", bpf_map_lookup_elem);

	printf("Function registration returned: %d\n", reg);

	reg = ubpf_register(vm, 2, "get_protocols", get_protocols);

	printf("Function registration returned: %d\n", reg);

	reg = ubpf_register(vm, 3, "register_hash_tables", register_hash_tables);

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
	struct rte_hash_names_params params_names = 
	{
		.params = {ipv4_rules_params, dst_ips, src_macs, dst_macs}, 
		.hash_tables = {&forbidden_src_ips, &forbidden_dst_ips, &forbidden_src_macs, &forbidden_dst_macs}
	};
	dpdk_init(&argc, &argv, &params_names);

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
