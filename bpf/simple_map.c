#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/in.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_tunnel.h>
#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include "bpf_api.h"

#ifndef __section
# define __section(x)  __attribute__((section(x), used))
#endif

enum {
        BPF_MAP_ID_MAP1,
        __BPF_MAP_ID_MAX,
#define BPF_MAP_ID_MAX  __BPF_MAP_ID_MAX
};

struct map_key {
	__u32 a;
	__u32 b;
};

struct map_entry {
	__u64 value_a;
	__u64 value_b;
};

struct bpf_elf_map __section("maps") map1 = {
        .type           =       BPF_MAP_TYPE_HASH,
        .id             =       BPF_MAP_ID_MAP1,
        .size_key       =       sizeof(struct map_key),
        .size_value     =       sizeof(struct map_entry),
        .max_elem       =       256,
};

__section("classifier")
int cls_main(struct __sk_buff *skb)
{
	// The current tests manipulate the map but don't attach the classifier so this does nothing.
	
	struct map_key key;
	struct map_entry *entry;

	// The eBPF verifier requries that the memory be initialized.
	key.a = 0;
	key.b = 0;

	// The following uses the map which is necessary for the loader to not error out.
	// Erroring out when the map isn't used is a design decision in the current loader.
        entry = map_lookup_elem(&map1, &key);

        return TC_ACT_UNSPEC;
}

char __license[] __section("license") = "GPL";
