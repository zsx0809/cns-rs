#include <linux/types.h>
#include <linux/bpf.h>

#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef __uint
#define __uint(name, val) int (*name)[val]
#endif
#ifndef __type
#define __type(name, val) typeof(val) *name
#endif

// BPF helper prototypes
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *) 3;
static __u64 (*bpf_get_socket_cookie)(void *ctx) = (void *) 46;
static __u64 (*bpf_get_current_uid_gid)(void) = (void *) 15;

#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_ntohl(x) __builtin_bswap32(x)

// Socket Address Storage
struct orig_dst_val {
    __u16 family; // AF_INET = 2, AF_INET6 = 10
    __u16 port;   // network order
    union {
        __u32 ip4;    // network order
        __u32 ip6[4]; // network order
    };
};

// Client Tuple Key (Client Source IP + Port)
struct client_tuple_key {
    __u16 family;
    __u16 port;   // network order
    union {
        __u32 ip4;    // network order
        __u32 ip6[4]; // network order
    };
};

// Config map:
// key 0 -> proxy_port (__u32)
// key 1 -> proxy_gid  (__u32)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} cns_config_map SEC(".maps");

// Map 1: cookie -> original dst
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct orig_dst_val);
} cookie_dst_map SEC(".maps");

// Map 2: client_tuple -> original dst
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct client_tuple_key);
    __type(value, struct orig_dst_val);
} tuple_dst_map SEC(".maps");

SEC("cgroup/connect4")
int cns_connect4(struct bpf_sock_addr *ctx) {
    // 1. 放行自身 GID 流量
    __u32 k_gid = 1;
    __u32 *pgid = bpf_map_lookup_elem(&cns_config_map, &k_gid);
    __u32 cns_gid = pgid ? *pgid : 3004;
    __u64 cur_gid = bpf_get_current_uid_gid() >> 32;
    if (cur_gid == cns_gid) {
        return 1;
    }

    // 2. DNS (53) 直连放行铁律
    if (ctx->user_port == bpf_htons(53)) {
        return 1;
    }

    // 3. 读取本地代理端口
    __u32 k_port = 0;
    __u32 *pport = bpf_map_lookup_elem(&cns_config_map, &k_port);
    __u16 proxy_port = pport ? (__u16)*pport : 7750;

    // 4. 防回环：若目标已经是 127.0.0.1 且端口为代理端口则直接放行
    if (ctx->user_ip4 == 0x0100007f && ctx->user_port == bpf_htons(proxy_port)) {
        return 1;
    }

    // 5. 记录原始目标地址
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct orig_dst_val dst = {};
    dst.family = 2; // AF_INET
    dst.port = ctx->user_port;
    dst.ip4 = ctx->user_ip4;
    bpf_map_update_elem(&cookie_dst_map, &cookie, &dst, BPF_ANY);

    // 6. 重定向至 127.0.0.1:proxy_port
    ctx->user_ip4 = 0x0100007f;
    ctx->user_port = bpf_htons(proxy_port);
    return 1;
}

SEC("cgroup/connect6")
int cns_connect6(struct bpf_sock_addr *ctx) {
    // 1. 放行自身 GID 流量
    __u32 k_gid = 1;
    __u32 *pgid = bpf_map_lookup_elem(&cns_config_map, &k_gid);
    __u32 cns_gid = pgid ? *pgid : 3004;
    __u64 cur_gid = bpf_get_current_uid_gid() >> 32;
    if (cur_gid == cns_gid) {
        return 1;
    }

    // 2. DNS (53) 直连放行
    if (ctx->user_port == bpf_htons(53)) {
        return 1;
    }

    // 3. 读取本地代理端口
    __u32 k_port = 0;
    __u32 *pport = bpf_map_lookup_elem(&cns_config_map, &k_port);
    __u16 proxy_port = pport ? (__u16)*pport : 7750;

    // 4. 防回环：若目标已经是 ::1 且端口为代理端口则直接放行
    if (ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0 &&
        ctx->user_ip6[2] == 0 && ctx->user_ip6[3] == bpf_htonl(1) &&
        ctx->user_port == bpf_htons(proxy_port)) {
        return 1;
    }

    // 5. 记录原始 IPv6 目标地址
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct orig_dst_val dst = {};
    dst.family = 10; // AF_INET6
    dst.port = ctx->user_port;
    dst.ip6[0] = ctx->user_ip6[0];
    dst.ip6[1] = ctx->user_ip6[1];
    dst.ip6[2] = ctx->user_ip6[2];
    dst.ip6[3] = ctx->user_ip6[3];
    bpf_map_update_elem(&cookie_dst_map, &cookie, &dst, BPF_ANY);

    // 6. 重定向至 [::1]:proxy_port
    ctx->user_ip6[0] = 0;
    ctx->user_ip6[1] = 0;
    ctx->user_ip6[2] = 0;
    ctx->user_ip6[3] = bpf_htonl(1);
    ctx->user_port = bpf_htons(proxy_port);
    return 1;
}

SEC("sockops")
int cns_sockops(struct bpf_sock_ops *skops) {
    if (skops->op != BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        return 1;
    }

    __u64 cookie = bpf_get_socket_cookie(skops);
    struct orig_dst_val *pdst = bpf_map_lookup_elem(&cookie_dst_map, &cookie);
    if (!pdst) {
        return 1;
    }

    struct client_tuple_key tuple = {};
    tuple.family = (__u16)skops->family;
    tuple.port = bpf_htons((__u16)skops->local_port);

    if (skops->family == 2) { // AF_INET
        tuple.ip4 = skops->local_ip4;
    } else if (skops->family == 10) { // AF_INET6
        // 使用 volatile 单独读取，防止 clang 对 ctx 指针做优化加法运算
        __u32 w0 = skops->local_ip6[0];
        __u32 w1 = skops->local_ip6[1];
        __u32 w2 = skops->local_ip6[2];
        __u32 w3 = skops->local_ip6[3];
        tuple.ip6[0] = w0;
        tuple.ip6[1] = w1;
        tuple.ip6[2] = w2;
        tuple.ip6[3] = w3;
    }

    bpf_map_update_elem(&tuple_dst_map, &tuple, pdst, BPF_ANY);
    bpf_map_delete_elem(&cookie_dst_map, &cookie);
    return 1;
}

char _license[] SEC("license") = "GPL";
