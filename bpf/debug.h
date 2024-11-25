/*
    Some debug utility
*/

#ifndef __DEBUG_H__
#define __DEBUG_H__

#include "utils.h"

static inline bool is_wanted_ipv4(u8 ip[IP_MAX_LEN], u8 want_ip[4]) {
    return ip[12] == want_ip[0] && ip[13] == want_ip[1] && ip[14] == want_ip[2] && ip[15] == want_ip[3];
}

static inline bool is_wanted_peers(u8 src_ip[IP_MAX_LEN],
                                   u8 dst_ip[IP_MAX_LEN],
                                   u8 want_client_ip[4],
                                   u8 want_server_ip[4],
                                   u8 want_service_ip[4]) {
    bool isClientServerRQ = is_wanted_ipv4(src_ip, want_client_ip) && is_wanted_ipv4(dst_ip, want_server_ip);
    bool isClientServiceRQ = is_wanted_ipv4(src_ip, want_client_ip) && is_wanted_ipv4(dst_ip, want_service_ip);
    bool isServerRS = is_wanted_ipv4(src_ip, want_server_ip) && is_wanted_ipv4(dst_ip, want_client_ip);
    bool isServiceRS = is_wanted_ipv4(src_ip, want_service_ip) && is_wanted_ipv4(dst_ip, want_client_ip);

    if (isClientServerRQ) {
        bpf_printk("----- DEBUG, pod to pod RQ -----\n");
    }
    if (isClientServiceRQ) {
        bpf_printk("----- DEBUG, pod to svc RQ -----\n");
    }
    if (isServerRS) {
        bpf_printk("----- DEBUG, pod to pod RS -----\n");
    }
    if (isServiceRS) {
        bpf_printk("----- DEBUG, svc to pod RS -----\n");
    }

    return isClientServerRQ || isClientServiceRQ || isServerRS || isServiceRS;
}

static inline void print_id_info(flow_id *id) {
    bpf_printk("src IP: %d.%d.%d.%d\n", id->src_ip[12], id->src_ip[13], id->src_ip[14], id->src_ip[15]);
    bpf_printk("src port: %d\n", id->src_port);
    bpf_printk("dst IP: %d.%d.%d.%d\n", id->dst_ip[12], id->dst_ip[13], id->dst_ip[14], id->dst_ip[15]);
    bpf_printk("dst port: %d\n", id->dst_port);
}

static inline void print_skb_info(struct __sk_buff *skb, u8 direction) {
    bpf_printk("if_index: %lu\n", skb->ifindex);
    bpf_printk("direction: %d\n", (int) direction);
    bpf_printk("mark: %lu\n", skb->mark);
    bpf_printk("skb_addr=%llu\n", skb);
    bpf_printk("skb_meta_addr=%llu\n", skb->data_meta);
    bpf_printk("skb_data_addr=%llu\n", skb->data);
    bpf_printk("hash=%lu\n", skb->hash);
    bpf_printk("tstamp=%llu\n", skb->tstamp);
}

#endif /* __DEBUG_H__ */
