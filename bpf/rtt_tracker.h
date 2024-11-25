/*
    A simple RTT tracker implemented using eBPF fentry hook to read RTT from TCP socket.
 */

#ifndef __RTT_TRACKER_H__
#define __RTT_TRACKER_H__

#include <bpf_tracing.h>
#include "utils.h"
#include "maps_definition.h"

static inline int rtt_lookup_and_update_flow(flow_id *id, u64 rtt) {
    additional_metrics *aggregate_flow = bpf_map_lookup_elem(&additional_flow_metrics, id);
    if (aggregate_flow != NULL) {
        if (aggregate_flow->flow_rtt < rtt) {
            aggregate_flow->flow_rtt = rtt;
        }
        long ret = bpf_map_update_elem(&additional_flow_metrics, id, aggregate_flow, BPF_ANY);
        if (trace_messages && ret != 0) {
            bpf_printk("error rtt updating flow %d\n", ret);
        }
        return 0;
    }
    return -1;
}

static inline int calculate_flow_rtt_tcp(struct sock *sk, struct sk_buff *skb) {
    if (!enable_rtt) {
        return 0;
    }

    u8 dscp = 0, protocol = 0;
    struct tcp_sock *ts;
    u16 family = 0;
    u64 rtt = 0;
    int ret = 0;
    flow_id id;
    __builtin_memset(&id, 0, sizeof(id));
    pkt_info pkt;
    __builtin_memset(&pkt, 0, sizeof(pkt));
    pkt.id = &id;

    pkt.if_index = BPF_CORE_READ(skb, skb_iif);
    // filter out TCP sockets with unknown or loopback interface
    if (pkt.if_index == 0 || pkt.if_index == 1) {
        return 0;
    }

    // read L2 info
    core_fill_in_l2(skb, &pkt, &family);

    // read L3 info
    core_fill_in_l3(skb, &pkt, family, &protocol, &dscp);

    if (protocol != IPPROTO_TCP) {
        return 0;
    }

    // read TCP info
    core_fill_in_tcp(skb, &pkt);

    // read TCP socket rtt and store it in nanoseconds
    ts = (struct tcp_sock *)(sk);
    rtt = BPF_CORE_READ(ts, srtt_us) >> 3;
    rtt *= 1000u;

    // check if this packet need to be filtered if filtering feature is enabled
    bool skip = check_and_do_flow_filtering(&pkt, 0);
    if (skip) {
        return 0;
    }

    // update flow with rtt info
    pkt.direction = INGRESS;
    ret = rtt_lookup_and_update_flow(pkt.id, rtt);
    if (ret == 0) {
        return 0;
    }

    additional_metrics new_flow = {
        .flow_rtt = rtt,
    };
    ret = bpf_map_update_elem(&additional_flow_metrics, &id, &new_flow, BPF_ANY);
    if (trace_messages && ret != 0) {
        bpf_printk("error rtt track creating flow %d\n", ret);
    }

    return 0;
}

SEC("fentry/tcp_rcv_established")
int BPF_PROG(tcp_rcv_fentry, struct sock *sk, struct sk_buff *skb) {
    if (sk == NULL || skb == NULL || do_sampling == 0) {
        return 0;
    }
    return calculate_flow_rtt_tcp(sk, skb);
}

SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_kprobe, struct sock *sk, struct sk_buff *skb) {
    if (sk == NULL || skb == NULL || do_sampling == 0) {
        return 0;
    }
    return calculate_flow_rtt_tcp(sk, skb);
}

#endif /* __RTT_TRACKER_H__ */
