/*
    Packet Drops using trace points.
*/

#ifndef __PKT_DROPS_H__
#define __PKT_DROPS_H__

#include "utils.h"

static inline long pkt_drop_lookup_and_update_flow(flow_id *id, u8 state, u16 flags,
                                                   enum skb_drop_reason reason, u64 len) {
    additional_metrics *aggregate_flow = bpf_map_lookup_elem(&additional_flow_metrics, id);
    if (aggregate_flow != NULL) {
        aggregate_flow->pkt_drops.packets += 1;
        aggregate_flow->pkt_drops.bytes += len;
        aggregate_flow->pkt_drops.latest_state = state;
        aggregate_flow->pkt_drops.latest_flags = flags;
        aggregate_flow->pkt_drops.latest_drop_cause = reason;
        long ret = bpf_map_update_elem(&additional_flow_metrics, id, aggregate_flow, BPF_EXIST);
        if (trace_messages && ret != 0) {
            bpf_printk("error packet drop updating flow %d\n", ret);
        }
        return 0;
    }
    return -1;
}

static inline int trace_pkt_drop(void *ctx, u8 state, struct sk_buff *skb,
                                 enum skb_drop_reason reason) {
    flow_id id;
    __builtin_memset(&id, 0, sizeof(id));
    pkt_info pkt;
    __builtin_memset(&pkt, 0, sizeof(pkt));
    pkt.id = &id;

    u8 protocol = 0, dscp = 0;
    u16 family = 0, flags = 0;

    u32 if_index = BPF_CORE_READ(skb, skb_iif);
    // filter out TCP sockets with unknown or loopback interface
    if (if_index == 0 || if_index == 1) {
        return 0;
    }
    // read L2 info
    core_fill_in_l2(skb, &pkt, &family);

    // read L3 info
    core_fill_in_l3(skb, &pkt, family, &protocol, &dscp);

    // read L4 info
    switch (protocol) {
    case IPPROTO_TCP:
        core_fill_in_tcp(skb, &pkt);
        break;
    case IPPROTO_UDP:
        core_fill_in_udp(skb, &pkt);
        break;
    case IPPROTO_SCTP:
        core_fill_in_sctp(skb, &pkt);
        break;
    case IPPROTO_ICMP:
        core_fill_in_icmpv4(skb, &pkt);
        break;
    case IPPROTO_ICMPV6:
        core_fill_in_icmpv6(skb, &pkt);
        break;
    default:
        return 0;
    }

    // check if this packet need to be filtered if filtering feature is enabled
    bool skip = check_and_do_flow_filtering(&pkt, reason);
    if (skip) {
        return 0;
    }
    u64 len = BPF_CORE_READ(skb, len);
    long ret = pkt_drop_lookup_and_update_flow(&id, state, flags, reason, len);
    if (ret == 0) {
        return 0;
    }
    // there is no matching flows so lets create new one and add the drops
    additional_metrics new_flow = {
        .pkt_drops.packets = 1,
        .pkt_drops.bytes = len,
        .pkt_drops.latest_state = state,
        .pkt_drops.latest_flags = flags,
        .pkt_drops.latest_drop_cause = reason,
    };
    ret = bpf_map_update_elem(&additional_flow_metrics, &id, &new_flow, BPF_ANY);
    if (trace_messages && ret != 0) {
        bpf_printk("error packet drop creating new flow %d\n", ret);
    }

    return ret;
}

SEC("tracepoint/skb/kfree_skb")
int kfree_skb(struct trace_event_raw_kfree_skb *args) {
    if (do_sampling == 0) {
        return 0;
    }

    struct sk_buff *skb = (struct sk_buff *)BPF_CORE_READ(args, skbaddr);
    struct sock *sk = (struct sock *)BPF_CORE_READ(skb, sk);
    enum skb_drop_reason reason = args->reason;

    // SKB_NOT_DROPPED_YET,
    // SKB_CONSUMED,
    // SKB_DROP_REASON_NOT_SPECIFIED,
    if (reason > SKB_DROP_REASON_NOT_SPECIFIED) {
        u8 state = 0;
        if (sk) {
            // pull in details from the packet headers and the sock struct
            bpf_probe_read(&state, sizeof(u8), (u8 *)&sk->__sk_common.skc_state);
        }
        return trace_pkt_drop(args, state, skb, reason);
    }
    return 0;
}

#endif //__PKT_DROPS_H__
