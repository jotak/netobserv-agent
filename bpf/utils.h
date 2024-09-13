#ifndef __UTILS_H__
#define __UTILS_H__

#include <bpf_core_read.h>
#include "types.h"
#include "maps_definition.h"
#include "flows_filter.h"

static u8 do_sampling = 0;

// sets the TCP header flags for connection information
static inline void set_flags(struct tcphdr *th, u16 *flags) {
    //If both ACK and SYN are set, then it is server -> client communication during 3-way handshake.
    if (th->ack && th->syn) {
        *flags |= SYN_ACK_FLAG;
    } else if (th->ack && th->fin) {
        // If both ACK and FIN are set, then it is graceful termination from server.
        *flags |= FIN_ACK_FLAG;
    } else if (th->ack && th->rst) {
        // If both ACK and RST are set, then it is abrupt connection termination.
        *flags |= RST_ACK_FLAG;
    } else if (th->fin) {
        *flags |= FIN_FLAG;
    } else if (th->syn) {
        *flags |= SYN_FLAG;
    } else if (th->ack) {
        *flags |= ACK_FLAG;
    } else if (th->rst) {
        *flags |= RST_FLAG;
    } else if (th->psh) {
        *flags |= PSH_FLAG;
    } else if (th->urg) {
        *flags |= URG_FLAG;
    } else if (th->ece) {
        *flags |= ECE_FLAG;
    } else if (th->cwr) {
        *flags |= CWR_FLAG;
    }
}

// Extract L4 info for the supported protocols
static inline void fill_l4info(void *l4_hdr_start, void *data_end, u8 protocol, pkt_info *pkt) {
    flow_id *id = pkt->id;
    id->transport_protocol = protocol;
    switch (protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = l4_hdr_start;
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
            id->src_port = bpf_ntohs(tcp->source);
            id->dst_port = bpf_ntohs(tcp->dest);
            set_flags(tcp, &pkt->flags);
            pkt->l4_hdr = (void *)tcp;
        }
    } break;
    case IPPROTO_UDP: {
        struct udphdr *udp = l4_hdr_start;
        if ((void *)udp + sizeof(*udp) <= data_end) {
            id->src_port = bpf_ntohs(udp->source);
            id->dst_port = bpf_ntohs(udp->dest);
            pkt->l4_hdr = (void *)udp;
        }
    } break;
    case IPPROTO_SCTP: {
        struct sctphdr *sctph = l4_hdr_start;
        if ((void *)sctph + sizeof(*sctph) <= data_end) {
            id->src_port = bpf_ntohs(sctph->source);
            id->dst_port = bpf_ntohs(sctph->dest);
            pkt->l4_hdr = (void *)sctph;
        }
    } break;
    case IPPROTO_ICMP: {
        struct icmphdr *icmph = l4_hdr_start;
        if ((void *)icmph + sizeof(*icmph) <= data_end) {
            id->icmp_type = icmph->type;
            id->icmp_code = icmph->code;
            pkt->l4_hdr = (void *)icmph;
        }
    } break;
    case IPPROTO_ICMPV6: {
        struct icmp6hdr *icmp6h = l4_hdr_start;
        if ((void *)icmp6h + sizeof(*icmp6h) <= data_end) {
            id->icmp_type = icmp6h->icmp6_type;
            id->icmp_code = icmp6h->icmp6_code;
            pkt->l4_hdr = (void *)icmp6h;
        }
    } break;
    default:
        break;
    }
}

static inline u8 ipv4_get_dscp(const struct iphdr *iph) {
    return (iph->tos >> DSCP_SHIFT) & DSCP_MASK;
}

static inline u8 ipv6_get_dscp(const struct ipv6hdr *ipv6h) {
    return ((bpf_ntohs(*(const __be16 *)ipv6h) >> 4) >> DSCP_SHIFT) & DSCP_MASK;
}

// sets flow fields from IPv4 header information
static inline int fill_iphdr(struct iphdr *ip, void *data_end, pkt_info *pkt) {
    void *l4_hdr_start;

    l4_hdr_start = (void *)ip + sizeof(*ip);
    if (l4_hdr_start > data_end) {
        return DISCARD;
    }
    flow_id *id = pkt->id;
    /* Save the IP Address to id directly. copy once. */
    __builtin_memcpy(id->src_ip, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(id->dst_ip, ip4in6, sizeof(ip4in6));
    __builtin_memcpy(id->src_ip + sizeof(ip4in6), &ip->saddr, sizeof(ip->saddr));
    __builtin_memcpy(id->dst_ip + sizeof(ip4in6), &ip->daddr, sizeof(ip->daddr));
    pkt->dscp = ipv4_get_dscp(ip);
    /* fill l4 header which will be added to id in flow_monitor function.*/
    fill_l4info(l4_hdr_start, data_end, ip->protocol, pkt);
    return SUBMIT;
}

// sets flow fields from IPv6 header information
static inline int fill_ip6hdr(struct ipv6hdr *ip, void *data_end, pkt_info *pkt) {
    void *l4_hdr_start;

    l4_hdr_start = (void *)ip + sizeof(*ip);
    if (l4_hdr_start > data_end) {
        return DISCARD;
    }
    flow_id *id = pkt->id;
    /* Save the IP Address to id directly. copy once. */
    __builtin_memcpy(id->src_ip, ip->saddr.in6_u.u6_addr8, IP_MAX_LEN);
    __builtin_memcpy(id->dst_ip, ip->daddr.in6_u.u6_addr8, IP_MAX_LEN);
    pkt->dscp = ipv6_get_dscp(ip);
    /* fill l4 header which will be added to id in flow_monitor function.*/
    fill_l4info(l4_hdr_start, data_end, ip->nexthdr, pkt);
    return SUBMIT;
}

// sets flow fields from Ethernet header information
static inline int fill_ethhdr(struct ethhdr *eth, void *data_end, pkt_info *pkt) {
    if ((void *)eth + sizeof(*eth) > data_end) {
        return DISCARD;
    }
    flow_id *id = pkt->id;
    __builtin_memcpy(id->dst_mac, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(id->src_mac, eth->h_source, ETH_ALEN);
    id->eth_protocol = bpf_ntohs(eth->h_proto);

    if (id->eth_protocol == ETH_P_IP) {
        struct iphdr *ip = (void *)eth + sizeof(*eth);
        return fill_iphdr(ip, data_end, pkt);
    } else if (id->eth_protocol == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);
        return fill_ip6hdr(ip6, data_end, pkt);
    } else {
        // TODO : Need to implement other specific ethertypes if needed
        // For now other parts of flow id remain zero
        __builtin_memset(&(id->src_ip), 0, sizeof(struct in6_addr));
        __builtin_memset(&(id->dst_ip), 0, sizeof(struct in6_addr));
        id->transport_protocol = 0;
        id->src_port = 0;
        id->dst_port = 0;
    }
    return SUBMIT;
}

static inline void set_key_with_l2_info(struct sk_buff *skb, flow_id *id, u16 *family) {
    struct ethhdr eth;
    __builtin_memset(&eth, 0, sizeof(eth));
    bpf_probe_read(&eth, sizeof(eth), (struct ethhdr *)(skb->head + skb->mac_header));
    id->eth_protocol = bpf_ntohs(eth.h_proto);
    __builtin_memcpy(id->dst_mac, eth.h_dest, ETH_ALEN);
    __builtin_memcpy(id->src_mac, eth.h_source, ETH_ALEN);
    if (id->eth_protocol == ETH_P_IP) {
        *family = AF_INET;
    } else if (id->eth_protocol == ETH_P_IPV6) {
        *family = AF_INET6;
    }
}

static inline void set_key_with_l3_info(struct sk_buff *skb, u16 family, flow_id *id,
                                        u8 *protocol) {
    if (family == AF_INET) {
        struct iphdr ip;
        __builtin_memset(&ip, 0, sizeof(ip));
        bpf_probe_read(&ip, sizeof(ip), (struct iphdr *)(skb->head + skb->network_header));
        __builtin_memcpy(id->src_ip, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(id->dst_ip, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(id->src_ip + sizeof(ip4in6), &ip.saddr, sizeof(ip.saddr));
        __builtin_memcpy(id->dst_ip + sizeof(ip4in6), &ip.daddr, sizeof(ip.daddr));
        *protocol = ip.protocol;
    } else if (family == AF_INET6) {
        struct ipv6hdr ip;
        __builtin_memset(&ip, 0, sizeof(ip));
        bpf_probe_read(&ip, sizeof(ip), (struct ipv6hdr *)(skb->head + skb->network_header));
        __builtin_memcpy(id->src_ip, ip.saddr.in6_u.u6_addr8, IP_MAX_LEN);
        __builtin_memcpy(id->dst_ip, ip.daddr.in6_u.u6_addr8, IP_MAX_LEN);
        *protocol = ip.nexthdr;
    }
}

static inline int set_key_with_tcp_info(struct sk_buff *skb, flow_id *id, u8 protocol, u16 *flags) {
    u16 sport = 0, dport = 0;
    struct tcphdr tcp;

    __builtin_memset(&tcp, 0, sizeof(tcp));
    bpf_probe_read(&tcp, sizeof(tcp), (struct tcphdr *)(skb->head + skb->transport_header));
    sport = bpf_ntohs(tcp.source);
    dport = bpf_ntohs(tcp.dest);
    set_flags(&tcp, flags);
    id->src_port = sport;
    id->dst_port = dport;
    id->transport_protocol = protocol;
    return tcp.doff * sizeof(u32);
}

static inline int set_key_with_udp_info(struct sk_buff *skb, flow_id *id, u8 protocol) {
    u16 sport = 0, dport = 0;
    struct udphdr udp;

    __builtin_memset(&udp, 0, sizeof(udp));
    bpf_probe_read(&udp, sizeof(udp), (struct udphdr *)(skb->head + skb->transport_header));
    sport = bpf_ntohs(udp.source);
    dport = bpf_ntohs(udp.dest);
    id->src_port = sport;
    id->dst_port = dport;
    id->transport_protocol = protocol;
    return bpf_ntohs(udp.len);
}

static inline int set_key_with_sctp_info(struct sk_buff *skb, flow_id *id, u8 protocol) {
    u16 sport = 0, dport = 0;
    struct sctphdr sctp;

    __builtin_memset(&sctp, 0, sizeof(sctp));
    bpf_probe_read(&sctp, sizeof(sctp), (struct sctphdr *)(skb->head + skb->transport_header));
    sport = bpf_ntohs(sctp.source);
    dport = bpf_ntohs(sctp.dest);
    id->src_port = sport;
    id->dst_port = dport;
    id->transport_protocol = protocol;
    return 0;
}

static inline int set_key_with_icmpv4_info(struct sk_buff *skb, flow_id *id, u8 protocol) {
    struct icmphdr icmph;
    __builtin_memset(&icmph, 0, sizeof(icmph));
    bpf_probe_read(&icmph, sizeof(icmph), (struct icmphdr *)(skb->head + skb->transport_header));
    id->icmp_type = icmph.type;
    id->icmp_code = icmph.code;
    id->transport_protocol = protocol;
    return 0;
}

static inline int set_key_with_icmpv6_info(struct sk_buff *skb, flow_id *id, u8 protocol) {
    struct icmp6hdr icmp6h;
    __builtin_memset(&icmp6h, 0, sizeof(icmp6h));
    bpf_probe_read(&icmp6h, sizeof(icmp6h), (struct icmp6hdr *)(skb->head + skb->transport_header));
    id->icmp_type = icmp6h.icmp6_type;
    id->icmp_code = icmp6h.icmp6_code;
    id->transport_protocol = protocol;
    return 0;
}

static inline long pkt_drop_lookup_and_update_flow(struct sk_buff *skb, flow_id *id, u8 state,
                                                   u16 flags, enum skb_drop_reason reason) {
    flow_metrics *aggregate_flow = bpf_map_lookup_elem(&aggregated_flows, id);
    if (aggregate_flow != NULL) {
        aggregate_flow->end_mono_time_ts = bpf_ktime_get_ns();
        aggregate_flow->pkt_drops.packets += 1;
        aggregate_flow->pkt_drops.bytes += skb->len;
        aggregate_flow->pkt_drops.latest_state = state;
        aggregate_flow->pkt_drops.latest_flags = flags;
        aggregate_flow->pkt_drops.latest_drop_cause = reason;
        long ret = bpf_map_update_elem(&aggregated_flows, id, aggregate_flow, BPF_EXIST);
        if (trace_messages && ret != 0) {
            bpf_printk("error packet drop updating flow %d\n", ret);
        }
        return 0;
    }
    return -1;
}

/*
 * check if flow filter is enabled and if we need to continue processing the packet or not
 */
static inline bool check_and_do_flow_filtering(flow_id *id, u16 flags) {
    // check if this packet need to be filtered if filtering feature is enabled
    if (enable_flows_filtering || enable_pca) {
        filter_action action = ACCEPT;
        u32 *filter_counter_p = NULL;
        u32 initVal = 1, key = 0;
        if (is_flow_filtered(id, &action, flags) != 0 && action != MAX_FILTER_ACTIONS) {
            // we have matching rules follow through the actions to decide if we should accept or reject the flow
            // and update global counter for both cases
            u32 reject_key = FILTER_REJECT_KEY, accept_key = FILTER_ACCEPT_KEY;
            bool skip = false;

            switch (action) {
            case REJECT:
                key = reject_key;
                skip = true;
                break;
            case ACCEPT:
                key = accept_key;
                break;
            // should never come here
            case MAX_FILTER_ACTIONS:
                return true;
            }

            // update global counter for flows dropped by filter
            filter_counter_p = bpf_map_lookup_elem(&global_counters, &key);
            if (!filter_counter_p) {
                bpf_map_update_elem(&global_counters, &key, &initVal, BPF_ANY);
            } else {
                __sync_fetch_and_add(filter_counter_p, 1);
            }
            if (skip) {
                return true;
            }
        } else {
            // we have no matching rules so we update global counter for flows that are not matched by any rule
            key = FILTER_NOMATCH_KEY;
            filter_counter_p = bpf_map_lookup_elem(&global_counters, &key);
            if (!filter_counter_p) {
                bpf_map_update_elem(&global_counters, &key, &initVal, BPF_ANY);
            } else {
                __sync_fetch_and_add(filter_counter_p, 1);
            }
            // we have accept rule but no match so we can't let mismatched flows in the hashmap table.
            if (action == ACCEPT || action == MAX_FILTER_ACTIONS) {
                return true;
            } else {
                // we have reject rule and no match so we can add the flows to the hashmap table.
            }
        }
    }
    return false;
}

static inline void core_fill_in_l2(struct sk_buff *skb, flow_id *id, u16 *family) {
    struct ethhdr eth;

    __builtin_memset(&eth, 0, sizeof(eth));

    u8 *skb_head = BPF_CORE_READ(skb, head);
    u16 skb_mac_header = BPF_CORE_READ(skb, mac_header);

    bpf_probe_read(&eth, sizeof(eth), (struct ethhdr *)(skb_head + skb_mac_header));
    __builtin_memcpy(id->dst_mac, eth.h_dest, ETH_ALEN);
    __builtin_memcpy(id->src_mac, eth.h_source, ETH_ALEN);
    id->eth_protocol = bpf_ntohs(eth.h_proto);
    if (id->eth_protocol == ETH_P_IP) {
        *family = AF_INET;
    } else if (id->eth_protocol == ETH_P_IPV6) {
        *family = AF_INET6;
    }
}

static inline void core_fill_in_l3(struct sk_buff *skb, flow_id *id, u16 family, u8 *protocol,
                                   u8 *dscp) {
    u16 skb_network_header = BPF_CORE_READ(skb, network_header);
    u8 *skb_head = BPF_CORE_READ(skb, head);

    switch (family) {
    case AF_INET: {
        struct iphdr ip;
        __builtin_memset(&ip, 0, sizeof(ip));
        bpf_probe_read(&ip, sizeof(ip), (struct iphdr *)(skb_head + skb_network_header));
        __builtin_memcpy(id->src_ip, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(id->dst_ip, ip4in6, sizeof(ip4in6));
        __builtin_memcpy(id->src_ip + sizeof(ip4in6), &ip.saddr, sizeof(ip.saddr));
        __builtin_memcpy(id->dst_ip + sizeof(ip4in6), &ip.daddr, sizeof(ip.daddr));
        *dscp = ipv4_get_dscp(&ip);
        *protocol = ip.protocol;
        break;
    }
    case AF_INET6: {
        struct ipv6hdr ip;
        __builtin_memset(&ip, 0, sizeof(ip));
        bpf_probe_read(&ip, sizeof(ip), (struct ipv6hdr *)(skb_head + skb_network_header));
        __builtin_memcpy(id->src_ip, ip.saddr.in6_u.u6_addr8, IP_MAX_LEN);
        __builtin_memcpy(id->dst_ip, ip.daddr.in6_u.u6_addr8, IP_MAX_LEN);
        *dscp = ipv6_get_dscp(&ip);
        *protocol = ip.nexthdr;
        break;
    }
    default:
        return;
    }
}

static inline void core_fill_in_tcp(struct sk_buff *skb, flow_id *id, u16 *flags) {
    u16 skb_transport_header = BPF_CORE_READ(skb, transport_header);
    u8 *skb_head = BPF_CORE_READ(skb, head);
    struct tcphdr tcp;
    u16 sport, dport;

    __builtin_memset(&tcp, 0, sizeof(tcp));

    bpf_probe_read(&tcp, sizeof(tcp), (struct tcphdr *)(skb_head + skb_transport_header));
    sport = bpf_ntohs(tcp.source);
    dport = bpf_ntohs(tcp.dest);
    id->src_port = sport;
    id->dst_port = dport;
    set_flags(&tcp, flags);
    id->transport_protocol = IPPROTO_TCP;
}

static inline void core_fill_in_udp(struct sk_buff *skb, flow_id *id) {
    u16 skb_transport_header = BPF_CORE_READ(skb, transport_header);
    u8 *skb_head = BPF_CORE_READ(skb, head);
    struct udphdr udp;
    u16 sport, dport;

    __builtin_memset(&udp, 0, sizeof(udp));

    bpf_probe_read(&udp, sizeof(udp), (struct udphdr *)(skb_head + skb_transport_header));
    sport = bpf_ntohs(udp.source);
    dport = bpf_ntohs(udp.dest);
    id->src_port = sport;
    id->dst_port = dport;
    id->transport_protocol = IPPROTO_UDP;
}

static inline void core_fill_in_sctp(struct sk_buff *skb, flow_id *id) {
    u16 skb_transport_header = BPF_CORE_READ(skb, transport_header);
    u8 *skb_head = BPF_CORE_READ(skb, head);
    struct sctphdr sctp;
    u16 sport, dport;

    __builtin_memset(&sctp, 0, sizeof(sctp));

    bpf_probe_read(&sctp, sizeof(sctp), (struct sctphdr *)(skb_head + skb_transport_header));
    sport = bpf_ntohs(sctp.source);
    dport = bpf_ntohs(sctp.dest);
    id->src_port = sport;
    id->dst_port = dport;
    id->transport_protocol = IPPROTO_SCTP;
}

static inline void core_fill_in_icmpv4(struct sk_buff *skb, flow_id *id) {
    u16 skb_transport_header = BPF_CORE_READ(skb, transport_header);
    u8 *skb_head = BPF_CORE_READ(skb, head);
    struct icmphdr icmph;
    __builtin_memset(&icmph, 0, sizeof(icmph));

    bpf_probe_read(&icmph, sizeof(icmph), (struct icmphdr *)(skb_head + skb_transport_header));
    id->icmp_type = icmph.type;
    id->icmp_code = icmph.code;
    id->transport_protocol = IPPROTO_ICMP;
}

static inline void core_fill_in_icmpv6(struct sk_buff *skb, flow_id *id) {
    u16 skb_transport_header = BPF_CORE_READ(skb, transport_header);
    u8 *skb_head = BPF_CORE_READ(skb, head);
    struct icmp6hdr icmph;
    __builtin_memset(&icmph, 0, sizeof(icmph));

    bpf_probe_read(&icmph, sizeof(icmph), (struct icmp6hdr *)(skb_head + skb_transport_header));
    id->icmp_type = icmph.icmp6_type;
    id->icmp_code = icmph.icmp6_code;
    id->transport_protocol = IPPROTO_ICMPV6;
}

static inline void fill_in_others_protocol(flow_id *id, u8 protocol) {
    id->transport_protocol = protocol;
}

#endif // __UTILS_H__
