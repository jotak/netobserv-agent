/*
    rule based filter to filter out packets not of interest to users.
*/

#ifndef __FLOWS_FILTER_H__
#define __FLOWS_FILTER_H__

#include "utils.h"

#define BPF_PRINTK(fmt, args...)                                                                   \
    if (trace_messages)                                                                            \
    bpf_printk(fmt, ##args)

static __always_inline int do_ip_group_lookup(flow_id *id, u16 eth_protocol, u16 *src_group_id, u16 *dst_group_id) {
    struct filter_cidr_key_t key_src, key_dst;
    u8 len, offset;

    __builtin_memset(&key_src, 0, sizeof(key_src));
    __builtin_memset(&key_dst, 0, sizeof(key_dst));

    if (eth_protocol == ETH_P_IP) {
        len = sizeof(u32);
        offset = sizeof(ip4in6);
        __builtin_memcpy(key_src.ip_data, id->src_ip + offset, len);
        __builtin_memcpy(key_dst.ip_data, id->dst_ip + offset, len);
        key_src.prefix_len = 32;
        key_dst.prefix_len = 32;
    } else if (eth_protocol == ETH_P_IPV6) {
        len = IP_MAX_LEN;
        offset = 0;
        __builtin_memcpy(key_src.ip_data, id->src_ip + offset, len);
        __builtin_memcpy(key_dst.ip_data, id->dst_ip + offset, len);
        key_src.prefix_len = 128;
        key_dst.prefix_len = 128;
    } else {
        return -1;
    }

    u16 * gid = (u16*)bpf_map_lookup_elem(&cidr_map, &key_src);
    if (gid != NULL) {
        *src_group_id = *gid;
    }
    gid = (u16*)bpf_map_lookup_elem(&cidr_map, &key_dst);
    if (gid != NULL) {
        *dst_group_id = *gid;
    }
    return 0;
}

static __always_inline bool match_ports(u16 *rule_ports, u16 port) {
    for (int i = 0; i < FILTER_MAX_PORTS && rule_ports[i] > 0; i++) {
        if (rule_ports[i] == port) {
            return true;
        }
    }
    return false;
}

static __always_inline int do_filter_rule_lookup(flow_id *id, u16 src_group_id, u16 dst_group_id,
                                                 filter_action *action, u16 flags, u32 drop_reason, u32 *sampling,
                                                 u8 direction, u16 eth_protocol) {
    int result = 0;
    struct filter_rule_key_t key;
    if (src_group_id < dst_group_id) {
        key.group_low = src_group_id;
        key.group_high = dst_group_id;
    } else {
        key.group_low = dst_group_id;
        key.group_high = src_group_id;
    }

    struct filter_value_t *rule = (struct filter_value_t *)bpf_map_lookup_elem(&filter_rules_map, &key);

    if (rule) {
        BPF_PRINTK("rule found drop_reason %d flags %d action %d\n", drop_reason, flags, rule->action);
        result++;
        *action = rule->action;

        if (rule->sample && sampling != NULL) {
            BPF_PRINTK("sampling action is set to %d\n", rule->sample);
            *sampling = rule->sample;
            result++;
        }
        // match specific rule protocol or use wildcard protocol
        if (rule->protocol == id->transport_protocol || rule->protocol == 0) {
            switch (id->transport_protocol) {
            case IPPROTO_TCP:
            case IPPROTO_UDP:
            case IPPROTO_SCTP:
                // dst_port matching
                if (rule->dst_ports[0] > 0) {
                    if (match_ports(rule->dst_ports, id->dst_port)) {
                        BPF_PRINTK("dst_port matched\n");
                        result++;
                    } else {
                        result = 0;
                        goto end;
                    }
                }
                // src_port matching
                if (rule->src_ports[0] > 0) {
                    if (match_ports(rule->src_ports, id->src_port)) {
                        BPF_PRINTK("src_port matched\n");
                        result++;
                    } else {
                        result = 0;
                        goto end;
                    }
                }
                // any side port matching
                if (rule->ports[0] > 0) {
                    if (match_ports(rule->ports, id->dst_port)) {
                        BPF_PRINTK("dst_port matched\n");
                        result++;
                    } else if (match_ports(rule->ports, id->src_port)) {
                        BPF_PRINTK("src_port matched\n");
                        result++;
                    } else {
                        result = 0;
                        goto end;
                    }
                }
                // for TCP only check TCP flags if its set
                if (id->transport_protocol == IPPROTO_TCP) {
                    if (rule->tcp_flags != 0) {
                        if (rule->tcp_flags == flags) {
                            BPF_PRINTK("tcp_flags matched\n");
                            result++;
                        } else {
                            result = 0;
                            goto end;
                        }
                    }
                }
                break;
            case IPPROTO_ICMP:
            case IPPROTO_ICMPV6:
                if (rule->icmp_type != 0) {
                    if (rule->icmp_type == id->icmp_type) {
                        BPF_PRINTK("icmp_type matched\n");
                        result++;
                    } else {
                        result = 0;
                        goto end;
                    }
                    if (rule->icmp_code != 0) {
                        if (rule->icmp_code == id->icmp_code) {
                            BPF_PRINTK("icmp_code matched\n");
                            result++;
                        } else {
                            result = 0;
                            goto end;
                        }
                    }
                }
                break;
            }
        } else {
            result = 0;
            goto end;
        }

        if (rule->direction != MAX_DIRECTION) {
            if (rule->direction == direction) {
                BPF_PRINTK("direction matched\n");
                result++;
            } else {
                result = 0;
                goto end;
            }
        }

        if (rule->filter_drops) {
            if (drop_reason != 0) {
                BPF_PRINTK("drop filter matched\n");
                result++;
            } else {
                result = 0;
                goto end;
            }
        }
    }
end:
    BPF_PRINTK("result: %d action %d\n", result, *action);
    return result;
}

/*
 * check if the flow match filter rule and return >= 1 if the flow is to be dropped
 */
static __always_inline int is_flow_filtered(flow_id *id, filter_action *action, u16 flags,
                                            u32 drop_reason, u16 eth_protocol, u32 *sampling,
                                            u8 direction) {
    *action = MAX_FILTER_ACTIONS;
    u16 src_group_id = 0, dst_group_id = 0;

    // Lets do first src/dst group lookups for IPs
    int result = do_ip_group_lookup(id, eth_protocol, &src_group_id, &dst_group_id);
    if (result < 0) {
        return result;
    }

    // Lookup rules for these groups
    return do_filter_rule_lookup(id, src_group_id, dst_group_id, action, flags, drop_reason, sampling, direction, eth_protocol);
}

#endif //__FLOWS_FILTER_H__
