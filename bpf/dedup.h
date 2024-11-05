/*
    Flows de-duplication logic
*/

#ifndef __DEDUP_H__
#define __DEDUP_H__

#include "utils.h"

static inline bool add_observation(flow_metrics *aggregate_flow, u32 if_index, u8 direction, u8 *src_ip, u8 *dst_ip) {
    bool changed = false;
    if (aggregate_flow->nb_observed_intf < MAX_FLOW_OBSERVATIONS) {
        bool found = false;
        for (u8 i = 0; i < aggregate_flow->nb_observed_intf; i++) {
            if (aggregate_flow->observed_intf[i].if_index == if_index && aggregate_flow->observed_intf[i].direction == direction) {
                found = true;
                break;
            }
        }
        if (!found) {
            aggregate_flow->observed_intf[aggregate_flow->nb_observed_intf].if_index = if_index;
            aggregate_flow->observed_intf[aggregate_flow->nb_observed_intf].direction = direction;
            aggregate_flow->nb_observed_intf++;
            changed = true;
        }
    }
    if (src_ip != NULL && aggregate_flow->nb_observed_src_ips < MAX_FLOW_OBSERVATIONS) {
        bool found = false;
        for (u8 i = 0; i < aggregate_flow->nb_observed_src_ips; i++) {
            if (__builtin_memcmp(aggregate_flow->observed_src_ips[i], src_ip + sizeof(ip4in6), sizeof(aggregate_flow->observed_src_ips[i])) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            __builtin_memcpy(aggregate_flow->observed_src_ips[aggregate_flow->nb_observed_src_ips], src_ip + sizeof(ip4in6), sizeof(aggregate_flow->observed_src_ips[aggregate_flow->nb_observed_src_ips]));
            aggregate_flow->nb_observed_src_ips++;
            changed = true;
        }
    }
    if (dst_ip != NULL && aggregate_flow->nb_observed_dst_ips < MAX_FLOW_OBSERVATIONS) {
        bool found = false;
        for (u8 i = 0; i < aggregate_flow->nb_observed_dst_ips; i++) {
            if (__builtin_memcmp(aggregate_flow->observed_dst_ips[i], dst_ip + sizeof(ip4in6), sizeof(aggregate_flow->observed_dst_ips[i])) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            __builtin_memcpy(aggregate_flow->observed_dst_ips[aggregate_flow->nb_observed_dst_ips], dst_ip + sizeof(ip4in6), sizeof(aggregate_flow->observed_dst_ips[aggregate_flow->nb_observed_src_ips]));
            aggregate_flow->nb_observed_dst_ips++;
            changed = true;
        }
    }
    return changed;
}

static inline flow_id* get_or_add_flow_for_packet(flow_id *fid, pkt_id *pkt_hash_ts, pkt_id *pkt_addr_ts, pkt_id *pkt_hash_addr, u32 mark) {
    // Stategy is: keyed by addr, hash, ts: pick two, try all combinations
    // First, try with address+hash
    flow_id *stored_id = (flow_id *)bpf_map_lookup_elem(&pkt_flow_map, pkt_hash_addr);
    if (stored_id != NULL) {
        return stored_id;
    }
    if (pkt_hash_ts->tstamp == 0 && mark == 0) {
        // Potential collision. Do not try to get flow id. Delete in case it exists.
        bpf_map_delete_elem(&pkt_flow_map, pkt_hash_ts);
        bpf_map_delete_elem(&pkt_flow_map, pkt_addr_ts);
        increase_counter(PKT_MAP_AVOID_POTENTIAL_COLLISION);
    } else {
        // Retry with hash+ts
        stored_id = (flow_id *)bpf_map_lookup_elem(&pkt_flow_map, pkt_hash_ts);
        if (stored_id != NULL) {
            return stored_id;
        }
        // Retry with address+ts
        stored_id = (flow_id *)bpf_map_lookup_elem(&pkt_flow_map, pkt_addr_ts);
        if (stored_id != NULL) {
            return stored_id;
        }
    }

    // store flow_id for this packet
    long ret = bpf_map_update_elem(&pkt_flow_map, pkt_hash_addr, fid, BPF_ANY);
    if (ret != 0) {
        increase_counter(HASHMAP_PACKETS_CANT_UPDATE);
    }
    ret = bpf_map_update_elem(&pkt_flow_map, pkt_hash_ts, fid, BPF_ANY);
    if (ret != 0) {
        increase_counter(HASHMAP_PACKETS_CANT_UPDATE);
    }
    ret = bpf_map_update_elem(&pkt_flow_map, pkt_addr_ts, fid, BPF_ANY);
    if (ret != 0) {
        increase_counter(HASHMAP_PACKETS_CANT_UPDATE);
    }
    return NULL;
}

// Check if the packet was already seen, add additional data to the flow (IPs, interface...) if that's a duplicate observation.
// Return 0 for duplicate, 1 for non-duplicate, 2 for duplicate but with unknown flow
static inline int check_dup(struct __sk_buff *skb, u8 direction, pkt_info *pkt) {
    // Set "unique" identifier for this packet
    pkt_id pkt_hash_ts;
    __builtin_memset(&pkt_hash_ts, 0, sizeof(pkt_hash_ts));
    pkt_hash_ts.hash = skb->hash;
    pkt_hash_ts.tstamp = skb->tstamp;

    pkt_id pkt_addr_ts;
    __builtin_memset(&pkt_addr_ts, 0, sizeof(pkt_addr_ts));
    // pkt_id_addr.skb_ref = BPF_CORE_READ(skb, head); // => head doesn't exist in https://docs.ebpf.io/linux/program-context/__sk_buff
    pkt_addr_ts.skb_ref = skb->data_meta;
    // pkt_id_addr.skb_ref = (u64)(void*)data;
    // pkt_id_addr.skb_ref = (u64)(void*)data_end;
    // pkt_id_addr.skb_ref = (u64)(void*)skb;
    pkt_addr_ts.tstamp = skb->tstamp;

    pkt_id pkt_hash_addr;
    __builtin_memset(&pkt_hash_addr, 0, sizeof(pkt_hash_addr));
    pkt_hash_addr.hash = skb->hash;
    pkt_hash_addr.skb_ref = skb->data_meta;

    u32 mark = skb->mark;
    if (mark == 0) {
        skb->mark = mark_bit;
        increase_counter(MARK_0);
    } else if (mark == mark_bit) {
        increase_counter(MARK_SEEN);
    } else {
        increase_counter(MARK_OTHER);
    }

    // Have we already seen this packet and created a flow?
    flow_id *existing_flow_id = get_or_add_flow_for_packet(pkt->id, &pkt_hash_ts, &pkt_addr_ts, &pkt_hash_addr, mark);
    if (existing_flow_id != NULL) {
        increase_counter(PKT_MAP_HIT);
        u8 *additional_src_ip = NULL, *additional_dst_ip = NULL;
        if (pkt->eth_protocol == ETH_P_IP && // only support ipv4 currently for additional IPs, to avoid stack-too-large
                __builtin_memcmp(existing_flow_id->src_ip, pkt->id->src_ip, IP_MAX_LEN) != 0) {
            additional_src_ip = pkt->id->src_ip;
        }
        if (pkt->eth_protocol == ETH_P_IP && // only support ipv4 currently for additional IPs, to avoid stack-too-large
                __builtin_memcmp(existing_flow_id->dst_ip, pkt->id->dst_ip, IP_MAX_LEN) != 0) {
            additional_dst_ip = pkt->id->dst_ip;
        }
        // Only add observation info, no more
        flow_metrics *aggregate_flow = (flow_metrics*)bpf_map_lookup_elem(&aggregated_flows, existing_flow_id);
        if (aggregate_flow != NULL) {
            if (add_observation(aggregate_flow, skb->ifindex, direction, additional_src_ip, additional_dst_ip)) {
                bpf_map_update_elem(&aggregated_flows, existing_flow_id, aggregate_flow, BPF_EXIST);
            }
        } else {
            // Flow might exist in another per-CPU map, or was flushed recently.
            // Create empty flow with just observation info 
            u64 current_ts = bpf_ktime_get_ns(); // Record the current time first.
            flow_metrics new_flow = {
                .start_mono_time_ts = current_ts,
                .end_mono_time_ts = current_ts,
            };
            add_observation(&new_flow, skb->ifindex, direction, additional_src_ip, additional_dst_ip);
            bpf_map_update_elem(&aggregated_flows, existing_flow_id, &new_flow, BPF_NOEXIST);
        }
        return 0;
    }

    increase_counter(PKT_MAP_MISS);

    if (mark == mark_bit) {
        // We reached this point despite mark being set, meaning we went into a map-miss for an already seen packet (e.g. due to skb address change)
        increase_counter(PKT_MAP_POTENTIAL_DUPLICATION);
    }
    return 1;
}

#endif /* __DEDUP_H__ */
