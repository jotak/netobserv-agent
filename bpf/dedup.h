/*
    Flows de-duplication logic
*/

#ifndef __DEDUP_H__
#define __DEDUP_H__

#include "utils.h"

static inline bool add_observation(observations *obs, u32 if_index, u8 direction, ip_port *src, ip_port *dst) {
    bool changed = false;
    if (obs->nb_observed_intf < MAX_OBSERVED_INTERFACES) {
        bool found = false;
        for (u8 i = 0; i < obs->nb_observed_intf; i++) {
            if (obs->observed_intf[i].if_index == if_index &&
                obs->observed_intf[i].direction == direction) {
                found = true;
                break;
            }
        }
        if (!found) {
            obs->observed_intf[obs->nb_observed_intf].if_index = if_index;
            obs->observed_intf[obs->nb_observed_intf].direction = direction;
            obs->nb_observed_intf++;
            changed = true;
        }
    }
    if (src != NULL && obs->nb_observed_src < MAX_OBSERVED_IPS) {
        bool found = false;
        for (u8 i = 0; i < obs->nb_observed_src; i++) {
            if (__builtin_memcmp(obs->observed_src[i].addr, src->addr, IP_MAX_LEN) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            __builtin_memcpy(obs->observed_src[obs->nb_observed_src].addr, src->addr, IP_MAX_LEN);
            obs->observed_src[obs->nb_observed_src].port = src->port;
            obs->nb_observed_src++;
            changed = true;
        }
    }
    if (dst != NULL && obs->nb_observed_dst < MAX_OBSERVED_IPS) {
        bool found = false;
        for (u8 i = 0; i < obs->nb_observed_dst; i++) {
            if (__builtin_memcmp(obs->observed_dst[i].addr, dst->addr, IP_MAX_LEN) == 0) {
                found = true;
                break;
            }
        }
        if (!found) {
            __builtin_memcpy(obs->observed_dst[obs->nb_observed_dst].addr, dst->addr, IP_MAX_LEN);
            obs->observed_dst[obs->nb_observed_dst].port = dst->port;
            obs->nb_observed_dst++;
            changed = true;
        }
    }
    return changed;
}

static inline flow_id *get_or_add_flow_for_packet(flow_id *fid, pkt_id *pkt_hash_ts,
                                                  pkt_id *pkt_addr_ts, pkt_id *pkt_hash_addr,
                                                  u32 mark) {
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
static inline int deduplicate(struct __sk_buff *skb, u8 direction, pkt_info *pkt) {
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
    flow_id *flow = get_or_add_flow_for_packet(pkt->id, &pkt_hash_ts, &pkt_addr_ts, &pkt_hash_addr, mark);
    if (flow != NULL) {
        increase_counter(PKT_MAP_HIT);
        ip_port additional_src = {
            .port = pkt->id->src_port,
        };
        ip_port *p_src = &additional_src;
        ip_port additional_dst = {
            .port = pkt->id->dst_port,
        };
        ip_port *p_dst = &additional_dst;
        // If packet IPs are same as existing flow id, we don't add them as observed IPs
        if (__builtin_memcmp(flow->src_ip, pkt->id->src_ip, IP_MAX_LEN) == 0) {
            p_src = NULL;
        } else {
            __builtin_memcpy(p_src->addr, pkt->id->src_ip, IP_MAX_LEN);
        }
        if (__builtin_memcmp(flow->dst_ip, pkt->id->dst_ip, IP_MAX_LEN) == 0) {
            p_dst = NULL;
        } else {
            __builtin_memcpy(p_dst->addr, pkt->id->dst_ip, IP_MAX_LEN);
        }
        // Only add observation info, no more
        observations *obs = (observations *)bpf_map_lookup_elem(&flow_observations, flow);
        if (obs != NULL) {
            if (add_observation(obs, skb->ifindex, direction, p_src, p_dst)) {
                bpf_map_update_elem(&flow_observations, flow, obs, BPF_EXIST);
            }
        } else {
            // Flow might exist in another per-CPU map, or was flushed recently.
            // Create empty flow with just observation info
            observations new_obs = {};
            add_observation(&new_obs, skb->ifindex, direction, p_src, p_dst);
            bpf_map_update_elem(&flow_observations, flow, &new_obs, BPF_NOEXIST);
        }
        return 0;
    }

    // Map miss
    increase_counter(PKT_MAP_MISS);
    if (mark == mark_bit) {
        // We reached this point despite mark being set, meaning we went into a map-miss for an already seen packet (e.g. due to skb address change)
        increase_counter(PKT_MAP_POTENTIAL_DUPLICATION);
    }

    // Add observation
    observations *obs = (observations *)bpf_map_lookup_elem(&flow_observations, pkt->id);
    if (obs != NULL) {
        // We don't add observed IPs that are already in the key (flowid)
        if (add_observation(obs, skb->ifindex, direction, NULL, NULL)) {
            bpf_map_update_elem(&flow_observations, pkt->id, obs, BPF_EXIST);
        }
    } else {
        // Create a new observation info
        struct observed_intf_t intf = {
            .direction = direction,
            .if_index = skb->ifindex,
        };
        observations obs = {
            .nb_observed_intf = 1,
            .observed_intf = {intf},
        };
        bpf_map_update_elem(&flow_observations, pkt->id, &obs, BPF_NOEXIST);
    }
    return 1;
}

#endif /* __DEDUP_H__ */
