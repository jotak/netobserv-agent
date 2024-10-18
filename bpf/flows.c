/*
    Flows v2.
    Flow monitor: A Flow-metric generator using TC.

    This program can be hooked on to TC ingress/egress hook to monitor packets
    to/from an interface.

    Logic:
        1) Store flow information in a per-cpu hash map.
        2) Upon flow completion (tcp->fin event), evict the entry from map, and
           send to userspace through ringbuffer.
           Eviction for non-tcp flows need to done by userspace
        3) When the map is full, we send the new flow entry to userspace via ringbuffer,
            until an entry is available.
        4) When hash collision is detected, we send the new entry to userpace via ringbuffer.
*/
#include <vmlinux.h>
#include <bpf_helpers.h>
#include "configs.h"
#include "utils.h"

/*
 * Defines a packet drops statistics tracker,
 * which attaches at kfree_skb hook. Is optional.
 */
#include "pkt_drops.h"

/*
 * Defines a dns tracker,
 * which attaches at net_dev_queue hook. Is optional.
 */
#include "dns_tracker.h"

/*
 * Defines an rtt tracker,
 * which runs inside flow_monitor. Is optional.
 */
#include "rtt_tracker.h"

/*
 * Defines a Packet Capture Agent (PCA) tracker,
 * It is enabled by setting env var ENABLE_PCA= true. Is Optional
 */
#include "pca.h"

/* Do flow filtering. Is optional. */
#include "flows_filter.h"
/*
 * Defines an Network events monitoring tracker,
 * which runs inside flow_monitor. Is optional.
 */
// #include "network_events_monitoring.h"

static inline int add_observation(flow_metrics *aggregate_flow, u32 if_index, u8 direction) {
    if (aggregate_flow->nb_observations < MAX_FLOW_OBSERVATIONS) {
        for (u8 i = 0; i < aggregate_flow->nb_observations; i++) {
            if (aggregate_flow->pkt_observations[i].if_index == if_index && aggregate_flow->pkt_observations[i].direction == direction) {
                return 0;
            }
        }
        aggregate_flow->pkt_observations[aggregate_flow->nb_observations].if_index = if_index;
        aggregate_flow->pkt_observations[aggregate_flow->nb_observations].direction = direction;
        aggregate_flow->nb_observations++;
        return 1;
    }
    return 0;
}

static inline int flow_monitor(struct __sk_buff *skb, u8 direction) {
    // If sampling is defined, will only parse 1 out of "sampling" flows
    if (sampling > 1 && (bpf_get_prandom_u32() % sampling) != 0) {
        do_sampling = 0;
        return TC_ACT_OK;
    }
    do_sampling = 1;

    // Set unique identifier for this packet
    pkt_id pkt_unique_id;
    __builtin_memset(&pkt_unique_id, 0, sizeof(pkt_unique_id));

    pkt_unique_id.hash = skb->hash;
    pkt_unique_id.skb_ptr = (u64)(void*)skb;
    pkt_unique_id.tstamp = skb->tstamp;

    // Have we already seen this packet and created a flow?
    flow_id *existing_flow_id = get_flow_for_packet(&pkt_unique_id);
    if (existing_flow_id != NULL) {
        // Only add pkt_observations info, no more
        flow_metrics *aggregate_flow = (flow_metrics *)bpf_map_lookup_elem(&aggregated_flows, existing_flow_id);
        if (aggregate_flow != NULL) {
            if (add_observation(aggregate_flow, skb->ifindex, direction) == 1) {
                bpf_map_update_elem(&aggregated_flows, existing_flow_id, aggregate_flow, BPF_EXIST);
            }
        } else {
            // Flow might exist in another per-CPU map, or was flushed recently.
            // Create empty flow with just pkt_observations info 
            u64 current_ts = bpf_ktime_get_ns(); // Record the current time first.
            flow_metrics new_flow = {
                .nb_observations = 1,
                .start_mono_time_ts = current_ts,
                .end_mono_time_ts = current_ts,
            };
            new_flow.pkt_observations[0].if_index = skb->ifindex;
            new_flow.pkt_observations[0].direction = direction;
            bpf_map_update_elem(&aggregated_flows, existing_flow_id, &new_flow, BPF_NOEXIST);
        }
        return TC_ACT_OK;
    }

    // Create new flow
    flow_id id;
    __builtin_memset(&id, 0, sizeof(id));

    pkt_info pkt;
    __builtin_memset(&pkt, 0, sizeof(pkt));

    pkt.current_ts = bpf_ktime_get_ns(); // Record the current time first.
    pkt.id = &id;

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = (struct ethhdr *)data;

    if (fill_ethhdr(eth, data_end, &pkt) == DISCARD) {
        return TC_ACT_OK;
    }

    // check if this packet need to be filtered if filtering feature is enabled
    bool skip = check_and_do_flow_filtering(&pkt);
    if (skip) {
        return TC_ACT_OK;
    }

    // store flow_id for this packet
    long ret = bpf_map_update_elem(&pkt_flow_map, &pkt_unique_id, &id, BPF_ANY);
    if (ret != 0) {
        increase_counter(HASHMAP_PACKETS_CANT_UPDATE);
    }

    int dns_errno = 0;
    if (enable_dns_tracking) {
        dns_errno = track_dns_packet(skb, &pkt);
    }
    // TODO: we need to add spinlock here when we deprecate versions prior to 5.1, or provide
    // a spinlocked alternative version and use it selectively https://lwn.net/Articles/779120/
    flow_metrics *aggregate_flow = (flow_metrics *)bpf_map_lookup_elem(&aggregated_flows, &id);
    if (aggregate_flow != NULL) {
        aggregate_flow->packets += 1;
        aggregate_flow->bytes += skb->len;
        aggregate_flow->end_mono_time_ts = pkt.current_ts;
        // it might happen that start_mono_time hasn't been set due to
        // the way percpu hashmap deal with concurrent map entries
        if (aggregate_flow->start_mono_time_ts == 0) {
            aggregate_flow->start_mono_time_ts = pkt.current_ts;
        }
        aggregate_flow->flags |= pkt.flags;
        aggregate_flow->dscp = pkt.dscp;
        aggregate_flow->dns_record.id = pkt.dns_id;
        aggregate_flow->dns_record.flags = pkt.dns_flags;
        aggregate_flow->dns_record.latency = pkt.dns_latency;
        aggregate_flow->dns_record.errno = dns_errno;
        add_observation(aggregate_flow, skb->ifindex, direction);
        long ret = bpf_map_update_elem(&aggregated_flows, &id, aggregate_flow, BPF_ANY);
        if (ret != 0) {
            u32 *error_counter_p = NULL;
            u32 initVal = 1, key = HASHMAP_FLOWS_DROPPED;
            // usually error -16 (-EBUSY) is printed here.
            // In this case, the flow is dropped, as submitting it to the ringbuffer would cause
            // a duplicated UNION of flows (two different flows with partial aggregation of the same packets),
            // which can't be deduplicated.
            // other possible values https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
            if (trace_messages) {
                bpf_printk("error updating flow %d\n", ret);
            }
            // Update global counter for hashmap update errors
            error_counter_p = bpf_map_lookup_elem(&global_counters, &key);
            if (!error_counter_p) {
                bpf_map_update_elem(&global_counters, &key, &initVal, BPF_ANY);
                return TC_ACT_OK;
            }
            __sync_fetch_and_add(error_counter_p, 1);
        }
    } else {
        // Key does not exist in the map, and will need to create a new entry.
        u64 rtt = 0;
        if (enable_rtt && id.transport_protocol == IPPROTO_TCP) {
            rtt = MIN_RTT;
        }
        flow_metrics new_flow = {
            .packets = 1,
            .bytes = skb->len,
            .nb_observations = 1,
            .eth_protocol = pkt.eth_protocol,
            .start_mono_time_ts = pkt.current_ts,
            .end_mono_time_ts = pkt.current_ts,
            .flags = pkt.flags,
            .dscp = pkt.dscp,
            .dns_record.id = pkt.dns_id,
            .dns_record.flags = pkt.dns_flags,
            .dns_record.latency = pkt.dns_latency,
            .dns_record.errno = dns_errno,
            .flow_rtt = rtt,
        };
        new_flow.pkt_observations[0].if_index = skb->ifindex;
        new_flow.pkt_observations[0].direction = direction;
        __builtin_memcpy(new_flow.dst_mac, pkt.dst_mac, ETH_ALEN);
        __builtin_memcpy(new_flow.src_mac, pkt.src_mac, ETH_ALEN);

        // even if we know that the entry is new, another CPU might be concurrently inserting a flow
        // so we need to specify BPF_ANY
        long ret = bpf_map_update_elem(&aggregated_flows, &id, &new_flow, BPF_ANY);
        if (ret != 0) {
            // usually error -16 (-EBUSY) or -7 (E2BIG) is printed here.
            // In this case, we send the single-packet flow via ringbuffer as in the worst case we can have
            // a repeated INTERSECTION of flows (different flows aggregating different packets),
            // which can be re-aggregated at userpace.
            // other possible values https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
            if (trace_messages) {
                bpf_printk("error adding flow %d\n", ret);
            }

            new_flow.errno = -ret;
            flow_record *record =
                (flow_record *)bpf_ringbuf_reserve(&direct_flows, sizeof(flow_record), 0);
            if (!record) {
                if (trace_messages) {
                    bpf_printk("couldn't reserve space in the ringbuf. Dropping flow");
                }
                return TC_ACT_OK;
            }
            record->id = id;
            record->metrics = new_flow;
            bpf_ringbuf_submit(record, 0);
        }
    }
    return TC_ACT_OK;
}

SEC("tc_ingress")
int tc_ingress_flow_parse(struct __sk_buff *skb) {
    return flow_monitor(skb, INGRESS);
}

SEC("tc_egress")
int tc_egress_flow_parse(struct __sk_buff *skb) {
    return flow_monitor(skb, EGRESS);
}

SEC("tcx_ingress")
int tcx_ingress_flow_parse(struct __sk_buff *skb) {
    flow_monitor(skb, INGRESS);
    // return TCX_NEXT to allow existing with other TCX hooks
    return TCX_NEXT;
}

SEC("tcx_egress")
int tcx_egress_flow_parse(struct __sk_buff *skb) {
    flow_monitor(skb, EGRESS);
    // return TCX_NEXT to allow existing with other TCX hooks
    return TCX_NEXT;
}

char _license[] SEC("license") = "GPL";
