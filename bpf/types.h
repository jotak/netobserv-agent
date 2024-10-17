#ifndef __TYPES_H__
#define __TYPES_H__

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_UNSPEC -1
#define IP_MAX_LEN 16

#define DISCARD 1
#define SUBMIT 0

// Flags according to RFC 9293 & https://www.iana.org/assignments/ipfix/ipfix.xhtml
typedef enum tcp_flags_t {
    FIN_FLAG = 0x01,
    SYN_FLAG = 0x02,
    RST_FLAG = 0x04,
    PSH_FLAG = 0x08,
    ACK_FLAG = 0x10,
    URG_FLAG = 0x20,
    ECE_FLAG = 0x40,
    CWR_FLAG = 0x80,
    // Custom flags exported
    SYN_ACK_FLAG = 0x100,
    FIN_ACK_FLAG = 0x200,
    RST_ACK_FLAG = 0x400,
} tcp_flags;
// Force emitting enum tcp_flags_t into the ELF.
const enum tcp_flags_t *unused10 __attribute__((unused));

#if defined(__BYTE_ORDER__) && defined(__ORDER_LITTLE_ENDIAN__) &&                                 \
    __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#elif defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) &&                                  \
    __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_ntohs(x) (x)
#define bpf_htons(x) (x)
#define bpf_ntohl(x) (x)
#define bpf_htonl(x) (x)
#else
#error "Endianness detection needs to be set up for your compiler?!"
#endif

typedef __u8 u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;

#define AF_INET 2
#define AF_INET6 10
#define ETH_ALEN 6
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_ARP 0x0806
#define IPPROTO_ICMPV6 58
#define DSCP_SHIFT 2
#define DSCP_MASK 0x3F
#define MIN_RTT 10000u //10us

#define MAX_FILTER_ENTRIES 1 // we have only one global filter
#define MAX_EVENT_MD 8
#define MAX_NETWORK_EVENTS 4

// according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
typedef enum direction_t {
    INGRESS,
    EGRESS,
    MAX_DIRECTION = 2,
} direction;
// Force emitting enum direction_t into the ELF.
const enum direction_t *unused8 __attribute__((unused));

const u8 ip4in6[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

typedef struct flow_metrics_t {
    u32 packets;
    u64 bytes;
    // Flow start and end times as monotomic timestamps in nanoseconds
    // as output from bpf_ktime_get_ns()
    u64 start_mono_time_ts;
    u64 end_mono_time_ts;
    // TCP Flags from https://www.ietf.org/rfc/rfc793.txt
    u16 flags;
    // The positive errno of a failed map insertion that caused a flow
    // to be sent via ringbuffer.
    // 0 otherwise
    // https://chromium.googlesource.com/chromiumos/docs/+/master/constants/errnos.md
    u8 errno;
    u8 dscp;
    struct pkt_drops_t {
        u32 packets;
        u64 bytes;
        u16 latest_flags;
        u8 latest_state;
        u32 latest_drop_cause;
    } __attribute__((packed)) pkt_drops;
    struct dns_record_t {
        u16 id;
        u16 flags;
        u64 latency;
        u8 errno;
    } __attribute__((packed)) dns_record;
    u64 flow_rtt;
    u8 network_events_idx;
    u8 network_events[MAX_NETWORK_EVENTS][MAX_EVENT_MD];
    struct translated_flow_t {
        u8 saddr[IP_MAX_LEN];
        u8 daddr[IP_MAX_LEN];
        u16 sport;
        u16 dport;
        u16 zone_id;
        u8 icmp_id;
    } __attribute__((packed)) translated_flow;
} __attribute__((packed)) flow_metrics;

// Force emitting struct pkt_drops into the ELF.
const struct pkt_drops_t *unused0 __attribute__((unused));

// Force emitting struct flow_metrics into the ELF.
const struct flow_metrics_t *unused1 __attribute__((unused));

// Attributes that uniquely identify a flow
typedef struct flow_id_t {
    u16 eth_protocol;
    u8 direction;
    // L2 data link layer
    u8 src_mac[ETH_ALEN];
    u8 dst_mac[ETH_ALEN];
    // L3 network layer
    // IPv4 addresses are encoded as IPv6 addresses with prefix ::ffff/96
    // as described in https://datatracker.ietf.org/doc/html/rfc4038#section-4.2
    u8 src_ip[IP_MAX_LEN];
    u8 dst_ip[IP_MAX_LEN];
    // L4 transport layer
    u16 src_port;
    u16 dst_port;
    u8 transport_protocol;
    // ICMP protocol
    u8 icmp_type;
    u8 icmp_code;
    // OS interface index
    u32 if_index;
} __attribute__((packed)) flow_id;

// Force emitting struct flow_id into the ELF.
const struct flow_id_t *unused2 __attribute__((unused));

// Flow record is a tuple containing both flow identifier and metrics. It is used to send
// a complete flow via ring buffer when only when the accounting hashmap is full.
// Contents in this struct must match byte-by-byte with Go's pkc/flow/Record struct
typedef struct flow_record_t {
    flow_id id;
    flow_metrics metrics;
} __attribute__((packed)) flow_record;

// Force emitting struct flow_record into the ELF.
const struct flow_record_t *unused3 __attribute__((unused));

// Force emitting struct dns_record into the ELF.
const struct dns_record_t *unused4 __attribute__((unused));

// Internal structure: Packet info structure parsed around functions.
typedef struct pkt_info_t {
    flow_id *id;
    u64 current_ts; // ts recorded when pkt came.
    u16 flags;      // TCP specific
    void *l4_hdr;   // Stores the actual l4 header
    u8 dscp;        // IPv4/6 DSCP value
    u16 dns_id;
    u16 dns_flags;
    u64 dns_latency;
} pkt_info;

// Structure for payload metadata
typedef struct payload_meta_t {
    u32 if_index;
    u32 pkt_len;
    u64 timestamp; // timestamp when packet received by ebpf
} __attribute__((packed)) payload_meta;

// DNS Flow record used as key to correlate DNS query and response
typedef struct dns_flow_id_t {
    u16 src_port;
    u16 dst_port;
    u8 src_ip[IP_MAX_LEN];
    u8 dst_ip[IP_MAX_LEN];
    u16 id;
    u8 protocol;
} __attribute__((packed)) dns_flow_id;

// Enum to define global counters keys and share it with userspace
typedef enum global_counters_key_t {
    HASHMAP_FLOWS_DROPPED,
    FILTER_REJECT,
    FILTER_ACCEPT,
    FILTER_NOMATCH,
    NETWORK_EVENTS_ERR,
    NETWORK_EVENTS_ERR_GROUPID_MISMATCH,
    NETWORK_EVENTS_ERR_UPDATE_MAP_FLOWS,
    NETWORK_EVENTS_GOOD,
    MAX_COUNTERS,
} global_counters_key;

// Force emitting enum global_counters_key_t into the ELF.
const enum global_counters_key_t *unused5 __attribute__((unused));

// filter key used as key to LPM map to filter out flows that are not interesting for the user
struct filter_key_t {
    u32 prefix_len;
    u8 ip_data[IP_MAX_LEN];
} __attribute__((packed));
// Force emitting struct filter_key_t into the ELF.
const struct filter_key_t *unused6 __attribute__((unused));

// Enum to define filter action
typedef enum filter_action_t {
    ACCEPT,
    REJECT,
    MAX_FILTER_ACTIONS,
} filter_action;
// Force emitting enum direction_t into the ELF.
const enum filter_action_t *unused7 __attribute__((unused));

// filter value used as value from LPM map lookup to filter out flows that are not interesting for the user
struct filter_value_t {
    u8 protocol;
    u16 dstPortStart;
    u16 dstPortEnd;
    u16 dstPort1;
    u16 dstPort2;
    u16 srcPortStart;
    u16 srcPortEnd;
    u16 srcPort1;
    u16 srcPort2;
    u16 portStart;
    u16 portEnd;
    u16 port1;
    u16 port2;
    u8 icmpType;
    u8 icmpCode;
    direction direction;
    filter_action action;
    tcp_flags tcpFlags;
    u8 filter_drops;
    u8 ip[IP_MAX_LEN];
} __attribute__((packed));
// Force emitting struct filter_value_t into the ELF.
const struct filter_value_t *unused9 __attribute__((unused));

// Force emitting struct translated_flow_t into the ELF.
const struct translated_flow_t *unused11 __attribute__((unused));

#endif /* __TYPES_H__ */
