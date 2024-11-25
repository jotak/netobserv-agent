package model

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"reflect"
	"time"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
)

// Values according to field 61 in https://www.iana.org/assignments/ipfix/ipfix.xhtml
const (
	DirectionIngress = uint8(0)
	DirectionEgress  = uint8(1)
)
const MacLen = 6

// IPv4Type / IPv6Type value as defined in IEEE 802: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
const (
	IPv6Type                 = 0x86DD
	networkEventsMaxEventsMD = 8
	MaxNetworkEvents         = 4
	MaxObservedIPs           = 3
	MaxObservedInterfaces    = 4
)

type HumanBytes uint64
type MacAddr [MacLen]uint8
type Direction uint8

// IPAddr encodes v4 and v6 IPs with a fixed length.
// IPv4 addresses are encoded as IPv6 addresses with prefix ::ffff/96
// as described in https://datatracker.ietf.org/doc/html/rfc4038#section-4.2
// (same behavior as Go's net.IP type)
type IPAddr [net.IPv6len]uint8

// record structure as parsed from eBPF
type RawRecord ebpf.BpfFlowRecordT

// Record contains accumulated metrics from a flow
type Record struct {
	Id      *ebpf.BpfFlowId
	Metrics *BpfFlowPayload

	// TODO: redundant field from RecordMetrics. Reorganize structs
	TimeFlowStart time.Time
	TimeFlowEnd   time.Time
	DNSLatency    time.Duration
	Interfaces    []string
	// AgentIP provides information about the source of the flow (the Agent that traced it)
	AgentIP net.IP
	// Calculated RTT which is set when record is created by calling NewRecord
	TimeFlowRtt            time.Duration
	NetworkMonitorEventsMD []string
	UdnID                  string
}

func NewRecord(
	key *ebpf.BpfFlowId,
	metrics *BpfFlowPayload,
	currentTime time.Time,
	monotonicCurrentTime uint64,
) *Record {
	startDelta := time.Duration(monotonicCurrentTime - metrics.StartMonoTimeTs)
	endDelta := time.Duration(monotonicCurrentTime - metrics.EndMonoTimeTs)

	var record = Record{
		Id:            key,
		Metrics:       metrics,
		TimeFlowStart: currentTime.Add(-startDelta),
		TimeFlowEnd:   currentTime.Add(-endDelta),
	}
	if metrics.FlowRtt != 0 {
		record.TimeFlowRtt = time.Duration(metrics.FlowRtt)
	}
	if metrics.DnsRecord.Latency != 0 {
		record.DNSLatency = time.Duration(metrics.DnsRecord.Latency)
	}
	record.NetworkMonitorEventsMD = make([]string, 0)
	return &record
}

func AccumulateBaseMetrics(r *ebpf.BpfFlowMetrics, src *ebpf.BpfFlowMetrics) {
	// time == 0 if the value has not been yet set
	if r.StartMonoTimeTs == 0 || (r.StartMonoTimeTs > src.StartMonoTimeTs && src.StartMonoTimeTs != 0) {
		r.StartMonoTimeTs = src.StartMonoTimeTs
	}
	if r.EndMonoTimeTs == 0 || r.EndMonoTimeTs < src.EndMonoTimeTs {
		r.EndMonoTimeTs = src.EndMonoTimeTs
	}
	r.Bytes += src.Bytes
	r.Packets += src.Packets
	r.Flags |= src.Flags
	if src.EthProtocol != 0 {
		r.EthProtocol = src.EthProtocol
	}
	if allZero(r.SrcMac) {
		r.SrcMac = src.SrcMac
	}
	if allZero(r.DstMac) {
		r.DstMac = src.DstMac
	}
	// Accumulate DNS
	r.DnsRecord.Flags |= src.DnsRecord.Flags
	if src.DnsRecord.Id != 0 {
		r.DnsRecord.Id = src.DnsRecord.Id
	}
	if r.DnsRecord.Errno != src.DnsRecord.Errno {
		r.DnsRecord.Errno = src.DnsRecord.Errno
	}
	if r.DnsRecord.Latency < src.DnsRecord.Latency {
		r.DnsRecord.Latency = src.DnsRecord.Latency
	}
	// Accumulate DSCP
	if src.Dscp != 0 {
		r.Dscp = src.Dscp
	}
	if src.ZoneId != 0 {
		r.ZoneId = src.ZoneId
	}
}

func networkEventsMDExist(events [MaxNetworkEvents][networkEventsMaxEventsMD]uint8, md [networkEventsMaxEventsMD]uint8) bool {
	for _, e := range events {
		// TODO: use uint8Equals, more performant?
		if reflect.DeepEqual(e, md) {
			return true
		}
	}
	return false
}

func accumulateInterfaces(dstSize *uint8, dstIntf *[MaxObservedInterfaces]ebpf.BpfObservedIntfT, srcSize uint8, srcIntf [MaxObservedInterfaces]ebpf.BpfObservedIntfT) {
	iObs := uint8(0)
outer:
	for *dstSize < uint8(len(dstIntf)) && iObs < srcSize {
		for u := uint8(0); u < *dstSize; u++ {
			if dstIntf[u].Direction == srcIntf[iObs].Direction &&
				dstIntf[u].IfIndex == srcIntf[iObs].IfIndex {
				// Ignore if already exists
				iObs++
				continue outer
			}
		}
		dstIntf[*dstSize] = srcIntf[iObs]
		*dstSize++
		iObs++
	}
}

func accumulateIPPorts(dstSize *uint8, dstIPPorts *[MaxObservedIPs]ebpf.BpfIpPortT, srcSize uint8, srcIPPorts [MaxObservedIPs]ebpf.BpfIpPortT) {
	iObs := uint8(0)
outer:
	for *dstSize < uint8(len(*dstIPPorts)) && iObs < srcSize {
		for u := uint8(0); u < *dstSize; u++ {
			if uint8Equals(dstIPPorts[u].Addr[:], srcIPPorts[iObs].Addr[:]) {
				// Ignore if already exists
				iObs++
				continue outer
			}
		}
		dstIPPorts[*dstSize] = srcIPPorts[iObs]
		*dstSize++
		iObs++
	}
}

func uint8Equals(a, b []uint8) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// IP returns the net.IP equivalent object
func IP(ia IPAddr) net.IP {
	return ia[:]
}

// IntEncodeV4 encodes an IPv4 address as an integer (in network encoding, big endian).
// It assumes that the passed IP is already IPv4. Otherwise it would just encode the
// last 4 bytes of an IPv6 address
func IntEncodeV4(ia [net.IPv6len]uint8) uint32 {
	return binary.BigEndian.Uint32(ia[net.IPv6len-net.IPv4len : net.IPv6len])
}

// IPAddrFromNetIP returns IPAddr from net.IP
func IPAddrFromNetIP(netIP net.IP) IPAddr {
	var arr [net.IPv6len]uint8
	copy(arr[:], (netIP)[0:net.IPv6len])
	return arr
}

func (ia *IPAddr) MarshalJSON() ([]byte, error) {
	return []byte(`"` + IP(*ia).String() + `"`), nil
}

func (m *MacAddr) String() string {
	return fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", m[0], m[1], m[2], m[3], m[4], m[5])
}

func (m *MacAddr) MarshalJSON() ([]byte, error) {
	return []byte("\"" + m.String() + "\""), nil
}

// ReadFrom reads a Record from a binary source, in LittleEndian order
func ReadFrom(reader io.Reader) (*RawRecord, error) {
	var fr RawRecord
	err := binary.Read(reader, binary.LittleEndian, &fr)
	return &fr, err
}

func AllZerosMetaData(s [networkEventsMaxEventsMD]uint8) bool {
	for _, v := range s {
		if v != 0 {
			return false
		}
	}
	return true
}

func allZero(s [6]uint8) bool {
	for _, v := range s {
		if v != 0 {
			return false
		}
	}
	return true
}
