// Code generated by bpf2go; DO NOT EDIT.
//go:build s390x

package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type BpfDirectionT uint32

const (
	BpfDirectionTINGRESS       BpfDirectionT = 0
	BpfDirectionTEGRESS        BpfDirectionT = 1
	BpfDirectionTMAX_DIRECTION BpfDirectionT = 2
)

type BpfDnsFlowId struct {
	SrcPort  uint16
	DstPort  uint16
	SrcIp    [16]uint8
	DstIp    [16]uint8
	Id       uint16
	Protocol uint8
}

type BpfDnsRecordT struct {
	Id      uint16
	Flags   uint16
	Latency uint64
	Errno   uint8
}

type BpfFilterActionT uint32

const (
	BpfFilterActionTACCEPT             BpfFilterActionT = 0
	BpfFilterActionTREJECT             BpfFilterActionT = 1
	BpfFilterActionTMAX_FILTER_ACTIONS BpfFilterActionT = 2
)

type BpfFilterKeyT struct {
	PrefixLen uint32
	IpData    [16]uint8
}

type BpfFilterValueT struct {
	Protocol     uint8
	DstPortStart uint16
	DstPortEnd   uint16
	DstPort1     uint16
	DstPort2     uint16
	SrcPortStart uint16
	SrcPortEnd   uint16
	SrcPort1     uint16
	SrcPort2     uint16
	PortStart    uint16
	PortEnd      uint16
	Port1        uint16
	Port2        uint16
	IcmpType     uint8
	IcmpCode     uint8
	Direction    BpfDirectionT
	Action       BpfFilterActionT
	TcpFlags     BpfTcpFlagsT
	FilterDrops  uint8
	Ip           [16]uint8
}

type BpfFlowId BpfFlowIdT

type BpfFlowIdT struct {
	SrcIp             [16]uint8
	DstIp             [16]uint8
	SrcPort           uint16
	DstPort           uint16
	TransportProtocol uint8
	IcmpType          uint8
	IcmpCode          uint8
}

type BpfFlowMetrics BpfFlowMetricsT

type BpfFlowMetricsT struct {
	EthProtocol      uint16
	ObservedIntf     [4]BpfPktObservationT
	NbObservedIntf   uint8
	ObservedSrcIps   [4][4]uint8
	NbObservedSrcIps uint8
	ObservedDstIps   [4][4]uint8
	NbObservedDstIps uint8
	SrcMac           [6]uint8
	DstMac           [6]uint8
	Packets          uint32
	Bytes            uint64
	StartMonoTimeTs  uint64
	EndMonoTimeTs    uint64
	Flags            uint16
	Errno            uint8
	Dscp             uint8
	PktDrops         BpfPktDropsT
	DnsRecord        BpfDnsRecordT
	FlowRtt          uint64
	NetworkEventsIdx uint8
	NetworkEvents    [4][8]uint8
}

type BpfFlowRecordT struct {
	Id      BpfFlowId
	Metrics BpfFlowMetrics
}

type BpfGlobalCountersKeyT uint32

const (
	BpfGlobalCountersKeyTHASHMAP_FLOWS_DROPPED               BpfGlobalCountersKeyT = 0
	BpfGlobalCountersKeyTHASHMAP_PACKETS_CANT_UPDATE         BpfGlobalCountersKeyT = 1
	BpfGlobalCountersKeyTHASHMAP_PACKETS_CANT_DELETE         BpfGlobalCountersKeyT = 2
	BpfGlobalCountersKeyTFILTER_REJECT                       BpfGlobalCountersKeyT = 3
	BpfGlobalCountersKeyTFILTER_ACCEPT                       BpfGlobalCountersKeyT = 4
	BpfGlobalCountersKeyTFILTER_NOMATCH                      BpfGlobalCountersKeyT = 5
	BpfGlobalCountersKeyTNETWORK_EVENTS_ERR                  BpfGlobalCountersKeyT = 6
	BpfGlobalCountersKeyTNETWORK_EVENTS_ERR_GROUPID_MISMATCH BpfGlobalCountersKeyT = 7
	BpfGlobalCountersKeyTNETWORK_EVENTS_ERR_UPDATE_MAP_FLOWS BpfGlobalCountersKeyT = 8
	BpfGlobalCountersKeyTNETWORK_EVENTS_GOOD                 BpfGlobalCountersKeyT = 9
	BpfGlobalCountersKeyTPKT_MAP_HIT                         BpfGlobalCountersKeyT = 10
	BpfGlobalCountersKeyTPKT_MAP_MISS                        BpfGlobalCountersKeyT = 11
	BpfGlobalCountersKeyTPKT_MAP_AVOID_POTENTIAL_COLLISION   BpfGlobalCountersKeyT = 12
	BpfGlobalCountersKeyTPKT_MAP_POTENTIAL_DUPLICATION       BpfGlobalCountersKeyT = 13
	BpfGlobalCountersKeyTMARK_0                              BpfGlobalCountersKeyT = 14
	BpfGlobalCountersKeyTMARK_SEEN                           BpfGlobalCountersKeyT = 15
	BpfGlobalCountersKeyTMARK_OTHER                          BpfGlobalCountersKeyT = 16
	BpfGlobalCountersKeyTMAX_COUNTERS                        BpfGlobalCountersKeyT = 17
)

type BpfPktDropsT struct {
	Packets         uint32
	Bytes           uint64
	LatestFlags     uint16
	LatestState     uint8
	LatestDropCause uint32
}

type BpfPktId struct {
	SkbRef uint64
	Hash   uint32
	Tstamp uint64
}

type BpfPktObservationT struct {
	Direction uint8
	IfIndex   uint32
}

type BpfTcpFlagsT uint32

const (
	BpfTcpFlagsTFIN_FLAG     BpfTcpFlagsT = 1
	BpfTcpFlagsTSYN_FLAG     BpfTcpFlagsT = 2
	BpfTcpFlagsTRST_FLAG     BpfTcpFlagsT = 4
	BpfTcpFlagsTPSH_FLAG     BpfTcpFlagsT = 8
	BpfTcpFlagsTACK_FLAG     BpfTcpFlagsT = 16
	BpfTcpFlagsTURG_FLAG     BpfTcpFlagsT = 32
	BpfTcpFlagsTECE_FLAG     BpfTcpFlagsT = 64
	BpfTcpFlagsTCWR_FLAG     BpfTcpFlagsT = 128
	BpfTcpFlagsTSYN_ACK_FLAG BpfTcpFlagsT = 256
	BpfTcpFlagsTFIN_ACK_FLAG BpfTcpFlagsT = 512
	BpfTcpFlagsTRST_ACK_FLAG BpfTcpFlagsT = 1024
)

// LoadBpf returns the embedded CollectionSpec for Bpf.
func LoadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load Bpf: %w", err)
	}

	return spec, err
}

// LoadBpfObjects loads Bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*BpfObjects
//	*BpfPrograms
//	*BpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func LoadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := LoadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// BpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfSpecs struct {
	BpfProgramSpecs
	BpfMapSpecs
}

// BpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfProgramSpecs struct {
	KfreeSkb                  *ebpf.ProgramSpec `ebpf:"kfree_skb"`
	RhNetworkEventsMonitoring *ebpf.ProgramSpec `ebpf:"rh_network_events_monitoring"`
	TcEgressFlowParse         *ebpf.ProgramSpec `ebpf:"tc_egress_flow_parse"`
	TcEgressPcaParse          *ebpf.ProgramSpec `ebpf:"tc_egress_pca_parse"`
	TcIngressFlowParse        *ebpf.ProgramSpec `ebpf:"tc_ingress_flow_parse"`
	TcIngressPcaParse         *ebpf.ProgramSpec `ebpf:"tc_ingress_pca_parse"`
	TcpRcvFentry              *ebpf.ProgramSpec `ebpf:"tcp_rcv_fentry"`
	TcpRcvKprobe              *ebpf.ProgramSpec `ebpf:"tcp_rcv_kprobe"`
	TcxEgressFlowParse        *ebpf.ProgramSpec `ebpf:"tcx_egress_flow_parse"`
	TcxEgressPcaParse         *ebpf.ProgramSpec `ebpf:"tcx_egress_pca_parse"`
	TcxIngressFlowParse       *ebpf.ProgramSpec `ebpf:"tcx_ingress_flow_parse"`
	TcxIngressPcaParse        *ebpf.ProgramSpec `ebpf:"tcx_ingress_pca_parse"`
}

// BpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type BpfMapSpecs struct {
	AggregatedFlows *ebpf.MapSpec `ebpf:"aggregated_flows"`
	DirectFlows     *ebpf.MapSpec `ebpf:"direct_flows"`
	DnsFlows        *ebpf.MapSpec `ebpf:"dns_flows"`
	FilterMap       *ebpf.MapSpec `ebpf:"filter_map"`
	GlobalCounters  *ebpf.MapSpec `ebpf:"global_counters"`
	PacketRecord    *ebpf.MapSpec `ebpf:"packet_record"`
	PktFlowMap      *ebpf.MapSpec `ebpf:"pkt_flow_map"`
}

// BpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfObjects struct {
	BpfPrograms
	BpfMaps
}

func (o *BpfObjects) Close() error {
	return _BpfClose(
		&o.BpfPrograms,
		&o.BpfMaps,
	)
}

// BpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfMaps struct {
	AggregatedFlows *ebpf.Map `ebpf:"aggregated_flows"`
	DirectFlows     *ebpf.Map `ebpf:"direct_flows"`
	DnsFlows        *ebpf.Map `ebpf:"dns_flows"`
	FilterMap       *ebpf.Map `ebpf:"filter_map"`
	GlobalCounters  *ebpf.Map `ebpf:"global_counters"`
	PacketRecord    *ebpf.Map `ebpf:"packet_record"`
	PktFlowMap      *ebpf.Map `ebpf:"pkt_flow_map"`
}

func (m *BpfMaps) Close() error {
	return _BpfClose(
		m.AggregatedFlows,
		m.DirectFlows,
		m.DnsFlows,
		m.FilterMap,
		m.GlobalCounters,
		m.PacketRecord,
		m.PktFlowMap,
	)
}

// BpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfPrograms struct {
	KfreeSkb                  *ebpf.Program `ebpf:"kfree_skb"`
	RhNetworkEventsMonitoring *ebpf.Program `ebpf:"rh_network_events_monitoring"`
	TcEgressFlowParse         *ebpf.Program `ebpf:"tc_egress_flow_parse"`
	TcEgressPcaParse          *ebpf.Program `ebpf:"tc_egress_pca_parse"`
	TcIngressFlowParse        *ebpf.Program `ebpf:"tc_ingress_flow_parse"`
	TcIngressPcaParse         *ebpf.Program `ebpf:"tc_ingress_pca_parse"`
	TcpRcvFentry              *ebpf.Program `ebpf:"tcp_rcv_fentry"`
	TcpRcvKprobe              *ebpf.Program `ebpf:"tcp_rcv_kprobe"`
	TcxEgressFlowParse        *ebpf.Program `ebpf:"tcx_egress_flow_parse"`
	TcxEgressPcaParse         *ebpf.Program `ebpf:"tcx_egress_pca_parse"`
	TcxIngressFlowParse       *ebpf.Program `ebpf:"tcx_ingress_flow_parse"`
	TcxIngressPcaParse        *ebpf.Program `ebpf:"tcx_ingress_pca_parse"`
}

func (p *BpfPrograms) Close() error {
	return _BpfClose(
		p.KfreeSkb,
		p.RhNetworkEventsMonitoring,
		p.TcEgressFlowParse,
		p.TcEgressPcaParse,
		p.TcIngressFlowParse,
		p.TcIngressPcaParse,
		p.TcpRcvFentry,
		p.TcpRcvKprobe,
		p.TcxEgressFlowParse,
		p.TcxEgressPcaParse,
		p.TcxIngressFlowParse,
		p.TcxIngressPcaParse,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_s390_bpfeb.o
var _BpfBytes []byte
