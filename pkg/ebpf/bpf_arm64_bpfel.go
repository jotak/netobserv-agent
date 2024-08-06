// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64

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
	SrcPortStart uint16
	SrcPortEnd   uint16
	PortStart    uint16
	PortEnd      uint16
	IcmpType     uint8
	IcmpCode     uint8
	Direction    BpfDirectionT
	Action       BpfFilterActionT
	TcpFlags     BpfTcpFlagsT
	Ip           [16]uint8
}

type BpfFlowId BpfFlowIdT

type BpfFlowIdT struct {
	EthProtocol       uint16
	Direction         uint8
	SrcMac            [6]uint8
	DstMac            [6]uint8
	SrcIp             [16]uint8
	DstIp             [16]uint8
	SrcPort           uint16
	DstPort           uint16
	TransportProtocol uint8
	IcmpType          uint8
	IcmpCode          uint8
	IfIndex           uint32
}

type BpfFlowMetrics BpfFlowMetricsT

type BpfFlowMetricsT struct {
	Packets         uint32
	Bytes           uint64
	StartMonoTimeTs uint64
	EndMonoTimeTs   uint64
	Flags           uint16
	Errno           uint8
	Dscp            uint8
	PktDrops        BpfPktDropsT
	DnsRecord       BpfDnsRecordT
	FlowRtt         uint64
}

type BpfFlowRecordT struct {
	Id      BpfFlowId
	Metrics BpfFlowMetrics
}

type BpfGlobalCountersKeyT uint32

const (
	BpfGlobalCountersKeyTHASHMAP_FLOWS_DROPPED_KEY BpfGlobalCountersKeyT = 0
	BpfGlobalCountersKeyTFILTER_REJECT_KEY         BpfGlobalCountersKeyT = 1
	BpfGlobalCountersKeyTFILTER_ACCEPT_KEY         BpfGlobalCountersKeyT = 2
	BpfGlobalCountersKeyTFILTER_NOMATCH_KEY        BpfGlobalCountersKeyT = 3
	BpfGlobalCountersKeyTMAX_DROPPED_FLOWS_KEY     BpfGlobalCountersKeyT = 4
)

type BpfPktDropsT struct {
	Packets         uint32
	Bytes           uint64
	LatestFlags     uint16
	LatestState     uint8
	LatestDropCause uint32
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
	KfreeSkb            *ebpf.ProgramSpec `ebpf:"kfree_skb"`
	TcEgressFlowParse   *ebpf.ProgramSpec `ebpf:"tc_egress_flow_parse"`
	TcEgressPcaParse    *ebpf.ProgramSpec `ebpf:"tc_egress_pca_parse"`
	TcIngressFlowParse  *ebpf.ProgramSpec `ebpf:"tc_ingress_flow_parse"`
	TcIngressPcaParse   *ebpf.ProgramSpec `ebpf:"tc_ingress_pca_parse"`
	TcpRcvFentry        *ebpf.ProgramSpec `ebpf:"tcp_rcv_fentry"`
	TcpRcvKprobe        *ebpf.ProgramSpec `ebpf:"tcp_rcv_kprobe"`
	TcxEgressFlowParse  *ebpf.ProgramSpec `ebpf:"tcx_egress_flow_parse"`
	TcxEgressPcaParse   *ebpf.ProgramSpec `ebpf:"tcx_egress_pca_parse"`
	TcxIngressFlowParse *ebpf.ProgramSpec `ebpf:"tcx_ingress_flow_parse"`
	TcxIngressPcaParse  *ebpf.ProgramSpec `ebpf:"tcx_ingress_pca_parse"`
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
}

func (m *BpfMaps) Close() error {
	return _BpfClose(
		m.AggregatedFlows,
		m.DirectFlows,
		m.DnsFlows,
		m.FilterMap,
		m.GlobalCounters,
		m.PacketRecord,
	)
}

// BpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to LoadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type BpfPrograms struct {
	KfreeSkb            *ebpf.Program `ebpf:"kfree_skb"`
	TcEgressFlowParse   *ebpf.Program `ebpf:"tc_egress_flow_parse"`
	TcEgressPcaParse    *ebpf.Program `ebpf:"tc_egress_pca_parse"`
	TcIngressFlowParse  *ebpf.Program `ebpf:"tc_ingress_flow_parse"`
	TcIngressPcaParse   *ebpf.Program `ebpf:"tc_ingress_pca_parse"`
	TcpRcvFentry        *ebpf.Program `ebpf:"tcp_rcv_fentry"`
	TcpRcvKprobe        *ebpf.Program `ebpf:"tcp_rcv_kprobe"`
	TcxEgressFlowParse  *ebpf.Program `ebpf:"tcx_egress_flow_parse"`
	TcxEgressPcaParse   *ebpf.Program `ebpf:"tcx_egress_pca_parse"`
	TcxIngressFlowParse *ebpf.Program `ebpf:"tcx_ingress_flow_parse"`
	TcxIngressPcaParse  *ebpf.Program `ebpf:"tcx_ingress_pca_parse"`
}

func (p *BpfPrograms) Close() error {
	return _BpfClose(
		p.KfreeSkb,
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
//go:embed bpf_arm64_bpfel.o
var _BpfBytes []byte
