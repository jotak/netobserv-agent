package model

import "github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"

type BpfFlowPayload struct {
	*ebpf.BpfFlowMetrics
	*ebpf.BpfAdditionalMetrics
	*ebpf.BpfObservations
}

type BpfFlowPayloads []BpfFlowPayload

func (a *BpfFlowPayloads) Accumulate() BpfFlowPayload {
	res := BpfFlowPayload{}
	for _, p := range *a {
		res.AccumulateBase(p.BpfFlowMetrics)
		res.AccumulateAdditional(p.BpfAdditionalMetrics)
		res.AccumulateObservation(p.BpfObservations)
	}
	return res
}

func (p *BpfFlowPayload) AccumulateBase(other *ebpf.BpfFlowMetrics) {
	p.BpfFlowMetrics = accumulateBase(p.BpfFlowMetrics, other)
}

func (p *BpfFlowPayload) AccumulateAdditional(other *ebpf.BpfAdditionalMetrics) {
	p.BpfAdditionalMetrics = accumulateAdditional(p.BpfAdditionalMetrics, other)
}

func (p *BpfFlowPayload) AccumulateObservation(other *ebpf.BpfObservations) {
	p.BpfObservations = accumulateObs(p.BpfObservations, other)
}

// TODO: merge in AccumulateBase
func accumulateBase(p *ebpf.BpfFlowMetrics, other *ebpf.BpfFlowMetrics) *ebpf.BpfFlowMetrics {
	if other == nil {
		return p
	}
	if p == nil {
		return other
	}
	// time == 0 if the value has not been yet set
	if p.StartMonoTimeTs == 0 || (p.StartMonoTimeTs > other.StartMonoTimeTs && other.StartMonoTimeTs != 0) {
		p.StartMonoTimeTs = other.StartMonoTimeTs
	}
	if p.EndMonoTimeTs == 0 || p.EndMonoTimeTs < other.EndMonoTimeTs {
		p.EndMonoTimeTs = other.EndMonoTimeTs
	}
	p.Bytes += other.Bytes
	p.Packets += other.Packets
	p.Flags |= other.Flags
	if other.EthProtocol != 0 {
		p.EthProtocol = other.EthProtocol
	}
	if allZero(p.SrcMac) {
		p.SrcMac = other.SrcMac
	}
	if allZero(p.DstMac) {
		p.DstMac = other.DstMac
	}
	p.DnsRecord.Flags |= other.DnsRecord.Flags
	if other.DnsRecord.Id != 0 {
		p.DnsRecord.Id = other.DnsRecord.Id
	}
	if p.DnsRecord.Errno != other.DnsRecord.Errno {
		p.DnsRecord.Errno = other.DnsRecord.Errno
	}
	if p.DnsRecord.Latency < other.DnsRecord.Latency {
		p.DnsRecord.Latency = other.DnsRecord.Latency
	}
	if other.Dscp != 0 {
		p.Dscp = other.Dscp
	}
	if other.ZoneId != 0 {
		p.ZoneId = other.ZoneId
	}
	return p
}

func accumulateAdditional(p *ebpf.BpfAdditionalMetrics, other *ebpf.BpfAdditionalMetrics) *ebpf.BpfAdditionalMetrics {
	if other == nil {
		return p
	}
	if p == nil {
		return other
	}
	// Accumulate Drop statistics
	p.PktDrops.Bytes += other.PktDrops.Bytes
	p.PktDrops.Packets += other.PktDrops.Packets
	p.PktDrops.LatestFlags |= other.PktDrops.LatestFlags
	if other.PktDrops.LatestDropCause != 0 {
		p.PktDrops.LatestDropCause = other.PktDrops.LatestDropCause
	}
	// Accumulate RTT
	if p.FlowRtt < other.FlowRtt {
		p.FlowRtt = other.FlowRtt
	}
	for _, md := range other.NetworkEvents {
		if !AllZerosMetaData(md) && !networkEventsMDExist(p.NetworkEvents, md) {
			copy(p.NetworkEvents[p.NetworkEventsIdx][:], md[:])
			p.NetworkEventsIdx = (p.NetworkEventsIdx + 1) % MaxNetworkEvents
		}
	}
	return p
}

func accumulateObs(p *ebpf.BpfObservations, other *ebpf.BpfObservations) *ebpf.BpfObservations {
	if other == nil {
		return p
	}
	if p == nil {
		return other
	}
	// Accumulate interfaces + directions
	accumulateInterfaces(&p.NbObservedIntf, &p.ObservedIntf, other.NbObservedIntf, other.ObservedIntf)
	// Accumulate additional IPs
	accumulateIPPorts(&p.NbObservedSrc, &p.ObservedSrc, other.NbObservedSrc, other.ObservedSrc)
	accumulateIPPorts(&p.NbObservedDst, &p.ObservedDst, other.NbObservedDst, other.ObservedDst)
	return p
}
