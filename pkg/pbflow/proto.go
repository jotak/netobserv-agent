package pbflow

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	ovnobserv "github.com/ovn-org/ovn-kubernetes/go-controller/observability-lib/sampledecoder"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var protoLog = logrus.WithField("component", "pbflow")

// FlowsToPB is an auxiliary function to convert flow records, as returned by the eBPF agent,
// into protobuf-encoded messages ready to be sent to the collector via GRPC
func FlowsToPB(inputRecords []*model.Record, maxLen int, s *ovnobserv.SampleDecoder) []*Records {
	entries := make([]*Record, 0, len(inputRecords))
	for _, record := range inputRecords {
		entries = append(entries, FlowToPB(record, s))
	}
	var records []*Records
	for len(entries) > 0 {
		end := len(entries)
		if end > maxLen {
			end = maxLen
		}
		records = append(records, &Records{Entries: entries[:end]})
		entries = entries[end:]
	}
	return records
}

// FlowToPB is an auxiliary function to convert a single flow record, as returned by the eBPF agent,
// into a protobuf-encoded message ready to be sent to the collector via kafka
func FlowToPB(fr *model.Record, s *ovnobserv.SampleDecoder) *Record {
	var pbflowRecord = Record{
		EthProtocol: uint32(fr.Metrics.EthProtocol),
		DataLink: &DataLink{
			SrcMac: macToUint64(&fr.Metrics.SrcMac),
			DstMac: macToUint64(&fr.Metrics.DstMac),
		},
		Network: &Network{
			Dscp: uint32(fr.Metrics.Dscp),
		},
		Transport: &Transport{
			Protocol: uint32(fr.Id.TransportProtocol),
			SrcPort:  uint32(fr.Id.SrcPort),
			DstPort:  uint32(fr.Id.DstPort),
		},
		IcmpType: uint32(fr.Id.IcmpType),
		IcmpCode: uint32(fr.Id.IcmpCode),
		Bytes:    fr.Metrics.Bytes,
		TimeFlowStart: &timestamppb.Timestamp{
			Seconds: fr.TimeFlowStart.Unix(),
			Nanos:   int32(fr.TimeFlowStart.Nanosecond()),
		},
		TimeFlowEnd: &timestamppb.Timestamp{
			Seconds: fr.TimeFlowEnd.Unix(),
			Nanos:   int32(fr.TimeFlowEnd.Nanosecond()),
		},
		Packets:                uint64(fr.Metrics.Packets),
		AgentIp:                agentIP(fr.AgentIP),
		Flags:                  uint32(fr.Metrics.Flags),
		PktDropBytes:           fr.Metrics.PktDrops.Bytes,
		PktDropPackets:         uint64(fr.Metrics.PktDrops.Packets),
		PktDropLatestFlags:     uint32(fr.Metrics.PktDrops.LatestFlags),
		PktDropLatestState:     uint32(fr.Metrics.PktDrops.LatestState),
		PktDropLatestDropCause: fr.Metrics.PktDrops.LatestDropCause,
		DnsId:                  uint32(fr.Metrics.DnsRecord.Id),
		DnsFlags:               uint32(fr.Metrics.DnsRecord.Flags),
		DnsErrno:               uint32(fr.Metrics.DnsRecord.Errno),
		TimeFlowRtt:            durationpb.New(fr.TimeFlowRtt),
		Xlat: &Xlat{
			SrcPort: uint32(fr.Metrics.TranslatedFlow.Sport),
			DstPort: uint32(fr.Metrics.TranslatedFlow.Dport),
			ZoneId:  uint32(fr.Metrics.TranslatedFlow.ZoneId),
			IcmpId:  uint32(fr.Metrics.TranslatedFlow.IcmpId),
		},
	}
	if fr.Metrics.DnsRecord.Latency != 0 {
		pbflowRecord.DnsLatency = durationpb.New(fr.DNSLatency)
	}
	if fr.Metrics.NbObservedIntf > 0 {
		pbflowRecord.DupList = make([]*DupMapEntry, 0)
		for i := 0; i < int(fr.Metrics.NbObservedIntf); i++ {
			o := fr.Metrics.ObservedIntf[i]
			var intf string
			if i < len(fr.Interfaces) {
				intf = fr.Interfaces[i]
			}
			pbflowRecord.DupList = append(pbflowRecord.DupList, &DupMapEntry{
				Interface: intf,
				Direction: Direction(o.Direction),
			})
		}
	}
	if fr.Metrics.NbObservedSrcIps > 0 {
		pbflowRecord.AdditionalSrcAddr = make([]*IP, 0)
		for i := 0; i < int(fr.Metrics.NbObservedSrcIps); i++ {
			ip := &IP{IpFamily: &IP_Ipv4{Ipv4: binary.BigEndian.Uint32(fr.Metrics.ObservedSrcIps[i][:])}}
			pbflowRecord.AdditionalSrcAddr = append(pbflowRecord.AdditionalSrcAddr, ip)
		}
	}
	if fr.Metrics.NbObservedDstIps > 0 {
		pbflowRecord.AdditionalDstAddr = make([]*IP, 0)
		for i := 0; i < int(fr.Metrics.NbObservedDstIps); i++ {
			ip := &IP{IpFamily: &IP_Ipv4{Ipv4: binary.BigEndian.Uint32(fr.Metrics.ObservedDstIps[i][:])}}
			pbflowRecord.AdditionalDstAddr = append(pbflowRecord.AdditionalDstAddr, ip)
		}
	}
	if fr.Metrics.EthProtocol == model.IPv6Type {
		pbflowRecord.Network.SrcAddr = &IP{IpFamily: &IP_Ipv6{Ipv6: fr.Id.SrcIp[:]}}
		pbflowRecord.Network.DstAddr = &IP{IpFamily: &IP_Ipv6{Ipv6: fr.Id.DstIp[:]}}
		pbflowRecord.Xlat.SrcAddr = &IP{IpFamily: &IP_Ipv6{Ipv6: fr.Metrics.TranslatedFlow.Saddr[:]}}
		pbflowRecord.Xlat.DstAddr = &IP{IpFamily: &IP_Ipv6{Ipv6: fr.Metrics.TranslatedFlow.Daddr[:]}}
	} else {
		pbflowRecord.Network.SrcAddr = &IP{IpFamily: &IP_Ipv4{Ipv4: model.IntEncodeV4(fr.Id.SrcIp)}}
		pbflowRecord.Network.DstAddr = &IP{IpFamily: &IP_Ipv4{Ipv4: model.IntEncodeV4(fr.Id.DstIp)}}
		pbflowRecord.Xlat.SrcAddr = &IP{IpFamily: &IP_Ipv4{Ipv4: model.IntEncodeV4(fr.Metrics.TranslatedFlow.Saddr)}}
		pbflowRecord.Xlat.DstAddr = &IP{IpFamily: &IP_Ipv4{Ipv4: model.IntEncodeV4(fr.Metrics.TranslatedFlow.Daddr)}}
	}
	if s != nil {
		seen := make(map[string]bool)
		for _, metadata := range fr.Metrics.NetworkEvents {
			if !model.AllZerosMetaData(metadata) {
				if md, err := s.DecodeCookie8Bytes(metadata); err == nil {
					protoLog.Debugf("Network Events Metadata %v decoded Cookie: %v", metadata, md)
					if !seen[md] {
						pbflowRecord.NetworkEventsMetadata = append(pbflowRecord.NetworkEventsMetadata, md)
						seen[md] = true
					}
				} else {
					protoLog.Errorf("unable to decode Network events cookie: %v", err)
				}
			}
		}
		zoneIDtoUdnIDMap, err := s.GetConntrackZoneToUDN()
		if err != nil {
			protoLog.Errorf("unable to get zoneIDtoUdnIdMap: %v", err)
		} else {
			if udnID, ok := zoneIDtoUdnIDMap[fmt.Sprint(fr.Metrics.TranslatedFlow.ZoneId)]; ok {
				pbflowRecord.Xlat.UdnId = udnID
				protoLog.Debugf("Packet Xlation zoneID %d mapped to udnID %s", fr.Metrics.TranslatedFlow.ZoneId, udnID)
			} else {
				protoLog.Errorf("unable to find zoneId %d in ZoneID2UdnID map", fr.Metrics.TranslatedFlow.ZoneId)
			}
		}
	}
	return &pbflowRecord
}

func PBToFlow(pb *Record) *model.Record {
	if pb == nil {
		return nil
	}
	out := model.Record{
		RawRecord: model.RawRecord{
			Id: ebpf.BpfFlowId{
				TransportProtocol: uint8(pb.Transport.Protocol),
				SrcIp:             ipToIPAddr(pb.Network.GetSrcAddr()),
				DstIp:             ipToIPAddr(pb.Network.GetDstAddr()),
				SrcPort:           uint16(pb.Transport.SrcPort),
				DstPort:           uint16(pb.Transport.DstPort),
				IcmpType:          uint8(pb.IcmpType),
				IcmpCode:          uint8(pb.IcmpCode),
			},
			Metrics: ebpf.BpfFlowMetrics{
				EthProtocol: uint16(pb.EthProtocol),
				SrcMac:      macToUint8(pb.DataLink.GetSrcMac()),
				DstMac:      macToUint8(pb.DataLink.GetDstMac()),
				Bytes:       pb.Bytes,
				Packets:     uint32(pb.Packets),
				Flags:       uint16(pb.Flags),
				Dscp:        uint8(pb.Network.Dscp),
				PktDrops: ebpf.BpfPktDropsT{
					Bytes:           pb.PktDropBytes,
					Packets:         uint32(pb.PktDropPackets),
					LatestFlags:     uint16(pb.PktDropLatestFlags),
					LatestState:     uint8(pb.PktDropLatestState),
					LatestDropCause: pb.PktDropLatestDropCause,
				},
				DnsRecord: ebpf.BpfDnsRecordT{
					Id:      uint16(pb.DnsId),
					Flags:   uint16(pb.DnsFlags),
					Errno:   uint8(pb.DnsErrno),
					Latency: uint64(pb.DnsLatency.AsDuration()),
				},
				TranslatedFlow: ebpf.BpfTranslatedFlowT{
					Saddr:  ipToIPAddr(pb.Xlat.GetSrcAddr()),
					Daddr:  ipToIPAddr(pb.Xlat.GetDstAddr()),
					Sport:  uint16(pb.Xlat.GetSrcPort()),
					Dport:  uint16(pb.Xlat.GetDstPort()),
					ZoneId: uint16(pb.Xlat.GetZoneId()),
					IcmpId: uint8(pb.Xlat.GetIcmpId()),
				},
			},
		},
		TimeFlowStart: pb.TimeFlowStart.AsTime(),
		TimeFlowEnd:   pb.TimeFlowEnd.AsTime(),
		AgentIP:       pbIPToNetIP(pb.AgentIp),
		TimeFlowRtt:   pb.TimeFlowRtt.AsDuration(),
		DNSLatency:    pb.DnsLatency.AsDuration(),
	}

	out.Metrics.NbObservedIntf = uint8(len(pb.GetDupList()))
	for i, entry := range pb.GetDupList() {
		intf := entry.Interface
		dir := uint8(entry.Direction)
		out.Metrics.ObservedIntf[i] = ebpf.BpfPktObservationT{Direction: dir}
		out.Interfaces = append(out.Interfaces, intf)
	}
	out.Metrics.NbObservedSrcIps = uint8(len(pb.GetAdditionalSrcAddr()))
	for i, ip := range pb.GetAdditionalSrcAddr() {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, ip.GetIpv4())
		out.Metrics.ObservedSrcIps[i] = [4]uint8(b)
	}
	out.Metrics.NbObservedDstIps = uint8(len(pb.GetAdditionalDstAddr()))
	for i, ip := range pb.GetAdditionalDstAddr() {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, ip.GetIpv4())
		out.Metrics.ObservedDstIps[i] = [4]uint8(b)
	}
	if len(pb.GetNetworkEventsMetadata()) != 0 {
		out.NetworkMonitorEventsMD = append(out.NetworkMonitorEventsMD, pb.GetNetworkEventsMetadata()...)
		protoLog.Debugf("decoded Network events monitor metadata: %v", out.NetworkMonitorEventsMD)
	}

	if len(pb.GetXlat().UdnId) != 0 {
		out.UdnID = pb.GetXlat().UdnId
	}
	return &out
}

// Mac bytes are encoded in the same order as in the array. This is, a Mac
// like 11:22:33:44:55:66 will be encoded as 0x112233445566
func macToUint64(m *[model.MacLen]uint8) uint64 {
	return uint64(m[5]) |
		(uint64(m[4]) << 8) |
		(uint64(m[3]) << 16) |
		(uint64(m[2]) << 24) |
		(uint64(m[1]) << 32) |
		(uint64(m[0]) << 40)
}

func agentIP(nip net.IP) *IP {
	if ip := nip.To4(); ip != nil {
		return &IP{IpFamily: &IP_Ipv4{Ipv4: binary.BigEndian.Uint32(ip)}}
	}
	// IPv6 address
	return &IP{IpFamily: &IP_Ipv6{Ipv6: nip}}
}

func pbIPToNetIP(ip *IP) net.IP {
	if ip.GetIpv6() != nil {
		return net.IP(ip.GetIpv6())
	}
	n := ip.GetIpv4()
	return net.IPv4(
		byte((n>>24)&0xFF),
		byte((n>>16)&0xFF),
		byte((n>>8)&0xFF),
		byte(n&0xFF))
}

func ipToIPAddr(ip *IP) model.IPAddr {
	return model.IPAddrFromNetIP(pbIPToNetIP(ip))
}

func macToUint8(mac uint64) [6]uint8 {
	return [6]uint8{
		uint8(mac >> 40),
		uint8(mac >> 32),
		uint8(mac >> 24),
		uint8(mac >> 16),
		uint8(mac >> 8),
		uint8(mac),
	}
}
