package tracer

import (
	"fmt"
	"net"
	"syscall"

	cilium "github.com/cilium/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
)

type Filters struct {
	config.FiltersV2Config
}

func NewFilters(cfg *config.FiltersV2Config) *Filters {
	return &Filters{FiltersV2Config: *cfg}
}

func (f *Filters) ProgramFilter(objects *ebpf.BpfObjects) error {
	// Set the LPM map with CIDRs
	groupMap := make(map[string]uint16)
	for i, group := range f.Groups {
		groupID := uint16(i + 1)
		groupMap[group.Name] = groupID
		for _, cidr := range group.CIDRs {
			key, err := buildCIDRKey(cidr)
			if err != nil {
				return fmt.Errorf("failed to build CIDR key: %w", err)
			}
			err = objects.CidrMap.Update(key, groupID, cilium.UpdateAny)
			if err != nil {
				return fmt.Errorf("failed to update filter CIDR LPM: %w", err)
			}
		}
	}
	// Set the rules hashmap
	for i := range f.Rules {
		rule := &f.Rules[i]
		log.Infof("Filter rule: %v", rule)
		groupID, found := groupMap[rule.Group]
		if !found {
			return fmt.Errorf("failed to process filter rule %d: group '%s' not defined", i, rule.Group)
		}
		var peers []uint16
		if len(rule.PeerGroups) > 0 {
			for _, peer := range rule.PeerGroups {
				peerGroupID, found := groupMap[peer]
				if !found {
					return fmt.Errorf("failed to process filter rule %d: peer group '%s' not defined", i, peer)
				}
				peers = append(peers, peerGroupID)
			}
		} else {
			peers = []uint16{0}
		}
		for _, peer := range peers {
			key, err := buildRuleKey(groupID, peer)
			if err != nil {
				return fmt.Errorf("failed to build rule key: %w", err)
			}

			val, err := getRuleValue(rule)
			if err != nil {
				return fmt.Errorf("failed to get filter value: %w", err)
			}

			err = objects.FilterRulesMap.Update(key, val, cilium.UpdateAny)
			if err != nil {
				return fmt.Errorf("failed to update filter rules map: %w", err)
			}

			log.Infof("Programmed filter with key: %v, value: %v", key, val)
		}
	}
	return nil
}

func buildCIDRKey(cidr string) (ebpf.BpfFilterCidrKeyT, error) {
	key := ebpf.BpfFilterCidrKeyT{}
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return key, fmt.Errorf("failed to parse CIDR: %w", err)
	}
	if ip.To4() != nil {
		copy(key.IpData[:], ip.To4())
	} else {
		copy(key.IpData[:], ip.To16())
	}
	pfLen, _ := ipNet.Mask.Size()
	key.PrefixLen = uint32(pfLen)
	return key, nil
}

func buildRuleKey(group, peer uint16) (ebpf.BpfFilterRuleKeyT, error) {
	key := ebpf.BpfFilterRuleKeyT{}
	if group < peer {
		key.GroupLow = group
		key.GroupHigh = peer
	} else {
		key.GroupLow = peer
		key.GroupHigh = group
	}
	return key, nil
}

// nolint:cyclop
func getRuleValue(rule *config.FilterRuleConfig) (ebpf.BpfFilterValueT, error) {
	val := ebpf.BpfFilterValueT{}

	switch rule.Direction {
	case "Ingress":
		val.Direction = ebpf.BpfDirectionTINGRESS
	case "Egress":
		val.Direction = ebpf.BpfDirectionTEGRESS
	default:
		val.Direction = ebpf.BpfDirectionTMAX_DIRECTION
	}

	switch rule.Action {
	case "Reject":
		val.Action = ebpf.BpfFilterActionTREJECT
	case "Accept":
		val.Action = ebpf.BpfFilterActionTACCEPT
	default:
		val.Action = ebpf.BpfFilterActionTMAX_FILTER_ACTIONS
	}

	switch rule.Protocol {
	case "TCP":
		val.Protocol = syscall.IPPROTO_TCP
	case "UDP":
		val.Protocol = syscall.IPPROTO_UDP
	case "SCTP":
		val.Protocol = syscall.IPPROTO_SCTP
	case "ICMP":
		val.Protocol = syscall.IPPROTO_ICMP
	case "ICMPv6":
		val.Protocol = syscall.IPPROTO_ICMPV6
	}

	// conversion to fixed size array; it's assumed rule config has been validated against overflow
	val.SrcPorts = [16]uint16(rule.SrcPorts)
	val.DstPorts = [16]uint16(rule.DstPorts)
	val.Ports = [16]uint16(rule.Ports)
	val.IcmpType = uint8(rule.IcmpType)
	val.IcmpCode = uint8(rule.IcmpCode)

	switch rule.TCPFlags {
	case "SYN":
		val.TcpFlags = ebpf.BpfTcpFlagsTSYN_FLAG
	case "SYN-ACK":
		val.TcpFlags = ebpf.BpfTcpFlagsTSYN_ACK_FLAG
	case "ACK":
		val.TcpFlags = ebpf.BpfTcpFlagsTACK_FLAG
	case "FIN":
		val.TcpFlags = ebpf.BpfTcpFlagsTFIN_FLAG
	case "RST":
		val.TcpFlags = ebpf.BpfTcpFlagsTRST_FLAG
	case "PUSH":
		val.TcpFlags = ebpf.BpfTcpFlagsTPSH_FLAG
	case "URG":
		val.TcpFlags = ebpf.BpfTcpFlagsTURG_FLAG
	case "ECE":
		val.TcpFlags = ebpf.BpfTcpFlagsTECE_FLAG
	case "CWR":
		val.TcpFlags = ebpf.BpfTcpFlagsTCWR_FLAG
	case "FIN-ACK":
		val.TcpFlags = ebpf.BpfTcpFlagsTFIN_ACK_FLAG
	case "RST-ACK":
		val.TcpFlags = ebpf.BpfTcpFlagsTRST_ACK_FLAG
	}

	if rule.Drops {
		val.FilterDrops = 1
	}

	if rule.Sample != 0 {
		val.Sample = rule.Sample
	}
	return val, nil
}

func (f *Filters) hasSampling() uint8 {
	for i := range f.Rules {
		if f.Rules[i].Sample > 0 {
			return 1
		}
	}
	return 0
}
