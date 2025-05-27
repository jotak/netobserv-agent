package tracer

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"

	cilium "github.com/cilium/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type FilterConfig struct {
	Direction       string
	IPCIDR          string
	Protocol        string
	SourcePort      intstr.IntOrString
	DestinationPort intstr.IntOrString
	Port            intstr.IntOrString
	IcmpType        int
	IcmpCode        int
	PeerIP          string
	PeerCIDR        string
	Action          string
	TCPFlags        string
	Drops           bool
	Sample          uint32
}

type Filter struct {
	config []*FilterConfig
}

func NewFilter(cfg []*FilterConfig) *Filter {
	return &Filter{config: cfg}
}

func (f *Filter) ProgramFilter(objects *ebpf.BpfObjects) error {
	for _, config := range f.config {
		log.Infof("Flow filter config: %v", f.config)
		key, err := f.getFilterKey(config)
		if err != nil {
			return fmt.Errorf("failed to get filter key: %w", err)
		}

		val, err := f.getFilterValue(config)
		if err != nil {
			return fmt.Errorf("failed to get filter value: %w", err)
		}

		if val.DoPeerCIDR_lookup == 1 {
			peerVal := uint8(1)
			peerKey, err := f.getPeerFilterKey(config)
			if err != nil {
				return fmt.Errorf("failed to get peer filter key: %w", err)
			}
			err = objects.PeerFilterMap.Update(peerKey, peerVal, cilium.UpdateAny)
			if err != nil {
				return fmt.Errorf("failed to update peer filter map: %w", err)
			}
			log.Infof("Programmed filter with PeerCIDR: %v", peerKey)
		}
		err = objects.FilterMap.Update(key, val, cilium.UpdateAny)
		if err != nil {
			return fmt.Errorf("failed to update filter map: %w", err)
		}

		log.Infof("Programmed filter with key: %v, value: %v", key, val)
	}
	return nil
}

func (f *Filter) buildFilterKey(cidr, ipStr string) (ebpf.BpfFilterKeyT, error) {
	key := ebpf.BpfFilterKeyT{}
	if cidr != "" {
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
	} else if ipStr != "" {
		ip := net.ParseIP(ipStr)
		if ip.To4() != nil {
			copy(key.IpData[:], ip.To4())
			key.PrefixLen = 32
		} else {
			copy(key.IpData[:], ip.To16())
			key.PrefixLen = 128
		}
	}
	return key, nil
}

func (f *Filter) getFilterKey(config *FilterConfig) (ebpf.BpfFilterKeyT, error) {
	if config.IPCIDR == "" {
		config.IPCIDR = "0.0.0.0/0"
	}
	return f.buildFilterKey(config.IPCIDR, "")
}

func (f *Filter) getPeerFilterKey(config *FilterConfig) (ebpf.BpfFilterKeyT, error) {
	return f.buildFilterKey(config.PeerCIDR, config.PeerIP)
}

// nolint:cyclop
func (f *Filter) getFilterValue(config *FilterConfig) (ebpf.BpfFilterValueT, error) {
	val := ebpf.BpfFilterValueT{}

	switch config.Direction {
	case "Ingress":
		val.Direction = ebpf.BpfDirectionTINGRESS
	case "Egress":
		val.Direction = ebpf.BpfDirectionTEGRESS
	default:
		val.Direction = ebpf.BpfDirectionTMAX_DIRECTION
	}

	switch config.Action {
	case "Reject":
		val.Action = ebpf.BpfFilterActionTREJECT
	case "Accept":
		val.Action = ebpf.BpfFilterActionTACCEPT
	default:
		val.Action = ebpf.BpfFilterActionTMAX_FILTER_ACTIONS
	}

	switch config.Protocol {
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

	val.DstPortStart, val.DstPortEnd = getDstPortsRange(config)
	val.DstPort1, val.DstPort2 = getDstPorts(config)
	val.SrcPortStart, val.SrcPortEnd = getSrcPortsRange(config)
	val.SrcPort1, val.SrcPort2 = getSrcPorts(config)
	val.PortStart, val.PortEnd = getPortsRange(config)
	val.Port1, val.Port2 = getPorts(config)
	val.IcmpType = uint8(config.IcmpType)
	val.IcmpCode = uint8(config.IcmpCode)

	switch config.TCPFlags {
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

	if config.Drops {
		val.FilterDrops = 1
	}

	if config.Sample != 0 {
		val.Sample = config.Sample
	}
	if config.PeerCIDR != "" || config.PeerIP != "" {
		val.DoPeerCIDR_lookup = 1
	}
	return val, nil
}

func getSrcPortsRange(config *FilterConfig) (uint16, uint16) {
	if config.SourcePort.Type == intstr.Int {
		return uint16(config.SourcePort.IntVal), 0
	}
	start, end, err := getPortsFromString(config.SourcePort.String(), "-")
	if err != nil {
		return 0, 0
	}
	return start, end
}

func getSrcPorts(config *FilterConfig) (uint16, uint16) {
	port1, port2, err := getPortsFromString(config.SourcePort.String(), ",")
	if err != nil {
		return 0, 0
	}
	return port1, port2
}

func getDstPortsRange(config *FilterConfig) (uint16, uint16) {
	if config.DestinationPort.Type == intstr.Int {
		return uint16(config.DestinationPort.IntVal), 0
	}
	start, end, err := getPortsFromString(config.DestinationPort.String(), "-")
	if err != nil {
		return 0, 0
	}
	return start, end
}

func getDstPorts(config *FilterConfig) (uint16, uint16) {
	port1, port2, err := getPortsFromString(config.DestinationPort.String(), ",")
	if err != nil {
		return 0, 0
	}
	return port1, port2
}

func getPortsRange(config *FilterConfig) (uint16, uint16) {
	if config.Port.Type == intstr.Int {
		return uint16(config.Port.IntVal), 0
	}
	start, end, err := getPortsFromString(config.Port.String(), "-")
	if err != nil {
		return 0, 0
	}
	return start, end
}

func getPorts(config *FilterConfig) (uint16, uint16) {
	port1, port2, err := getPortsFromString(config.Port.String(), ",")
	if err != nil {
		return 0, 0
	}
	return port1, port2
}

func getPortsFromString(s, sep string) (uint16, uint16, error) {
	ps := strings.SplitN(s, sep, 2)
	if len(ps) != 2 {
		return 0, 0, fmt.Errorf("invalid ports range. Expected two integers separated by %s but found %s", sep, s)
	}
	startPort, err := strconv.ParseUint(ps[0], 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid start port number %w", err)
	}
	endPort, err := strconv.ParseUint(ps[1], 10, 16)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid end port number %w", err)
	}
	if sep == "-" && startPort > endPort {
		return 0, 0, fmt.Errorf("invalid port range. Start port is greater than end port")
	}
	if startPort == endPort {
		return 0, 0, fmt.Errorf("invalid port range. Start and end port are equal. Remove the %s and enter a single port", sep)
	}
	if startPort == 0 {
		return 0, 0, fmt.Errorf("invalid start port 0")
	}
	return uint16(startPort), uint16(endPort), nil
}

func ConvertFilterPortsToInstr(intPort int32, rangePorts, ports string) intstr.IntOrString {
	if rangePorts != "" {
		return intstr.FromString(rangePorts)
	}
	if ports != "" {
		return intstr.FromString(ports)
	}
	return intstr.FromInt32(intPort)
}

func (f *Filter) hasSampling() uint8 {
	for _, r := range f.config {
		if r.Sample > 0 {
			return 1
		}
	}
	return 0
}
