package model

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
)

func TestRecordBinaryEncoding(t *testing.T) {
	// Makes sure that we read the C *packed* flow structure according
	// to the order defined in bpf/flow.h
	fr, err := ReadFrom(bytes.NewReader([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x06, 0x07, 0x08, 0x09, // network: u8[16] src_ip
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d, // network: u32 dst_ip
		0x0e, 0x0f, // transport: u16 src_port
		0x10, 0x11, // transport: u16 dst_port
		0x12,       // transport: u8 transport_protocol
		0x00,       // icmp: u8 icmp_type
		0x00,       // icmp: u8 icmp_code
		0x01, 0x02, // u16 eth_protocol
		0x04, 0x05, 0x06, 0x07, 0x08, 0x09, // data_link: u8[6] src_mac
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // data_link: u8[6] dst_mac
		0x06, 0x07, 0x08, 0x09, // u32 packets
		0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, // u64 bytes
		0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, // u64 flow_start_time
		0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, // u64 flow_end_time
		0x13, 0x14, // flags
		0x33, // u8 errno
		0x60, // u8 dscp
		// dns_record structure
		01, 00, // id
		0x80, 00, // flags
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, // latency
		0x00, // errno
	}))
	require.NoError(t, err)

	assert.Equal(t, RawRecord{
		Id: ebpf.BpfFlowId{
			SrcIp:             IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x06, 0x07, 0x08, 0x09},
			DstIp:             IPAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x0a, 0x0b, 0x0c, 0x0d},
			SrcPort:           0x0f0e,
			DstPort:           0x1110,
			TransportProtocol: 0x12,
			IcmpType:          0x00,
			IcmpCode:          0x00,
		},
		Metrics: ebpf.BpfFlowMetrics{
			EthProtocol:     0x0201,
			SrcMac:          MacAddr{0x04, 0x05, 0x06, 0x07, 0x08, 0x09},
			DstMac:          MacAddr{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
			Packets:         0x09080706,
			Bytes:           0x1a19181716151413,
			StartMonoTimeTs: 0x1a19181716151413,
			EndMonoTimeTs:   0x1a19181716151413,
			Flags:           0x1413,
			Errno:           0x33,
			Dscp:            0x60,
			DnsRecord: ebpf.BpfDnsRecordT{
				Id:      0x0001,
				Flags:   0x0080,
				Latency: 0x1817161514131211,
				Errno:   0,
			},
			ZoneId: 2,
		},
	}, *fr)
	// assert that IP addresses are interpreted as IPv4 addresses
	assert.Equal(t, "6.7.8.9", IP(fr.Id.SrcIp).String())
	assert.Equal(t, "10.11.12.13", IP(fr.Id.DstIp).String())
}

func TestAccumulateIPPorts(t *testing.T) {
	base := [MaxObservedIPs]ebpf.BpfIpPortT{
		{
			Addr: [16]uint8{10, 11, 12, 13},
			Port: 8080,
		},
		{
			Addr: [16]uint8{20, 21, 22, 23},
			Port: 6060,
		},
		{
			Addr: [16]uint8{},
			Port: 0,
		},
	}
	other := [MaxObservedIPs]ebpf.BpfIpPortT{
		{
			Addr: [16]uint8{10, 11, 12, 13},
			Port: 8080,
		},
		{
			Addr: [16]uint8{10, 11, 12, 42},
			Port: 6060,
		},
		{
			Addr: [16]uint8{30, 31, 32, 33},
			Port: 0,
		},
		// {40, 41, 42, 43},
	}

	size := uint8(2)

	accumulateIPPorts(&size, &base, 4, other)
	assert.Equal(t, [MaxObservedIPs][4]uint8{
		{10, 11, 12, 13},
		{20, 21, 22, 23},
		{10, 11, 12, 42},
		// {30, 31, 32, 33},
	}, base)
}
