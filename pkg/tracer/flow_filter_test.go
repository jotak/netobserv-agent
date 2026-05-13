package tracer

import (
	"net"
	"syscall"
	"testing"

	"github.com/netobserv/netobserv-ebpf-agent/pkg/config"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/stretchr/testify/assert"
)

func TestFilter_buildCIDRKey(t *testing.T) {
	expectedIP := net.ParseIP("192.168.1.0").To4()
	expectedPrefixLen := uint32(24)

	key, err := buildCIDRKey("192.168.1.0/24")

	assert.Nil(t, err)
	assert.Equal(t, []uint8(expectedIP), key.IpData[:4])
	assert.Equal(t, expectedPrefixLen, key.PrefixLen)
}

func TestFilter_getFlowFilterValue(t *testing.T) {
	config := &config.FilterRuleConfig{
		Direction: "Ingress",
		Protocol:  "TCP",
		SrcPorts:  []uint16{8080},
		DstPorts:  []uint16{8000, 9000},
	}

	value, err := getRuleValue(config)

	assert.Nil(t, err)
	assert.Equal(t, ebpf.BpfDirectionTINGRESS, value.Direction)
	assert.Equal(t, uint8(syscall.IPPROTO_TCP), value.Protocol)
	assert.Equal(t, uint16(8080), value.SrcPorts[0])
	assert.Equal(t, uint16(0), value.SrcPorts[1])
	assert.Equal(t, uint16(8000), value.DstPorts[0])
	assert.Equal(t, uint16(9000), value.DstPorts[1])
	assert.Equal(t, uint16(0), value.Ports[0])
}

func TestBuildFilterKey(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		wantKey   ebpf.BpfFilterCidrKeyT
		wantError bool
	}{
		{
			name: "Valid CIDR IPv4",
			cidr: "192.168.1.0/24",
			wantKey: ebpf.BpfFilterCidrKeyT{
				IpData:    [16]byte{192, 168, 1, 0},
				PrefixLen: 24,
			},
			wantError: false,
		},
		{
			name: "Valid default IPv4 CIDR",
			cidr: "0.0.0.0/0",
			wantKey: ebpf.BpfFilterCidrKeyT{
				IpData:    [16]byte{0},
				PrefixLen: 0,
			},
			wantError: false,
		},
		{
			name: "Valid CIDR IPv6",
			cidr: "2001:db8::/48",
			wantKey: ebpf.BpfFilterCidrKeyT{
				IpData:    [16]byte{0x20, 0x01, 0x0d, 0xb8},
				PrefixLen: 48,
			},
			wantError: false,
		},
		{
			name: "Valid default IPv6 CIDR",
			cidr: "0::0/0",
			wantKey: ebpf.BpfFilterCidrKeyT{
				IpData:    [16]byte{0},
				PrefixLen: 0,
			},
			wantError: false,
		},
		{
			name:      "Invalid CIDR",
			cidr:      "invalidCIDR",
			wantKey:   ebpf.BpfFilterCidrKeyT{},
			wantError: true,
		},
		{
			name:      "Empty input",
			cidr:      "",
			wantKey:   ebpf.BpfFilterCidrKeyT{},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := buildCIDRKey(tt.cidr)

			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantKey, key)
			}
		})
	}
}
