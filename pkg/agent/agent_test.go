package agent

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/gavv/monotime"
	test2 "github.com/mariomac/guara/pkg/test"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/ebpf"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var agentIP = "192.168.1.13"

const timeout = 2 * time.Second

func TestFlowsAgent_InvalidConfigs(t *testing.T) {
	for _, tc := range []struct {
		d string
		c Config
	}{{
		d: "invalid export type",
		c: Config{Export: "foo"},
	}, {
		d: "GRPC: missing host",
		c: Config{Export: "grpc", TargetPort: 3333},
	}, {
		d: "GRPC: missing port",
		c: Config{Export: "grpc", TargetHost: "flp"},
	}, {
		d: "Kafka: missing brokers",
		c: Config{Export: "kafka"},
	}} {
		t.Run(tc.d, func(t *testing.T) {
			_, err := FlowsAgent(&tc.c)
			assert.Error(t, err)
		})
	}
}

var (
	key1 = ebpf.BpfFlowId{
		SrcPort: 123,
		DstPort: 456,
	}
	key2 = ebpf.BpfFlowId{
		SrcPort: 333,
		DstPort: 532,
	}
	obsByIf3 = [model.MaxObservedInterfaces]ebpf.BpfObservedIntfT{{IfIndex: 3, Direction: 0}}
	obsByIf4 = [model.MaxObservedInterfaces]ebpf.BpfObservedIntfT{{IfIndex: 4, Direction: 1}}
)

func TestFlowsAgent_Decoration(t *testing.T) {
	export := testAgent(t, &Config{
		CacheActiveTimeout: 10 * time.Millisecond,
		CacheMaxFlows:      100,
	})

	exported := export.Get(t, timeout)
	assert.Len(t, exported, 2)

	// Tests that the decoration stage has been properly executed. It should
	// add the interface name and the agent IP
	for _, f := range exported {
		assert.Equal(t, agentIP, f.AgentIP.String())
		switch *f.Id {
		case key1, key2:
			assert.Equal(t, "foo", f.Interfaces[0])
		default:
			assert.Equal(t, "bar", f.Interfaces[0])
		}
	}
}

func testAgent(t *testing.T, cfg *Config) *test.ExporterFake {
	ebpfTracer := test.NewTracerFake()
	export := test.NewExporterFake()
	agent, err := flowsAgent(cfg,
		metrics.NewMetrics(&metrics.Settings{}),
		test.SliceInformerFake{
			{Name: "foo", Index: 3},
			{Name: "bar", Index: 4},
		}, ebpfTracer, export.Export,
		net.ParseIP(agentIP), nil)
	require.NoError(t, err)

	go func() {
		require.NoError(t, agent.Run(context.Background()))
	}()
	test2.Eventually(t, timeout, func(t require.TestingT) {
		require.Equal(t, StatusStarted, agent.status)
	})

	now := uint64(monotime.Now())
	key1Metrics := model.BpfFlowPayloads{
		{
			BpfFlowMetrics:  &ebpf.BpfFlowMetrics{Packets: 3, Bytes: 44, StartMonoTimeTs: now + 1000, EndMonoTimeTs: now + 1_000_000_000},
			BpfObservations: &ebpf.BpfObservations{NbObservedIntf: 1, ObservedIntf: obsByIf3},
		},
		{
			BpfFlowMetrics:  &ebpf.BpfFlowMetrics{Packets: 1, Bytes: 22, StartMonoTimeTs: now, EndMonoTimeTs: now + 3000},
			BpfObservations: &ebpf.BpfObservations{NbObservedIntf: 1, ObservedIntf: obsByIf4},
		},
	}
	key2Metrics := model.BpfFlowPayloads{
		{
			BpfFlowMetrics:  &ebpf.BpfFlowMetrics{Packets: 7, Bytes: 33, StartMonoTimeTs: now, EndMonoTimeTs: now + 2_000_000_000},
			BpfObservations: &ebpf.BpfObservations{NbObservedIntf: 1, ObservedIntf: obsByIf3},
		},
	}
	ebpfTracer.AppendLookupResults(map[ebpf.BpfFlowId]model.BpfFlowPayload{
		key1: key1Metrics.Accumulate(),
		key2: key2Metrics.Accumulate(),
	})
	return export
}
