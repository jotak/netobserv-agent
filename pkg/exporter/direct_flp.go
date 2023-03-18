package exporter

import (
	"context"
	"fmt"

	flpconfig "github.com/netobserv/flowlogs-pipeline/pkg/config"
	flppipe "github.com/netobserv/flowlogs-pipeline/pkg/pipeline"
	"github.com/netobserv/flowlogs-pipeline/pkg/pipeline/decode"
	flputils "github.com/netobserv/flowlogs-pipeline/pkg/pipeline/utils"
	flpprom "github.com/netobserv/flowlogs-pipeline/pkg/prometheus"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/flow"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var log = logrus.WithField("component", "exporter/DirectFLP")

// DirectFLP flow exporter
type DirectFLP struct {
	flowPackets chan *pbflow.Records
}

func StartDirectFLP(jsonConfig string) (*DirectFLP, error) {
	var cfg flpconfig.ConfigFileStruct
	// Note that, despite jsonConfig being json, we use yaml unmarshaler because the json one
	// is screwed up for HTTPClientConfig in github.com/prometheus/common/config (used for Loki)
	// This is ok as YAML is a superset of JSON.
	// E.g. try unmarshaling `{"clientConfig":{"authorization":{}}}` as a api.WriteLoki
	// See also https://github.com/prometheus/prometheus/issues/11816
	if err := yaml.Unmarshal([]byte(jsonConfig), &cfg); err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	flowPackets := make(chan *pbflow.Records, 100)
	this := DirectFLP{
		flowPackets: flowPackets,
	}
	promServer := flpprom.StartServerAsync(&cfg.MetricsSettings)

	// Create new flows pipeline
	flp, err := flppipe.NewPipelineFromIngester(&cfg, &this)

	if err != nil {
		return nil, fmt.Errorf("failed to initialize pipeline %w", err)
	}

	// Starts the flows pipeline; blocking call
	go func() {
		flp.Run()
		_ = promServer.Shutdown(context.Background())
	}()

	return &this, nil
}

func (d *DirectFLP) Ingest(out chan<- flpconfig.GenericMap) {
	go func() {
		<-flputils.ExitChannel()
		d.Close()
	}()
	for fp := range d.flowPackets {
		log.Debugf("Ingested %v records", len(fp.Entries))
		for _, entry := range fp.Entries {
			out <- decode.PBFlowToMap(entry)
		}
	}
}

func (d *DirectFLP) Close() {
	close(d.flowPackets)
}

// ExportFlows accepts slices of *flow.Record by its input channel, converts them
// to *pbflow.Records instances, and submits them to the collector.
func (d *DirectFLP) ExportFlows(input <-chan []*flow.Record) {
	for inputRecords := range input {
		pbRecords := flowsToPBNoChunk(inputRecords)
		d.flowPackets <- pbRecords
	}
}
