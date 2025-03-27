package exporter

import (
	"github.com/netobserv/netobserv-ebpf-agent/pkg/metrics"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/model"
	"github.com/netobserv/netobserv-ebpf-agent/pkg/pbflow"

	amqp "github.com/rabbitmq/amqp091-go"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

var mqlog = logrus.WithField("component", "exporter/MQProto")

const (
	componentMQ = "mq"
	queueName   = "flows"
)

// MQProto exports flows over MQ, encoded as a protobuf that is understandable by the
// Flowlogs-Pipeline collector
type MQProto struct {
	Channel *amqp.Channel
	Metrics *metrics.Metrics
}

func NewMQProto(address string, m *metrics.Metrics) (*MQProto, error) {
	conn, err := amqp.Dial(address)
	if err != nil {
		return nil, err
	}
	ch, err := conn.Channel()
	if err != nil {
		return nil, err
	}
	_, err = ch.QueueDeclare(
		queueName, // name
		false,     // durable
		false,     // delete when unused
		false,     // exclusive
		false,     // no-wait
		nil,       // arguments
	)
	if err != nil {
		return nil, err
	}
	return &MQProto{
		Channel: ch,
		Metrics: m,
	}, nil
}

func (m *MQProto) ExportFlows(input <-chan []*model.Record) {
	mqlog.Info("starting Kafka exporter")
	for records := range input {
		m.batchAndSubmit(records)
	}
}

func (m *MQProto) batchAndSubmit(records []*model.Record) {
	mqlog.Debugf("sending %d records", len(records))
	for _, record := range records {
		pbBytes, err := proto.Marshal(pbflow.FlowToPB(record))
		if err != nil {
			mqlog.WithError(err).Debug("can't encode protobuf message. Ignoring")
			m.Metrics.Errors.WithErrorName(componentMQ, "CannotEncodeMessage", metrics.HighSeverity).Inc()
			continue
		}
		err = m.Channel.Publish(
			"",        // exchange
			queueName, // routing key
			false,     // mandatory
			false,     // immediate
			amqp.Publishing{
				ContentType: "text/plain",
				Body:        pbBytes,
			})

		if err != nil {
			mqlog.WithError(err).Error("can't write messages into Kafka")
			m.Metrics.Errors.WithErrorName(componentMQ, "CannotWriteMessage", metrics.HighSeverity).Inc()
		}
	}
	m.Metrics.EvictionCounter.WithSource(componentMQ).Inc()
	m.Metrics.EvictedFlowsCounter.WithSource(componentMQ).Add(float64(len(records)))
}
