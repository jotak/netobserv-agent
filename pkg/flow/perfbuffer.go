package flow

import (
	"time"

	"github.com/sirupsen/logrus"
)

type PerfBuffer struct {
	maxEntries   int
	evictTimeout time.Duration
	entries      map[uint16](*PacketRecord)
}

func NewPerfBuffer(
	maxEntries int, evictTimeout time.Duration,
) *PerfBuffer {
	return &PerfBuffer{
		maxEntries:   maxEntries,
		evictTimeout: evictTimeout,
		entries:      map[uint16]*PacketRecord{},
	}
}

func (c *PerfBuffer) PBuffer(in <-chan *PacketRecord, out chan<- []*PacketRecord) {
	evictTick := time.NewTicker(c.evictTimeout)
	defer evictTick.Stop()
	ind := 0
	for {
		select {
		case <-evictTick.C:
			if len(c.entries) == 0 {
				break
			}
			evictingEntries := c.entries
			c.entries = map[uint16]*PacketRecord{}
			logrus.WithField("packets", len(evictingEntries)).
				Debug("evicting packets from userspace  on timeout")
			c.evict(evictingEntries, out)
		case packet, ok := <-in:
			if !ok {
				plog.Debug("input channel closed. Evicting entries")
				c.evict(c.entries, out)
				plog.Debug("exiting perfbuffer routine")
				return
			}
			if len(c.entries) >= c.maxEntries {
				evictingEntries := c.entries
				c.entries = map[uint16]*PacketRecord{}
				logrus.WithField("packets", len(evictingEntries)).
					Debug("evicting packets from userspace accounter after reaching cache max length")
				c.evict(evictingEntries, out)
			}
			c.entries[uint16(ind)] = NewPacketRecord(packet.Stream, (uint16)(len(packet.Stream)), packet.Time)
			ind++
		}
	}
}

func (c *PerfBuffer) evict(entries map[uint16](*PacketRecord), evictor chan<- []*PacketRecord) {
	packets := make([]*PacketRecord, 0, len(entries))
	for _, payload := range entries {
		packets = append(packets, NewPacketRecord(payload.Stream, (uint16)(len(payload.Stream)), payload.Time))
	}
	alog.WithField("numEntries", len(packets)).Debug("packets evicted from userspace accounter")
	evictor <- packets
}