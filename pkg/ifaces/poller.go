package ifaces

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netns"
)

// Poller periodically looks for the network interfaces in the system and forwards Event
// notifications when interfaces are added or deleted.
type Poller struct {
	period     time.Duration
	sharedMap  *imap
	interfaces func(handle netns.NsHandle, ns string) ([]Interface, error) // can be changed for mocking
	bufLen     int
}

func newCombinedPoller(period time.Duration, bufLen int, sharedMap *imap) *Poller {
	return &Poller{
		period:     period,
		bufLen:     bufLen,
		interfaces: netInterfaces,
		sharedMap:  sharedMap,
	}
}

func (np *Poller) pollForEvents(ctx context.Context, netnsHandle netns.NsHandle, ns string, out chan Event) {
	log := logrus.WithField("component", "ifaces.Poller")
	log.WithField("period", np.period).Debug("subscribing to Interface events")
	ticker := time.NewTicker(np.period)

	defer ticker.Stop()
	for {
		if ifaces, err := np.interfaces(netnsHandle, ns); err != nil {
			log.WithError(err).Error("can't fetch network interfaces: you might be missing flows")
		} else {
			log.WithField("names", ifaces).Trace("fetched interface names")
			np.diffNames(out, ifaces)
		}
		select {
		case <-ctx.Done():
			log.Debug("stopped")
			return
		case <-ticker.C:
			// continue after a period
		}
	}
}

// diffNames compares and updates the internal account of interfaces with the latest list of
// polled interfaces. It forwards Events for any detected addition or removal of interfaces.
func (np *Poller) diffNames(events chan Event, ifaces []Interface) {
	// Check for new interfaces
	acquired := map[InterfaceKey]struct{}{}
	for _, iface := range ifaces {
		acquired[iface.InterfaceKey] = struct{}{}
		if _, ok := np.sharedMap.load(iface.InterfaceKey); !ok {
			ilog.WithField("interface", iface).Debug("added network interface")
			np.sharedMap.store(iface.InterfaceKey, iface)
			events <- Event{
				Type:      EventAdded,
				Interface: iface,
			}
		}
	}
	// Check for deleted interfaces
	np.sharedMap.forEach(func(key InterfaceKey, _ Interface) bool {
		if _, ok := acquired[key]; !ok {
			if iface, deleted := np.sharedMap.delete(key); deleted {
				ilog.WithField("interface", iface).Debug("deleted network interface")
				events <- Event{
					Type:      EventDeleted,
					Interface: iface,
				}
			}
		}
		return true
	})
}
