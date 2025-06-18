package ifaces

import (
	"sync"
	"sync/atomic"
)

type imap struct {
	backend sync.Map
	size    atomic.Uint32
}

func (m *imap) store(k InterfaceKey, v Interface) {
	if _, exists := m.backend.Load(k); !exists {
		m.size.Add(1)
	}
	m.backend.Store(k, v)
}

func (m *imap) delete(k InterfaceKey) (Interface, bool) {
	if i, exists := m.backend.Load(k); exists {
		m.backend.Delete(k)
		s := m.size.Load()
		if s > 0 {
			m.size.Store(s - 1)
		}
		return i.(Interface), true
	}
	return Interface{}, false
}

func (m *imap) load(k InterfaceKey) (Interface, bool) {
	if i, b := m.backend.Load(k); b {
		return i.(Interface), true
	}
	return Interface{}, false
}

func (m *imap) forEach(f func(InterfaceKey, Interface) bool) {
	m.backend.Range(func(key, value any) bool {
		return f(key.(InterfaceKey), value.(Interface))
	})
}

func (m *imap) len() int {
	return int(m.size.Load())
}
