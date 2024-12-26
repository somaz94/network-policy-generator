package monitor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
)

// Monitor represents a network traffic monitor
type Monitor struct {
	client          kubernetes.Interface
	collector       Collector
	stopCh          chan struct{}
	mu              sync.RWMutex
	traffic         []securityv1.TrafficFlow
	namespace       string
	collectInterval time.Duration
}

// MonitorOption defines functional options for Monitor
type MonitorOption func(*Monitor)

// WithCollectInterval sets the collection interval
func WithCollectInterval(interval time.Duration) MonitorOption {
	return func(m *Monitor) {
		m.collectInterval = interval
	}
}

// NewMonitor creates a new network traffic monitor
func NewMonitor(client kubernetes.Interface, namespace string, opts ...MonitorOption) *Monitor {
	m := &Monitor{
		client:          client,
		collector:       Collector{client: client, namespace: namespace},
		stopCh:          make(chan struct{}),
		traffic:         make([]securityv1.TrafficFlow, 0),
		namespace:       namespace,
		collectInterval: 30 * time.Second,
	}

	// Apply options
	for _, opt := range opts {
		opt(m)
	}

	return m
}

// Start begins monitoring network traffic
func (m *Monitor) Start(ctx context.Context) error {
	log := log.FromContext(ctx)
	log.Info("Starting network traffic monitoring", "namespace", m.namespace)

	go m.monitorTraffic(ctx)
	return nil
}

// Stop stops monitoring network traffic
func (m *Monitor) Stop() {
	close(m.stopCh)
}

// GetTraffic returns the observed traffic flows
func (m *Monitor) GetTraffic() []securityv1.TrafficFlow {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]securityv1.TrafficFlow{}, m.traffic...)
}

// monitorTraffic is the main monitoring loop
func (m *Monitor) monitorTraffic(ctx context.Context) {
	log := log.FromContext(ctx)
	ticker := time.NewTicker(m.collectInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info("Stopping network traffic monitoring due to context cancellation")
			return
		case <-m.stopCh:
			log.Info("Stopping network traffic monitoring")
			return
		case <-ticker.C:
			if err := m.collectTrafficData(ctx); err != nil {
				log.Error(err, "Failed to collect traffic data")
			}
		}
	}
}

// collectTrafficData gathers network traffic information using the collector
func (m *Monitor) collectTrafficData(ctx context.Context) error {
	log := log.FromContext(ctx)

	flows, err := m.collector.CollectTrafficData(ctx)
	if err != nil {
		return fmt.Errorf("failed to collect traffic data: %w", err)
	}

	for _, flow := range flows {
		m.addTrafficFlow(flow)
	}

	log.Info("Successfully collected traffic data",
		"namespace", m.namespace,
		"flowCount", len(flows))

	return nil
}

// addTrafficFlow adds a new traffic flow to the monitor
func (m *Monitor) addTrafficFlow(flow securityv1.TrafficFlow) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !isValidFlow(flow) {
		return
	}

	for _, existing := range m.traffic {
		if isFlowEqual(existing, flow) {
			return
		}
	}

	m.traffic = append(m.traffic, flow)
}

// isValidFlow checks if a traffic flow is valid
func isValidFlow(flow securityv1.TrafficFlow) bool {
	return flow.SourceNamespace != "" &&
		flow.SourcePod != "" &&
		flow.Protocol != "" &&
		flow.Port > 0
}

// isFlowEqual checks if two traffic flows are equal
func isFlowEqual(a, b securityv1.TrafficFlow) bool {
	return a.SourceNamespace == b.SourceNamespace &&
		a.SourcePod == b.SourcePod &&
		a.DestNamespace == b.DestNamespace &&
		a.DestPod == b.DestPod &&
		a.Protocol == b.Protocol &&
		a.Port == b.Port
}
