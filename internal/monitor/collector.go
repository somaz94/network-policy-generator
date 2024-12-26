package monitor

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
)

// Collector handles the collection of network traffic data
type Collector struct {
	client    kubernetes.Interface
	namespace string
}

// NewCollector creates a new traffic collector
func NewCollector(client kubernetes.Interface, namespace string) *Collector {
	return &Collector{
		client:    client,
		namespace: namespace,
	}
}

// CollectTrafficData gathers network traffic information from various sources
func (c *Collector) CollectTrafficData(ctx context.Context) ([]securityv1.TrafficFlow, error) {
	log := log.FromContext(ctx)
	var flows []securityv1.TrafficFlow

	pods, err := c.client.CoreV1().Pods(c.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list pods: %w", err)
	}

	for _, pod := range pods.Items {
		podFlows, err := c.CollectPodTraffic(&pod)
		if err != nil {
			log.Error(err, "Failed to collect pod traffic", "pod", pod.Name)
			continue
		}
		flows = append(flows, podFlows...)
	}

	return flows, nil
}

// CollectPodTraffic collects traffic information for a specific pod
func (c *Collector) CollectPodTraffic(pod *corev1.Pod) ([]securityv1.TrafficFlow, error) {
	var flows []securityv1.TrafficFlow

	for _, container := range pod.Spec.Containers {
		for _, port := range container.Ports {
			flow := securityv1.TrafficFlow{
				SourceNamespace: pod.Namespace,
				SourcePod:       pod.Name,
				Protocol:        string(port.Protocol),
				Port:            port.ContainerPort,
			}
			flows = append(flows, flow)
		}

		flows = append(flows, c.AnalyzeEnvVars(container.Env, pod)...)
	}

	return flows, nil
}

// AnalyzeEnvVars analyzes environment variables for service dependencies
func (c *Collector) AnalyzeEnvVars(envVars []corev1.EnvVar, sourcePod *corev1.Pod) []securityv1.TrafficFlow {
	var flows []securityv1.TrafficFlow

	for _, env := range envVars {
		if strings.Contains(strings.ToLower(env.Name), "host") ||
			strings.Contains(strings.ToLower(env.Name), "url") ||
			strings.Contains(strings.ToLower(env.Name), "endpoint") {

			host, port := ParseHostAndPort(env.Value)
			if host != "" {
				flow := securityv1.TrafficFlow{
					SourceNamespace: sourcePod.Namespace,
					SourcePod:       sourcePod.Name,
					DestNamespace:   ExtractNamespace(host),
					DestPod:         ExtractServiceName(host),
					Port:            port,
					Protocol:        "TCP",
				}
				flows = append(flows, flow)
			}
		}
	}

	return flows
}

// ParseHostAndPort extracts host and port from a URL or host string
func ParseHostAndPort(value string) (string, int32) {
	parts := strings.Split(value, ":")
	if len(parts) < 2 {
		return parts[0], 80
	}

	port, err := strconv.ParseInt(parts[1], 10, 32)
	if err != nil {
		return parts[0], 80
	}

	return parts[0], int32(port)
}

// ExtractNamespace extracts namespace from a kubernetes service DNS name
func ExtractNamespace(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

// ExtractServiceName extracts service name from a kubernetes service DNS name
func ExtractServiceName(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}
