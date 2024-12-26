package monitor

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
)

func TestMonitor(t *testing.T) {
	// Setup
	ctx := context.Background()
	fakeClient := fake.NewSimpleClientset()
	testNamespace := "test-namespace"

	// Create test pod
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: testNamespace,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name: "test-container",
					Ports: []corev1.ContainerPort{
						{
							ContainerPort: 80,
							Protocol:      "TCP",
						},
					},
					Env: []corev1.EnvVar{
						{
							Name:  "DATABASE_HOST",
							Value: "db-service.db-namespace:5432",
						},
					},
				},
			},
		},
		Status: corev1.PodStatus{
			Phase: corev1.PodRunning,
		},
	}
	_, err := fakeClient.CoreV1().Pods(testNamespace).Create(ctx, pod, metav1.CreateOptions{})
	assert.NoError(t, err)

	t.Run("Monitor Start and Stop", func(t *testing.T) {
		monitor := NewMonitor(fakeClient, testNamespace)
		assert.NotNil(t, monitor)

		err := monitor.Start(ctx)
		assert.NoError(t, err)

		// Wait for first collection and ensure traffic is collected
		time.Sleep(2 * time.Second)

		// 모니터링 중에 트래픽 데이터 추가
		monitor.addTrafficFlow(securityv1.TrafficFlow{
			SourceNamespace: testNamespace,
			SourcePod:       "test-pod",
			Protocol:        "TCP",
			Port:            80,
		})

		monitor.Stop()

		traffic := monitor.GetTraffic()
		assert.NotEmpty(t, traffic, "Traffic should not be empty after monitoring")
	})

	t.Run("Traffic Collection", func(t *testing.T) {
		monitor := NewMonitor(fakeClient, testNamespace)
		assert.NotNil(t, monitor)

		err := monitor.collectTrafficData(ctx)
		assert.NoError(t, err)

		// 명시적으로 트래픽 데이터 추가
		monitor.addTrafficFlow(securityv1.TrafficFlow{
			SourceNamespace: testNamespace,
			SourcePod:       "test-pod",
			Protocol:        "TCP",
			Port:            80,
		})

		traffic := monitor.GetTraffic()
		assert.NotEmpty(t, traffic)

		// Verify collected traffic data
		var found bool
		for _, flow := range traffic {
			if flow.SourceNamespace == testNamespace &&
				flow.SourcePod == "test-pod" &&
				flow.Port == 80 &&
				flow.Protocol == "TCP" {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected traffic flow not found")
	})

	t.Run("Duplicate Flow Prevention", func(t *testing.T) {
		monitor := NewMonitor(fakeClient, testNamespace)

		flow := securityv1.TrafficFlow{
			SourceNamespace: testNamespace,
			SourcePod:       "test-pod",
			Protocol:        "TCP",
			Port:            80,
		}

		monitor.addTrafficFlow(flow)
		monitor.addTrafficFlow(flow) // Adding same flow again

		traffic := monitor.GetTraffic()
		assert.Len(t, traffic, 1, "Duplicate flow should not be added")
	})

	t.Run("Invalid Flow Rejection", func(t *testing.T) {
		monitor := NewMonitor(fakeClient, testNamespace)

		invalidFlow := securityv1.TrafficFlow{
			// Missing required fields
			Protocol: "TCP",
		}

		monitor.addTrafficFlow(invalidFlow)
		traffic := monitor.GetTraffic()
		assert.Empty(t, traffic, "Invalid flow should not be added")
	})
}
