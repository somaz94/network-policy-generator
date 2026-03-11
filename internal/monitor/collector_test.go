package monitor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestCollector(t *testing.T) {
	// Setup
	fakeClient := fake.NewSimpleClientset()
	testNamespace := "test-namespace"
	collector := NewCollector(fakeClient, testNamespace)

	t.Run("Collect Pod Traffic", func(t *testing.T) {
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
					},
				},
			},
		}

		flows, err := collector.CollectPodTraffic(pod)
		assert.NoError(t, err)
		assert.NotEmpty(t, flows)
		assert.Equal(t, testNamespace, flows[0].SourceNamespace)
		assert.Equal(t, "test-pod", flows[0].SourcePod)
		assert.Equal(t, int32(80), flows[0].Port)
	})

	t.Run("Parse Host and Port", func(t *testing.T) {
		testCases := []struct {
			input        string
			expectedHost string
			expectedPort int32
			description  string
		}{
			{
				input:        "example.com:8080",
				expectedHost: "example.com",
				expectedPort: 8080,
				description:  "Valid host and port",
			},
			{
				input:        "example.com",
				expectedHost: "example.com",
				expectedPort: 80,
				description:  "Host only, default port",
			},
			{
				input:        "example.com:invalid",
				expectedHost: "example.com",
				expectedPort: 80,
				description:  "Invalid port, use default",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				host, port := ParseHostAndPort(tc.input)
				assert.Equal(t, tc.expectedHost, host)
				assert.Equal(t, tc.expectedPort, port)
			})
		}
	})

	t.Run("Analyze Environment Variables", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: testNamespace,
			},
		}

		envVars := []corev1.EnvVar{
			{
				Name:  "DATABASE_HOST",
				Value: "db.database:5432",
			},
			{
				Name:  "API_ENDPOINT",
				Value: "api-service.api:8080",
			},
		}

		flows := collector.AnalyzeEnvVars(envVars, pod)
		assert.Len(t, flows, 2)

		// Verify first flow
		assert.Equal(t, "database", flows[0].DestNamespace)
		assert.Equal(t, "db", flows[0].DestPod)
		assert.Equal(t, int32(5432), flows[0].Port)

		// Verify second flow
		assert.Equal(t, "api", flows[1].DestNamespace)
		assert.Equal(t, "api-service", flows[1].DestPod)
		assert.Equal(t, int32(8080), flows[1].Port)
	})
}

func TestExtractNamespaceEdgeCases(t *testing.T) {
	t.Run("Single part host", func(t *testing.T) {
		ns := ExtractNamespace("singlehost")
		assert.Equal(t, "", ns)
	})

	t.Run("Full FQDN", func(t *testing.T) {
		ns := ExtractNamespace("svc.namespace.svc.cluster.local")
		assert.Equal(t, "namespace", ns)
	})
}

func TestExtractServiceNameEdgeCases(t *testing.T) {
	t.Run("Empty string", func(t *testing.T) {
		svc := ExtractServiceName("")
		assert.Equal(t, "", svc)
	})

	t.Run("Full FQDN", func(t *testing.T) {
		svc := ExtractServiceName("my-svc.namespace.svc.cluster.local")
		assert.Equal(t, "my-svc", svc)
	})
}

func TestCollectTrafficData(t *testing.T) {
	ctx := context.Background()
	fakeClient := fake.NewSimpleClientset()
	testNamespace := "collect-test-ns"

	// Create a pod in the fake client
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web-pod",
			Namespace: testNamespace,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "web",
				Ports: []corev1.ContainerPort{
					{ContainerPort: 8080, Protocol: "TCP"},
				},
				Env: []corev1.EnvVar{
					{Name: "REDIS_HOST", Value: "redis.cache:6379"},
				},
			}},
		},
	}
	_, err := fakeClient.CoreV1().Pods(testNamespace).Create(ctx, pod, metav1.CreateOptions{})
	assert.NoError(t, err)

	collector := NewCollector(fakeClient, testNamespace)
	flows, err := collector.CollectTrafficData(ctx)
	assert.NoError(t, err)
	assert.NotEmpty(t, flows)

	// Should have port flow + env var flow
	assert.GreaterOrEqual(t, len(flows), 2)
}

func TestAnalyzeEnvVarsNoMatch(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	collector := NewCollector(fakeClient, "test-ns")

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod", Namespace: "test-ns"},
	}

	envVars := []corev1.EnvVar{
		{Name: "LOG_LEVEL", Value: "debug"},
		{Name: "MAX_RETRIES", Value: "3"},
	}

	flows := collector.AnalyzeEnvVars(envVars, pod)
	assert.Empty(t, flows)
}
