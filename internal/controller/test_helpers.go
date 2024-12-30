/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
)

const (
	timeout  = time.Second * 3
	interval = time.Millisecond * 250
)

// setupTestNamespace creates a new test namespace
func setupTestNamespace(ctx context.Context, k8sClient client.Client) (string, error) {
	namespace := fmt.Sprintf("test-namespace-%d", time.Now().UnixNano())
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespace,
		},
	}
	return namespace, k8sClient.Create(ctx, ns)
}

// createBasicGenerator creates a basic NetworkPolicyGenerator for testing
func createBasicGenerator(namespace, name string) *securityv1.NetworkPolicyGenerator {
	return &securityv1.NetworkPolicyGenerator{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: securityv1.NetworkPolicyGeneratorSpec{
			Mode:     "learning",
			Duration: metav1.Duration{Duration: time.Minute},
			Policy: securityv1.PolicyConfig{
				Type:              "deny",
				AllowedNamespaces: []string{"test-ns1", "test-ns2"},
			},
			GlobalRules: []securityv1.GlobalRule{
				{
					Type:      "allow",
					Port:      80,
					Protocol:  "TCP",
					Direction: "ingress",
				},
				{
					Type:      "deny",
					Port:      25,
					Protocol:  "TCP",
					Direction: "egress",
				},
			},
		},
	}
}

type mockClient struct {
	client.Client
	statusUpdateError error
	deleteError       error
}

func (m *mockClient) Status() client.StatusWriter {
	return &mockStatusWriter{
		StatusWriter: m.Client.Status(),
		err:          m.statusUpdateError,
	}
}

func (m *mockClient) Delete(ctx context.Context, obj client.Object, opts ...client.DeleteOption) error {
	if m.deleteError != nil {
		return m.deleteError
	}
	return m.Client.Delete(ctx, obj, opts...)
}

func (m *mockClient) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	err := m.Client.Get(ctx, key, obj)
	if err != nil {
		return err
	}
	// Copy the object to preserve any modifications made by the test
	return nil
}

type mockStatusWriter struct {
	client.StatusWriter
	err error
}

func (m *mockStatusWriter) Update(ctx context.Context, obj client.Object, opts ...client.SubResourceUpdateOption) error {
	if m.err != nil {
		return m.err
	}
	return m.StatusWriter.Update(ctx, obj, opts...)
}
