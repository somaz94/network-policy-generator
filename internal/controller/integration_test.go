package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
	"github.com/somaz94/network-policy-generator/internal/policy"
)

var _ = Describe("NetworkPolicyGenerator Integration", func() {
	const (
		timeout  = time.Second * 10
		interval = time.Millisecond * 250
	)

	Context("When deploying a complete setup", func() {
		var (
			ctx        context.Context
			namespace  string
			generator  *securityv1.NetworkPolicyGenerator
			testPod    *corev1.Pod
			targetNs   string
			reconciler *NetworkPolicyGeneratorReconciler
		)

		BeforeEach(func() {
			ctx = context.Background()
			namespace = "test-ns"
			targetNs = "target-ns"

			reconciler = &NetworkPolicyGeneratorReconciler{
				Client:    k8sClient,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
			}

			// Create test namespaces
			Expect(k8sClient.Create(ctx, &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: namespace},
			})).To(Succeed())
			Expect(k8sClient.Create(ctx, &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: targetNs},
			})).To(Succeed())

			// Create test pods
			testPod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod",
					Namespace: namespace,
					Labels: map[string]string{
						"app": "test",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  "nginx",
							Image: "nginx:latest",
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
			Expect(k8sClient.Create(ctx, testPod)).To(Succeed())

			// Create generator with new structure
			generator = &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-generator",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:     "enforcing",
					Duration: metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type:              "deny",
						AllowedNamespaces: []string{targetNs},
					},
					GlobalRules: []securityv1.GlobalRule{
						{
							Type:      "allow",
							Port:      80,
							Protocol:  "TCP",
							Direction: "ingress",
						},
					},
				},
				Status: securityv1.NetworkPolicyGeneratorStatus{
					Phase:        "Enforcing",
					LastAnalyzed: metav1.Now(),
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())
		})

		It("should create correct network policies", func() {
			// Trigger reconciliation
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      generator.Name,
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			// Verify network policy
			networkPolicy := &networkingv1.NetworkPolicy{}
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generator.Name + "-generated",
					Namespace: namespace,
				}, networkPolicy)
				if err != nil {
					return false
				}

				// Verify policy types
				if len(networkPolicy.Spec.PolicyTypes) != 2 {
					return false
				}

				// Verify ingress rules
				if len(networkPolicy.Spec.Ingress) != 2 {
					return false
				}

				// Verify allowed namespaces
				if len(networkPolicy.Spec.Ingress[0].From) != 1 {
					return false
				}

				// Verify global rules
				if len(networkPolicy.Spec.Ingress[1].Ports) != 1 {
					return false
				}

				return true
			}, timeout, interval).Should(BeTrue())
		})
	})
})
