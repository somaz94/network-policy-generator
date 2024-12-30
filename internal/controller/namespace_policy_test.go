package controller

import (
	"context"

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

var _ = Describe("Namespace Policy Tests", func() {
	Context("When handling namespace policies", func() {
		var (
			ctx           context.Context
			generatorName string
			namespace     string
			reconciler    *NetworkPolicyGeneratorReconciler
		)

		BeforeEach(func() {
			var err error
			ctx = context.Background()
			generatorName = "test-generator"

			namespace, err = setupTestNamespace(ctx, k8sClient)
			Expect(err).NotTo(HaveOccurred())

			reconciler = &NetworkPolicyGeneratorReconciler{
				Client:    k8sClient,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
			}

			generator := createBasicGenerator(namespace, generatorName)
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())
		})

		It("should handle allowed namespaces correctly", func() {
			By("Creating allowed namespaces")
			allowedNamespaces := []string{"allowed-ns1", "allowed-ns2"}
			for _, ns := range allowedNamespaces {
				Expect(k8sClient.Create(ctx, &corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{Name: ns},
				})).To(Succeed())
			}

			By("Updating generator with allowed namespaces")
			generator := &securityv1.NetworkPolicyGenerator{}
			Eventually(func() error {
				if err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				}, generator); err != nil {
					return err
				}
				generator.Spec.Mode = "enforcing"
				generator.Spec.Policy.AllowedNamespaces = allowedNamespaces
				return k8sClient.Update(ctx, generator)
			}, timeout, interval).Should(Succeed())

			By("Reconciling and verifying NetworkPolicy")
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			networkPolicy := &networkingv1.NetworkPolicy{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName + "-generated",
					Namespace: namespace,
				}, networkPolicy)
			}, timeout, interval).Should(Succeed())

			By("Verifying namespace selectors")
			Expect(networkPolicy.Spec.Ingress).To(HaveLen(2))
			Expect(networkPolicy.Spec.Ingress[0].From).To(HaveLen(2))

			// Verify namespace selectors for allowed namespaces
			for i, ns := range allowedNamespaces {
				Expect(networkPolicy.Spec.Ingress[0].From[i].NamespaceSelector.MatchLabels["kubernetes.io/metadata.name"]).To(Equal(ns))
			}

			// Verify global rules
			Expect(networkPolicy.Spec.Ingress[1].Ports).To(HaveLen(1))
			Expect(networkPolicy.Spec.Ingress[1].From[0].IPBlock.CIDR).To(Equal("0.0.0.0/0"))
		})
	})
})
