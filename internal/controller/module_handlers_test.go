package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/somaz94/network-policy-generator/internal/policy"
)

var _ = Describe("Mode Handlers", func() {
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
	})

	Context("Invalid Mode", func() {
		It("should reject invalid mode", func() {
			generator := createBasicGenerator(namespace, generatorName)
			generator.Spec.Mode = "invalid"

			err := k8sClient.Create(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Unsupported value"))
		})
	})

	Context("Learning Mode", func() {
		It("should handle initial learning mode setup", func() {
			generator := createBasicGenerator(namespace, generatorName)
			generator.Spec.Duration = metav1.Duration{Duration: 1 * time.Minute}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			result, err := reconciler.handleLearningMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(1 * time.Minute))
			Expect(generator.Status.Phase).To(Equal("Learning"))
			Expect(generator.Status.LastAnalyzed.IsZero()).To(BeFalse())
		})

		It("should maintain learning mode during duration", func() {
			generator := createBasicGenerator(namespace, generatorName)
			generator.Spec.Duration = metav1.Duration{Duration: 5 * time.Minute}
			generator.Status.Phase = "Learning"

			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			generator.Status.LastAnalyzed = metav1.NewTime(time.Now())
			Expect(k8sClient.Status().Update(ctx, generator)).To(Succeed())

			result, err := reconciler.handleLearningMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(5 * time.Minute))
		})
	})

	Context("Enforcing Mode", func() {
		It("should create network policies in enforcing mode", func() {
			generator := createBasicGenerator(namespace, generatorName)
			generator.Spec.Mode = "enforcing"
			generator.Status.Phase = "Enforcing"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			result, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(5 * time.Minute))

			networkPolicy := &networkingv1.NetworkPolicy{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName + "-generated",
					Namespace: namespace,
				}, networkPolicy)
			}, timeout, interval).Should(Succeed())

			Expect(networkPolicy.OwnerReferences).To(HaveLen(1))
			Expect(networkPolicy.OwnerReferences[0].Name).To(Equal(generatorName))
		})

		It("should handle policy update in enforcing mode", func() {
			generator := createBasicGenerator(namespace, generatorName)
			generator.Spec.Mode = "enforcing"
			generator.Status.Phase = "Enforcing"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			_, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())

			// Modify generator configuration
			generator.Spec.Policy.AllowedNamespaces = []string{"test-namespace"}
			Expect(k8sClient.Update(ctx, generator)).To(Succeed())

			result, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(5 * time.Minute))

			networkPolicy := &networkingv1.NetworkPolicy{}
			Eventually(func() []networkingv1.NetworkPolicyIngressRule {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName + "-generated",
					Namespace: namespace,
				}, networkPolicy)
				if err != nil {
					return nil
				}
				return networkPolicy.Spec.Ingress
			}, timeout, interval).Should(Not(BeEmpty()))
		})
	})
})
