package controller

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
	"github.com/somaz94/network-policy-generator/internal/policy"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

var _ = Describe("Mode Transition Tests", func() {
	var (
		key = types.NamespacedName{
			Name:      testGeneratorName,
			Namespace: nsDefault,
		}
		reconciler *NetworkPolicyGeneratorReconciler
	)

	BeforeEach(func() {
		reconciler = &NetworkPolicyGeneratorReconciler{
			Client:    k8sClient,
			Scheme:    k8sClient.Scheme(),
			Generator: policy.NewGenerator(),
			Validator: policy.NewValidator(),
			Recorder:  record.NewFakeRecorder(100),
		}
	})

	Context("When changing modes", func() {
		It("should transition from learning to enforcing mode after duration", func() {
			ctx := context.Background()
			startTime := time.Now().Add(-2 * time.Second)

			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      key.Name,
					Namespace: key.Namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode: policy.ModeLearning,
					Policy: securityv1.PolicyConfig{
						Type: policy.PolicyTypeDeny,
					},
					Duration: metav1.Duration{Duration: time.Second},
				},
				Status: securityv1.NetworkPolicyGeneratorStatus{
					Phase:        policy.PhaseLearning,
					LastAnalyzed: metav1.NewTime(startTime),
				},
			}

			// Create the generator
			Expect(k8sClient.Create(ctx, generator)).Should(Succeed())
			defer func() { _ = k8sClient.Delete(ctx, generator) }()

			// Update status
			createdGenerator := &securityv1.NetworkPolicyGenerator{}
			Eventually(func() error {
				if err := k8sClient.Get(ctx, key, createdGenerator); err != nil {
					return err
				}
				createdGenerator.Status.Phase = policy.PhaseLearning
				createdGenerator.Status.LastAnalyzed = metav1.NewTime(startTime)
				return k8sClient.Status().Update(ctx, createdGenerator)
			}, timeout, interval).Should(Succeed())

			// Trigger multiple reconciliations to ensure mode transition
			for i := 0; i < 3; i++ {
				_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: key})
				Expect(err).NotTo(HaveOccurred())
				time.Sleep(time.Millisecond * 500)
			}

			// Wait for mode transition
			Eventually(func() string {
				err := k8sClient.Get(ctx, key, createdGenerator)
				if err != nil {
					return ""
				}
				return createdGenerator.Spec.Mode
			}, timeout, interval).Should(Equal(policy.ModeEnforcing))
		})

		It("should handle direct mode changes", func() {
			ctx := context.Background()
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      nameModeChangeTest,
					Namespace: nsDefault,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode: policy.ModeLearning,
					// Learning mode requires a positive duration; a long one keeps the
					// controller from auto-transitioning before the explicit update below.
					Duration: metav1.Duration{Duration: time.Hour},
					Policy: securityv1.PolicyConfig{
						Type: policy.PolicyTypeDeny,
					},
				},
			}

			// Create initial generator
			Expect(k8sClient.Create(ctx, generator)).Should(Succeed())
			defer func() { _ = k8sClient.Delete(ctx, generator) }()

			// Update mode to enforcing
			updatedGenerator := &securityv1.NetworkPolicyGenerator{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      nameModeChangeTest,
				Namespace: nsDefault,
			}, updatedGenerator)).Should(Succeed())

			updatedGenerator.Spec.Mode = policy.ModeEnforcing
			Expect(k8sClient.Update(ctx, updatedGenerator)).Should(Succeed())

			// Verify mode change
			Eventually(func() string {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      nameModeChangeTest,
					Namespace: nsDefault,
				}, updatedGenerator)
				if err != nil {
					return ""
				}
				return updatedGenerator.Spec.Mode
			}, timeout, interval).Should(Equal(policy.ModeEnforcing))
		})
	})
})
