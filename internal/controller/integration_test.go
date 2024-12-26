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
	ctrl "sigs.k8s.io/controller-runtime"

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
			ctx       context.Context
			namespace string
			generator *securityv1.NetworkPolicyGenerator
			testPod   *corev1.Pod
			targetNs  string
			targetPod *corev1.Pod
		)

		BeforeEach(func() {
			ctx = context.Background()
			namespace = "test-ns"
			targetNs = "target-ns"

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

			targetPod = &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "target-pod",
					Namespace: targetNs,
					Labels: map[string]string{
						"app": "target",
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
			Expect(k8sClient.Create(ctx, targetPod)).To(Succeed())

			// Create NetworkPolicyGenerator with TypeMeta
			generator = &securityv1.NetworkPolicyGenerator{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "security.policy.io/v1",
					Kind:       "NetworkPolicyGenerator",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-generator",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:     "learning",
					Duration: metav1.Duration{Duration: time.Minute},
					DefaultPolicy: securityv1.DefaultPolicy{
						Type: securityv1.PolicyDeny,
						Traffic: securityv1.TrafficPolicy{
							Ingress: securityv1.DirectionPolicy{
								FollowDefault: true,
								Policy:        securityv1.PolicyDeny,
							},
							Egress: securityv1.DirectionPolicy{
								FollowDefault: true,
								Policy:        securityv1.PolicyDeny,
							},
						},
					},
					AllowedNamespaces: []string{targetNs},
					GlobalAllowRules: &securityv1.GlobalRuleSet{
						Enabled: true,
						Traffic: securityv1.GlobalTrafficRules{
							Ingress: []securityv1.GlobalRule{
								{
									Port:     80,
									Protocol: "TCP",
								},
							},
						},
					},
					GlobalDenyRules: &securityv1.GlobalRuleSet{
						Enabled: true,
						Traffic: securityv1.GlobalTrafficRules{
							Egress: []securityv1.GlobalRule{
								{
									Port:     25,
									Protocol: "TCP",
								},
							},
						},
					},
				},
				Status: securityv1.NetworkPolicyGeneratorStatus{
					Phase: "",
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Reconciler 생성 및 초기 reconcile 실행
			reconciler := &NetworkPolicyGeneratorReconciler{
				Client:    k8sClient,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
			}

			// 초기 reconcile 실행
			_, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      generator.Name,
					Namespace: generator.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			// Cleanup
			Expect(k8sClient.Delete(ctx, generator)).To(Succeed())
			Expect(k8sClient.Delete(ctx, testPod)).To(Succeed())
			Expect(k8sClient.Delete(ctx, targetPod)).To(Succeed())
			Expect(k8sClient.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})).To(Succeed())
			Expect(k8sClient.Delete(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: targetNs}})).To(Succeed())
		})

		It("Should complete the full learning and enforcement cycle", func() {
			By("Verifying the generator enters learning mode")
			Eventually(func() string {
				var updatedGenerator securityv1.NetworkPolicyGenerator
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generator.Name,
					Namespace: generator.Namespace,
				}, &updatedGenerator)
				if err != nil {
					return ""
				}
				return updatedGenerator.Status.Phase
			}, timeout, interval).Should(Equal("Learning"))

			By("Simulating traffic observation")
			updatedGenerator := &securityv1.NetworkPolicyGenerator{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      generator.Name,
				Namespace: generator.Namespace,
			}, updatedGenerator)).To(Succeed())

			// LastAnalyzed 시간을 과거로 설정하여 학습 기간이 종료되도록 함
			pastTime := metav1.NewTime(time.Now().Add(-2 * time.Minute))
			updatedGenerator.Status.LastAnalyzed = pastTime
			Expect(k8sClient.Status().Update(ctx, updatedGenerator)).To(Succeed())

			// 트래픽 관찰 데이터 추가
			updatedGenerator.Status.ObservedTraffic = []securityv1.TrafficFlow{
				{
					SourceNamespace: namespace,
					SourcePod:       "test-pod",
					DestNamespace:   targetNs,
					DestPod:         "target-pod",
					Protocol:        "TCP",
					Port:            80,
				},
			}
			Expect(k8sClient.Status().Update(ctx, updatedGenerator)).To(Succeed())

			// Reconcile을 호출하여 상태 전환 트리거
			reconciler := &NetworkPolicyGeneratorReconciler{
				Client:    k8sClient,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
			}

			_, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      generator.Name,
					Namespace: generator.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			// Learning 모드에서 Enforcing 모드로 전환되는 것을 기다림
			Eventually(func() string {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generator.Name,
					Namespace: generator.Namespace,
				}, updatedGenerator)
				if err != nil {
					return ""
				}
				return updatedGenerator.Status.Phase
			}, timeout, interval).Should(Equal("Enforcing"))

			By("Switching to enforcing mode and enabling global rules")
			Eventually(func() error {
				if err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generator.Name,
					Namespace: generator.Namespace,
				}, updatedGenerator); err != nil {
					return err
				}
				updatedGenerator.Spec.Mode = "enforcing"
				updatedGenerator.Spec.GlobalAllowRules.Enabled = true
				updatedGenerator.Spec.GlobalDenyRules.Enabled = true
				return k8sClient.Update(ctx, updatedGenerator)
			}, timeout, interval).Should(Succeed())

			// 다시 Reconcile 호출
			_, err = reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      generator.Name,
					Namespace: generator.Namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying NetworkPolicy creation")
			var networkPolicy networkingv1.NetworkPolicy
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      generator.Name + "-generated",
					Namespace: generator.Namespace,
				}, &networkPolicy)
			}, timeout, interval).Should(Succeed())

			Expect(networkPolicy.Spec.PolicyTypes).To(ContainElements(
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			))
			Expect(networkPolicy.Spec.Ingress).NotTo(BeEmpty())
			Expect(networkPolicy.Spec.Egress).NotTo(BeEmpty())

			By("Verifying NetworkPolicy rules structure")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generator.Name + "-generated",
					Namespace: generator.Namespace,
				}, &networkPolicy)
				if err != nil {
					return false
				}

				// Verify Ingress rules
				if len(networkPolicy.Spec.Ingress) != 1 || len(networkPolicy.Spec.Ingress[0].Ports) != 1 {
					return false
				}
				ingressPort := networkPolicy.Spec.Ingress[0].Ports[0]
				if ingressPort.Port.IntVal != 80 || *ingressPort.Protocol != "TCP" {
					return false
				}

				// Verify Egress rules
				if len(networkPolicy.Spec.Egress) != 1 || len(networkPolicy.Spec.Egress[0].Ports) != 1 {
					return false
				}
				egressPort := networkPolicy.Spec.Egress[0].Ports[0]
				return egressPort.Port.IntVal == 25 && *egressPort.Protocol == "TCP"
			}, timeout, interval).Should(BeTrue())
		})
	})
})
