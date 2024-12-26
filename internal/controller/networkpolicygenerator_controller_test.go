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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
	"github.com/somaz94/network-policy-generator/internal/policy"
)

var _ = Describe("NetworkPolicyGenerator Controller", func() {
	Context("When reconciling a resource", func() {
		var (
			ctx           context.Context
			generatorName string
			namespace     string
		)

		BeforeEach(func() {
			ctx = context.Background()
			generatorName = "test-generator"
			namespace = fmt.Sprintf("test-namespace-%d", time.Now().UnixNano())

			// Create new namespace
			ns := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespace,
				},
			}
			Expect(k8sClient.Create(ctx, ns)).To(Succeed())

			// Create the NetworkPolicyGenerator object
			generator := &securityv1.NetworkPolicyGenerator{
				TypeMeta: metav1.TypeMeta{
					APIVersion: "security.policy.io/v1",
					Kind:       "NetworkPolicyGenerator",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName,
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:     "learning",
					Duration: metav1.Duration{Duration: 5 * time.Minute},
					DefaultPolicy: securityv1.DefaultPolicy{
						Type: securityv1.PolicyDeny,
					},
					GlobalAllowRules: &securityv1.GlobalRuleSet{
						Enabled: false,
						Ingress: []securityv1.GlobalRule{
							{
								Port:     80,
								Protocol: "TCP",
							},
						},
					},
					GlobalDenyRules: &securityv1.GlobalRuleSet{
						Enabled: false,
						Egress: []securityv1.GlobalRule{
							{
								Port:     25,
								Protocol: "TCP",
							},
						},
					},
				},
			}

			Expect(k8sClient.Create(ctx, generator)).To(Succeed())
		})

		It("should successfully reconcile in learning mode", func() {
			By("Creating a new NetworkPolicyGenerator")
			generator := &securityv1.NetworkPolicyGenerator{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      generatorName,
				Namespace: namespace,
			}, generator)).To(Succeed())

			By("Reconciling the resource")
			reconciler := &NetworkPolicyGeneratorReconciler{
				Client:    k8sClient,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
			}

			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(BeNumerically(">", 0))

			By("Verifying the status is updated to Learning")
			Eventually(func() string {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				}, generator)
				if err != nil {
					return ""
				}
				return generator.Status.Phase
			}, time.Second*5, time.Millisecond*500).Should(Equal("Learning"))

			By("Verifying NetworkPolicy is created in learning mode")
			networkPolicy := &networkingv1.NetworkPolicy{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName + "-generated",
					Namespace: namespace,
				}, networkPolicy)
			}, time.Second*10).Should(Succeed())

			By("Verifying NetworkPolicy owner references")
			Expect(networkPolicy.OwnerReferences).To(HaveLen(1))
			Expect(networkPolicy.OwnerReferences[0].APIVersion).To(Equal(securityv1.GroupVersion.String()))
			Expect(networkPolicy.OwnerReferences[0].Kind).To(Equal("NetworkPolicyGenerator"))
			Expect(networkPolicy.OwnerReferences[0].Name).To(Equal(generatorName))
			Expect(networkPolicy.OwnerReferences[0].Controller).To(Equal(pointer.Bool(true)))
		})

		It("should successfully reconcile in enforcing mode with global rules", func() {
			By("Creating a NetworkPolicyGenerator in enforcing mode")
			generator := &securityv1.NetworkPolicyGenerator{}
			Eventually(func() error {
				if err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				}, generator); err != nil {
					return err
				}
				generator.Spec.Mode = "enforcing"
				generator.Spec.GlobalAllowRules.Enabled = true
				generator.Spec.GlobalDenyRules.Enabled = true
				return k8sClient.Update(ctx, generator)
			}, time.Second*10).Should(Succeed())

			By("Reconciling the resource")
			reconciler := &NetworkPolicyGeneratorReconciler{
				Client:    k8sClient,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying NetworkPolicy is created with global rules")
			networkPolicy := &networkingv1.NetworkPolicy{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName + "-generated",
					Namespace: namespace,
				}, networkPolicy)
			}, time.Second*10).Should(Succeed())

			Expect(networkPolicy.Spec.Ingress).To(HaveLen(1))
			Expect(networkPolicy.Spec.Ingress[0].Ports[0].Port.IntVal).To(Equal(int32(80)))

			Expect(networkPolicy.Spec.Egress).To(HaveLen(1))
			Expect(networkPolicy.Spec.Egress[0].Ports[0].Port.IntVal).To(Equal(int32(25)))
		})

		It("should handle disabled global rules", func() {
			By("Creating a NetworkPolicyGenerator with disabled global rules")
			generator := &securityv1.NetworkPolicyGenerator{}
			Eventually(func() error {
				if err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				}, generator); err != nil {
					return err
				}
				generator.Spec.Mode = "enforcing"
				generator.Spec.GlobalAllowRules.Enabled = false
				generator.Spec.GlobalDenyRules.Enabled = false
				return k8sClient.Update(ctx, generator)
			}, time.Second*10).Should(Succeed())

			By("Reconciling the resource")
			reconciler := &NetworkPolicyGeneratorReconciler{
				Client:    k8sClient,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying NetworkPolicy is created without global rules")
			networkPolicy := &networkingv1.NetworkPolicy{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName + "-generated",
					Namespace: namespace,
				}, networkPolicy)
			}, time.Second*10).Should(Succeed())

			Expect(networkPolicy.Spec.Ingress).To(BeEmpty())
			Expect(networkPolicy.Spec.Egress).To(BeEmpty())
		})

		It("should handle invalid modes", func() {
			By("Creating a NetworkPolicyGenerator with invalid mode")
			generator := &securityv1.NetworkPolicyGenerator{}
			Eventually(func() error {
				if err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				}, generator); err != nil {
					return err
				}
				generator.Spec.Mode = "invalid"
				return k8sClient.Update(ctx, generator)
			}, time.Second*10).Should(Succeed())

			By("Reconciling the resource")
			reconciler := &NetworkPolicyGeneratorReconciler{
				Client:    k8sClient,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
			}

			result, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid mode"))
			Expect(result).To(Equal(reconcile.Result{}))
		})

		It("should handle finalizers correctly", func() {
			By("Creating a new NetworkPolicyGenerator")
			generator := &securityv1.NetworkPolicyGenerator{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      generatorName,
				Namespace: namespace,
			}, generator)).To(Succeed())

			By("Reconciling the resource first time")
			reconciler := &NetworkPolicyGeneratorReconciler{
				Client:    k8sClient,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying finalizer is added to the resource")
			Eventually(func() bool {
				if err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				}, generator); err != nil {
					return false
				}
				return containsString(generator.ObjectMeta.Finalizers, finalizerName)
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Creating NetworkPolicy")
			generator.Spec.Mode = "enforcing"
			Expect(k8sClient.Update(ctx, generator)).To(Succeed())

			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying NetworkPolicy exists")
			networkPolicy := &networkingv1.NetworkPolicy{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName + "-generated",
					Namespace: namespace,
				}, networkPolicy)
			}, time.Second*10).Should(Succeed())

			By("Deleting the NetworkPolicyGenerator")
			Expect(k8sClient.Delete(ctx, generator)).To(Succeed())

			By("Reconciling after deletion request")
			_, err = reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying NetworkPolicy is deleted")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName + "-generated",
					Namespace: namespace,
				}, networkPolicy)
				return apierrors.IsNotFound(err)
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())

			By("Verifying NetworkPolicyGenerator is deleted")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				}, generator)
				return apierrors.IsNotFound(err)
			}, time.Second*10, time.Millisecond*250).Should(BeTrue())
		})

		It("should handle finalizer removal correctly when NetworkPolicy is already deleted", func() {
			By("Setting up NetworkPolicyGenerator with finalizer")
			generator := &securityv1.NetworkPolicyGenerator{}
			Eventually(func() error {
				if err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				}, generator); err != nil {
					return err
				}
				generator.ObjectMeta.Finalizers = append(generator.ObjectMeta.Finalizers, finalizerName)
				return k8sClient.Update(ctx, generator)
			}, time.Second*10).Should(Succeed())

			By("Deleting the NetworkPolicyGenerator")
			Expect(k8sClient.Delete(ctx, generator)).To(Succeed())

			By("Reconciling the deletion")
			reconciler := &NetworkPolicyGeneratorReconciler{
				Client:    k8sClient,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
			}

			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			By("Verifying NetworkPolicyGenerator is deleted")
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				}, generator)
				return apierrors.IsNotFound(err)
			}, time.Second*10).Should(BeTrue())
		})
	})
})
