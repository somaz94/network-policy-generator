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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
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
			var err error
			ctx = context.Background()
			generatorName = "test-generator"

			// Create test namespace using helper function
			namespace, err = setupTestNamespace(ctx, k8sClient)
			Expect(err).NotTo(HaveOccurred())

			// Create basic NetworkPolicyGenerator using helper function from test_helpers.go
			generator := createBasicGenerator(namespace, generatorName)
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
			}, timeout, interval).Should(Equal("Learning"))

			By("Verifying NetworkPolicy is not created in learning mode")
			networkPolicy := &networkingv1.NetworkPolicy{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      generatorName + "-generated",
				Namespace: namespace,
			}, networkPolicy)
			Expect(apierrors.IsNotFound(err)).To(BeTrue())
		})

		It("should handle invalid modes", func() {
			By("Creating a NetworkPolicyGenerator with invalid mode")
			generator := createBasicGenerator(namespace, generatorName+"-invalid")
			generator.Spec.Mode = "invalid"

			// 에러가 발생하는 것이 정상적인 동작
			err := k8sClient.Create(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("Unsupported value"))

			// 올바른 모드로 변경
			generator.Spec.Mode = "learning"
			generator.Name = generatorName + "-valid"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())
		})

		It("should handle finalizers correctly", func() {
			By("Creating a new NetworkPolicyGenerator")
			generator := &securityv1.NetworkPolicyGenerator{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      generatorName,
				Namespace: namespace,
			}, generator)).To(Succeed())

			By("Setting initial mode to enforcing")
			generator.Spec.Mode = "enforcing"
			Expect(k8sClient.Update(ctx, generator)).To(Succeed())

			reconciler := &NetworkPolicyGeneratorReconciler{
				Client:    k8sClient,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
			}

			By("Reconciling and waiting for finalizer")
			Eventually(func() bool {
				_, err := reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      generatorName,
						Namespace: namespace,
					},
				})
				if err != nil {
					return false
				}

				if err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				}, generator); err != nil {
					return false
				}
				return containsString(generator.ObjectMeta.Finalizers, finalizerName)
			}, timeout, interval).Should(BeTrue())

			By("Deleting the resource")
			Expect(k8sClient.Delete(ctx, generator)).To(Succeed())

			By("Verifying cleanup with multiple reconciliations")
			Eventually(func() bool {
				// Try to reconcile a few times
				_, _ = reconciler.Reconcile(ctx, reconcile.Request{
					NamespacedName: types.NamespacedName{
						Name:      generatorName,
						Namespace: namespace,
					},
				})

				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				}, generator)
				return apierrors.IsNotFound(err)
			}, timeout, interval).Should(BeTrue())
		})

		It("should handle status update errors", func() {
			generator := createBasicGenerator(namespace, generatorName)
			generator.Spec.Mode = "learning"

			// Mock status update error
			mockClient := &mockClient{Client: k8sClient}
			mockClient.statusUpdateError = fmt.Errorf("status update failed")

			reconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockClient,
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
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("status update failed"))
		})

		It("should handle policy deletion errors", func() {
			generator := &securityv1.NetworkPolicyGenerator{}
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name:      generatorName,
				Namespace: namespace,
			}, generator)).To(Succeed())

			// Add finalizer
			generator.ObjectMeta.Finalizers = []string{finalizerName}
			Expect(k8sClient.Update(ctx, generator)).To(Succeed())

			// Create NetworkPolicy
			networkPolicy := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generator.Name + "-generated",
					Namespace: generator.Namespace,
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: securityv1.GroupVersion.String(),
						Kind:       "NetworkPolicyGenerator",
						Name:       generator.Name,
						UID:        generator.UID,
					}},
				},
			}
			Expect(k8sClient.Create(ctx, networkPolicy)).To(Succeed())

			// Delete the generator to trigger deletion timestamp
			Expect(k8sClient.Delete(ctx, generator)).To(Succeed())

			// Mock delete error
			mockClient := &mockClient{Client: k8sClient}
			mockClient.deleteError = fmt.Errorf("delete failed")

			reconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockClient,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
			}

			// Wait for deletion timestamp to be set
			Eventually(func() bool {
				err := k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				}, generator)
				return err == nil && generator.DeletionTimestamp != nil
			}, timeout, interval).Should(BeTrue())

			// Attempt reconciliation
			_, err := reconciler.Reconcile(ctx, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName,
					Namespace: namespace,
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("delete failed"))
		})
	})
})
