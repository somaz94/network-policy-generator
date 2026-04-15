package controller

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"

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
			Recorder:  record.NewFakeRecorder(100),
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

	Context("Enforcing Mode with PolicyEngine", func() {
		It("should default to kubernetes engine when policyEngine is empty", func() {
			generator := createBasicGenerator(namespace, generatorName+"-k8s")
			generator.Spec.Mode = "enforcing"
			generator.Spec.PolicyEngine = ""
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			result, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(5 * time.Minute))
		})

		It("should use kubernetes engine explicitly", func() {
			generator := createBasicGenerator(namespace, generatorName+"-k8s-explicit")
			generator.Spec.Mode = "enforcing"
			generator.Spec.PolicyEngine = "kubernetes"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			result, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(5 * time.Minute))
		})

		It("should reject unsupported policy engine", func() {
			generator := createBasicGenerator(namespace, generatorName+"-bad-engine")
			generator.Spec.Mode = "enforcing"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Set invalid engine directly on the object (bypassing CRD validation)
			generator.Spec.PolicyEngine = "unknown-engine"

			_, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unsupported policy engine"))
		})
	})

	Context("NewReconciler", func() {
		It("should create reconciler with initialized fields", func() {
			r := NewReconciler(k8sClient, k8sClient.Scheme(), record.NewFakeRecorder(100))
			Expect(r).NotTo(BeNil())
			Expect(r.Client).NotTo(BeNil())
			Expect(r.Scheme).NotTo(BeNil())
			Expect(r.Generator).NotTo(BeNil())
			Expect(r.Validator).NotTo(BeNil())
		})
	})

	Context("Learning Mode Transition", func() {
		It("should transition to enforcing after duration expires", func() {
			generator := createBasicGenerator(namespace, generatorName+"-transition")
			generator.Spec.Duration = metav1.Duration{Duration: 1 * time.Second}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// First call triggers initial setup
			result, err := reconciler.handleLearningMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
			Expect(generator.Status.Phase).To(Equal("Learning"))

			// Re-fetch to get latest version
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: generatorName + "-transition", Namespace: namespace,
			}, generator)).To(Succeed())

			// Set LastAnalyzed to past to simulate duration elapsed
			generator.Status.LastAnalyzed = metav1.NewTime(time.Now().Add(-5 * time.Second))
			Expect(k8sClient.Status().Update(ctx, generator)).To(Succeed())

			result, err = reconciler.handleLearningMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue())
			Expect(generator.Status.Phase).To(Equal("Enforcing"))
		})
	})

	Context("CiliumGVK helper", func() {
		It("should return correct GVK", func() {
			gvk := gvkForEngine(policy.EngineCilium)
			Expect(gvk.Group).To(Equal("cilium.io"))
			Expect(gvk.Version).To(Equal("v2"))
			Expect(gvk.Kind).To(Equal("CiliumNetworkPolicy"))
		})
	})

	Context("Cilium Enforcing Mode", func() {
		It("should attempt cilium policy generation", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-cilium",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "cilium",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type:              "deny",
						AllowedNamespaces: []string{"ns1"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Cilium CRD is not installed in envtest, so applyCiliumPolicy will fail
			_, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("Learning Mode Error Handling", func() {
		It("should return error when initial status update fails", func() {
			generator := createBasicGenerator(namespace, generatorName+"-learn-err")
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			mockCl := &mockClient{Client: k8sClient, statusUpdateError: fmt.Errorf("status update failed")}
			errReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err := errReconciler.handleLearningMode(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("status update failed"))
		})

		It("should return error when transition status update fails", func() {
			generator := createBasicGenerator(namespace, generatorName+"-trans-err")
			generator.Spec.Duration = metav1.Duration{Duration: 1 * time.Second}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// First call: initial setup (succeeds)
			_, err := reconciler.handleLearningMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())

			// Re-fetch
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: generatorName + "-trans-err", Namespace: namespace,
			}, generator)).To(Succeed())

			// Set LastAnalyzed to past
			generator.Status.LastAnalyzed = metav1.NewTime(time.Now().Add(-5 * time.Second))
			Expect(k8sClient.Status().Update(ctx, generator)).To(Succeed())

			// Now use mock with status update error
			mockCl := &mockClient{Client: k8sClient, statusUpdateError: fmt.Errorf("transition failed")}
			errReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err = errReconciler.handleLearningMode(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("transition failed"))
		})
	})

	Context("Kubernetes Enforcing Error Handling", func() {
		It("should return error when status update fails after applying policies", func() {
			generator := createBasicGenerator(namespace, generatorName+"-k8s-status-err")
			generator.Spec.Mode = "enforcing"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			mockCl := &mockClient{Client: k8sClient, statusUpdateError: fmt.Errorf("enforcing status failed")}
			errReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err := errReconciler.handleEnforcingMode(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("enforcing status failed"))
		})
	})

	Context("SetupWithManager", func() {
		It("should setup the controller with a manager", func() {
			mgr, err := ctrl.NewManager(cfg, ctrl.Options{
				Scheme: k8sClient.Scheme(),
			})
			Expect(err).NotTo(HaveOccurred())

			r := NewReconciler(mgr.GetClient(), mgr.GetScheme(), record.NewFakeRecorder(100))
			err = r.SetupWithManager(mgr)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("Reconcile Edge Cases", func() {
		It("should handle not-found resource gracefully", func() {
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "nonexistent",
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result).To(Equal(ctrl.Result{}))
		})

		It("should handle deletion without finalizer", func() {
			generator := createBasicGenerator(namespace, generatorName+"-no-finalizer")
			generator.Spec.Mode = "enforcing"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Delete immediately (no finalizer added yet since no reconcile)
			Expect(k8sClient.Delete(ctx, generator)).To(Succeed())

			// Reconcile should handle gracefully
			Eventually(func() error {
				_, err := reconciler.Reconcile(ctx, ctrl.Request{
					NamespacedName: types.NamespacedName{
						Name:      generatorName + "-no-finalizer",
						Namespace: namespace,
					},
				})
				return err
			}, timeout, interval).Should(Succeed())
		})

		It("should reconcile enforcing mode end to end", func() {
			generator := createBasicGenerator(namespace, generatorName+"-e2e-enforcing")
			generator.Spec.Mode = "enforcing"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// First reconcile: sets phase, adds finalizer
			_, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName + "-e2e-enforcing",
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			// Second reconcile: applies policies
			result, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName + "-e2e-enforcing",
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(5 * time.Minute))

			// Verify policy was created
			np := &networkingv1.NetworkPolicy{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName + "-e2e-enforcing-generated",
					Namespace: namespace,
				}, np)
			}, timeout, interval).Should(Succeed())
		})
	})

	Context("Delete NetworkPolicies for Allow Type", func() {
		It("should delete policies in denied namespaces for allow type", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-allow-del",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:     "enforcing",
					Duration: metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type:             "allow",
						DeniedNamespaces: []string{namespace},
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Create a network policy in the namespace
			np := &networkingv1.NetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-allow-del-generated",
					Namespace: namespace,
				},
			}
			Expect(k8sClient.Create(ctx, np)).To(Succeed())

			// deleteNetworkPolicies should clean it up
			err := reconciler.deleteNetworkPolicies(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("Learning Mode Spec Update Error", func() {
		It("should return error when spec update fails during transition", func() {
			generator := createBasicGenerator(namespace, generatorName+"-spec-err")
			generator.Spec.Duration = metav1.Duration{Duration: 1 * time.Second}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// First call: initial setup
			_, err := reconciler.handleLearningMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())

			// Re-fetch
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: generatorName + "-spec-err", Namespace: namespace,
			}, generator)).To(Succeed())

			// Set LastAnalyzed to past
			generator.Status.LastAnalyzed = metav1.NewTime(time.Now().Add(-5 * time.Second))
			Expect(k8sClient.Status().Update(ctx, generator)).To(Succeed())

			// Mock that fails on Update (spec update after transition)
			mockCl := &mockClient{Client: k8sClient, updateError: fmt.Errorf("spec update failed")}
			errReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err = errReconciler.handleLearningMode(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec update failed"))
		})
	})

	Context("Reconcile Add Finalizer Error", func() {
		It("should return error when adding finalizer fails", func() {
			generator := createBasicGenerator(namespace, generatorName+"-fin-err")
			generator.Spec.Mode = "enforcing"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Mock that fails on Update (adding finalizer)
			mockCl := &mockClient{Client: k8sClient, updateError: fmt.Errorf("finalizer add failed")}
			errReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err := errReconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName + "-fin-err",
					Namespace: namespace,
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("finalizer add failed"))
		})
	})

	Context("Apply NetworkPolicy Error", func() {
		It("should return error when creating policy fails", func() {
			generator := createBasicGenerator(namespace, generatorName+"-apply-err")
			generator.Spec.Mode = "enforcing"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Mock that fails on Create (applyNetworkPolicy)
			mockCl := &mockClient{Client: k8sClient, createError: fmt.Errorf("create policy failed")}
			errReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err := errReconciler.handleEnforcingMode(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("create policy failed"))
		})

		It("should return error when Get returns non-not-found error", func() {
			generator := createBasicGenerator(namespace, generatorName+"-get-err")
			generator.Spec.Mode = "enforcing"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Mock that returns a non-not-found error on Get
			mockCl := &mockClient{Client: k8sClient, getError: fmt.Errorf("connection refused")}
			errReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err := errReconciler.handleEnforcingMode(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("connection refused"))
		})
	})

	Context("Reconcile Deletion with Finalizer", func() {
		It("should clean up policies and remove finalizer on deletion", func() {
			generator := createBasicGenerator(namespace, generatorName+"-del-fin")
			generator.Spec.Mode = "enforcing"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// First reconcile adds finalizer
			_, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName + "-del-fin",
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			// Verify finalizer was added
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: generatorName + "-del-fin", Namespace: namespace,
			}, generator)).To(Succeed())
			Expect(generator.Finalizers).To(ContainElement("security.policy.io/finalizer"))

			// Delete the generator
			Expect(k8sClient.Delete(ctx, generator)).To(Succeed())

			// Reconcile should handle finalizer cleanup
			_, err = reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName + "-del-fin",
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return error when delete policies fails during finalizer cleanup", func() {
			generator := createBasicGenerator(namespace, generatorName+"-del-err")
			generator.Spec.Mode = "enforcing"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Add finalizer via reconcile
			_, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName + "-del-err",
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			// Re-fetch and delete
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: generatorName + "-del-err", Namespace: namespace,
			}, generator)).To(Succeed())
			Expect(k8sClient.Delete(ctx, generator)).To(Succeed())

			// Mock that fails on Delete (deleteNetworkPolicies)
			mockCl := &mockClient{Client: k8sClient, deleteError: fmt.Errorf("delete policy failed")}
			errReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err = errReconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName + "-del-err",
					Namespace: namespace,
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("delete policy failed"))
		})

		It("should return error when removing finalizer fails", func() {
			generator := createBasicGenerator(namespace, generatorName+"-rm-fin-err")
			generator.Spec.Mode = "enforcing"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Add finalizer via reconcile
			_, err := reconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName + "-rm-fin-err",
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())

			// Re-fetch and delete
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: generatorName + "-rm-fin-err", Namespace: namespace,
			}, generator)).To(Succeed())
			Expect(k8sClient.Delete(ctx, generator)).To(Succeed())

			// Mock that fails on Update (removing finalizer) but allows Delete
			mockCl := &mockClient{Client: k8sClient, updateError: fmt.Errorf("remove finalizer failed")}
			errReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err = errReconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName + "-rm-fin-err",
					Namespace: namespace,
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("remove finalizer failed"))
		})
	})

	Context("Reconcile Status Update Error", func() {
		It("should return error when initial status update fails in Reconcile", func() {
			generator := createBasicGenerator(namespace, generatorName+"-status-init-err")
			generator.Spec.Mode = "enforcing"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			mockCl := &mockClient{Client: k8sClient, statusUpdateError: fmt.Errorf("status init failed")}
			errReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err := errReconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName + "-status-init-err",
					Namespace: namespace,
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("status init failed"))
		})
	})

	Context("Kubernetes Dry Run Mode", func() {
		It("should store generated policies in status without applying", func() {
			generator := createBasicGenerator(namespace, generatorName+"-k8s-dryrun")
			generator.Spec.Mode = "enforcing"
			generator.Spec.DryRun = true
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			result, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(5 * time.Minute))

			// Re-fetch to check status
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: generatorName + "-k8s-dryrun", Namespace: namespace,
			}, generator)).To(Succeed())
			Expect(generator.Status.GeneratedPolicies).NotTo(BeEmpty())
			Expect(generator.Status.AppliedPoliciesCount).To(Equal(0))

			// Verify no actual NetworkPolicy was created
			np := &networkingv1.NetworkPolicy{}
			err = k8sClient.Get(ctx, types.NamespacedName{
				Name:      generatorName + "-k8s-dryrun-generated",
				Namespace: namespace,
			}, np)
			Expect(apierrors.IsNotFound(err)).To(BeTrue())
		})

		It("should return error when status update fails in dry-run", func() {
			generator := createBasicGenerator(namespace, generatorName+"-k8s-dryrun-err")
			generator.Spec.Mode = "enforcing"
			generator.Spec.DryRun = true
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			mockCl := &mockClient{Client: k8sClient, statusUpdateError: fmt.Errorf("dryrun status failed")}
			errReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err := errReconciler.handleEnforcingMode(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("dryrun status failed"))
		})
	})

	Context("Cilium Dry Run Mode", func() {
		It("should store generated cilium policies in status without applying", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-cilium-dryrun",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "cilium",
					DryRun:       true,
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type:              "deny",
						AllowedNamespaces: []string{"ns1"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			result, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(5 * time.Minute))

			// Re-fetch to check status
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: generatorName + "-cilium-dryrun", Namespace: namespace,
			}, generator)).To(Succeed())
			Expect(generator.Status.GeneratedPolicies).NotTo(BeEmpty())
			Expect(generator.Status.AppliedPoliciesCount).To(Equal(0))
		})

		It("should return error when status update fails in cilium dry-run", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-cilium-dryrun-err",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "cilium",
					DryRun:       true,
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type:              "deny",
						AllowedNamespaces: []string{"ns1"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			mockCl := &mockClient{Client: k8sClient, statusUpdateError: fmt.Errorf("cilium dryrun status failed")}
			errReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err := errReconciler.handleEnforcingMode(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("cilium dryrun status failed"))
		})
	})

	Context("Policy Diff Tracking", func() {
		It("should track Created action for new policies", func() {
			generator := createBasicGenerator(namespace, generatorName+"-diff-create")
			generator.Spec.Mode = "enforcing"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			result, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(5 * time.Minute))

			// Re-fetch to check status
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: generatorName + "-diff-create", Namespace: namespace,
			}, generator)).To(Succeed())
			Expect(generator.Status.PolicyDiff).NotTo(BeEmpty())
			Expect(generator.Status.PolicyDiff[0].Action).To(Equal("Created"))
			Expect(generator.Status.AppliedPoliciesCount).To(Equal(1))
		})

		It("should track Updated action for existing policies", func() {
			generator := createBasicGenerator(namespace, generatorName+"-diff-update")
			generator.Spec.Mode = "enforcing"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// First apply creates the policy
			_, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())

			// Re-fetch
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: generatorName + "-diff-update", Namespace: namespace,
			}, generator)).To(Succeed())

			// Second apply should be "Updated"
			_, err = reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())

			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: generatorName + "-diff-update", Namespace: namespace,
			}, generator)).To(Succeed())
			Expect(generator.Status.PolicyDiff).NotTo(BeEmpty())
			Expect(generator.Status.PolicyDiff[0].Action).To(Equal("Updated"))
		})
	})

	Context("Enforcing with Pod Selector", func() {
		It("should create policy with pod selector labels", func() {
			generator := createBasicGenerator(namespace, generatorName+"-podselector")
			generator.Spec.Mode = "enforcing"
			generator.Spec.Policy.PodSelector = map[string]string{
				"app":  "web",
				"tier": "frontend",
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			_, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())

			np := &networkingv1.NetworkPolicy{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName + "-podselector-generated",
					Namespace: namespace,
				}, np)
			}, timeout, interval).Should(Succeed())

			Expect(np.Spec.PodSelector.MatchLabels["app"]).To(Equal("web"))
			Expect(np.Spec.PodSelector.MatchLabels["tier"]).To(Equal("frontend"))
		})
	})

	Context("Enforcing with CIDR Rules", func() {
		It("should create policy with CIDR-based rules", func() {
			generator := createBasicGenerator(namespace, generatorName+"-cidr")
			generator.Spec.Mode = "enforcing"
			generator.Spec.CIDRRules = []securityv1.CIDRRule{
				{
					CIDR:      "10.0.0.0/8",
					Direction: "egress",
				},
				{
					CIDR:      "192.168.1.0/24",
					Except:    []string{"192.168.1.100/32"},
					Direction: "ingress",
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			_, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())

			np := &networkingv1.NetworkPolicy{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName + "-cidr-generated",
					Namespace: namespace,
				}, np)
			}, timeout, interval).Should(Succeed())

			// Should have CIDR ingress rule
			hasCIDRIngress := false
			for _, rule := range np.Spec.Ingress {
				for _, from := range rule.From {
					if from.IPBlock != nil && from.IPBlock.CIDR == "192.168.1.0/24" {
						hasCIDRIngress = true
						Expect(from.IPBlock.Except).To(ContainElement("192.168.1.100/32"))
					}
				}
			}
			Expect(hasCIDRIngress).To(BeTrue())

			// Should have CIDR egress rule
			hasCIDREgress := false
			for _, rule := range np.Spec.Egress {
				for _, to := range rule.To {
					if to.IPBlock != nil && to.IPBlock.CIDR == "10.0.0.0/8" {
						hasCIDREgress = true
					}
				}
			}
			Expect(hasCIDREgress).To(BeTrue())
		})
	})

	Context("Enforcing with Named Port", func() {
		It("should create policy with named port in global rules", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-namedport",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:     "enforcing",
					Duration: metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type: "deny",
					},
					GlobalRules: []securityv1.GlobalRule{
						{
							Type:      "allow",
							NamedPort: "http",
							Protocol:  "TCP",
							Direction: "ingress",
						},
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			_, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())

			np := &networkingv1.NetworkPolicy{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName + "-namedport-generated",
					Namespace: namespace,
				}, np)
			}, timeout, interval).Should(Succeed())

			hasNamedPort := false
			for _, rule := range np.Spec.Ingress {
				for _, port := range rule.Ports {
					if port.Port != nil && port.Port.StrVal == "http" {
						hasNamedPort = true
					}
				}
			}
			Expect(hasNamedPort).To(BeTrue())
		})
	})

	Context("CalicoGVK helper", func() {
		It("should return correct GVK", func() {
			gvk := gvkForEngine(policy.EngineCalico)
			Expect(gvk.Group).To(Equal("crd.projectcalico.org"))
			Expect(gvk.Version).To(Equal("v1"))
			Expect(gvk.Kind).To(Equal("NetworkPolicy"))
		})
	})

	Context("Calico Enforcing Mode", func() {
		It("should attempt calico policy generation", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-calico",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "calico",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type: "deny",
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Calico CRD is not installed in envtest, so applyCalicoPolicy will fail
			_, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("Calico Enforcing Success Path", func() {
		It("should successfully apply calico policy with mock client", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-calico-ok",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "calico",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type: "deny",
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			mockCl := &mockClient{
				Client:     k8sClient,
				getError:   apierrors.NewNotFound(schema.GroupResource{Group: "crd.projectcalico.org", Resource: "networkpolicies"}, ""),
				noopCreate: true,
			}
			calicoReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			result, err := calicoReconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(5 * time.Minute))
		})

		It("should handle calico dry-run mode", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-calico-dryrun",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "calico",
					DryRun:       true,
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type: "deny",
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			result, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(5 * time.Minute))

			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: generatorName + "-calico-dryrun", Namespace: namespace,
			}, generator)).To(Succeed())
			Expect(generator.Status.GeneratedPolicies).NotTo(BeEmpty())
			Expect(generator.Status.AppliedPoliciesCount).To(Equal(0))
		})
	})

	Context("Calico Enforcing via handleEnforcingMode", func() {
		It("should dispatch to calico engine", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-calico-dispatch",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "calico",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type: "deny",
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// handleEnforcingMode should dispatch to handleEnforcingMode
			// Calico CRD not installed, so it will fail at apply time
			_, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("Policy Template Integration", func() {
		It("should apply template rules in enforcing mode", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-template",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					TemplateName: "web-app",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type: "deny",
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			_, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())

			// Check the generated NetworkPolicy has ingress rules from web-app template
			np := &networkingv1.NetworkPolicy{}
			Eventually(func() error {
				return k8sClient.Get(ctx, types.NamespacedName{
					Name:      generatorName + "-template-generated",
					Namespace: namespace,
				}, np)
			}, timeout, interval).Should(Succeed())

			// web-app template adds port 80 and 443 ingress rules
			Expect(np.Spec.Ingress).NotTo(BeEmpty())
		})

		It("should not modify spec when template is empty", func() {
			generator := createBasicGenerator(namespace, generatorName+"-no-template")
			generator.Spec.Mode = "enforcing"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			originalRules := len(generator.Spec.GlobalRules)
			_, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(generator.Spec.GlobalRules)).To(Equal(originalRules))
		})

		It("should not modify spec when template name is invalid", func() {
			generator := createBasicGenerator(namespace, generatorName+"-bad-template")
			generator.Spec.Mode = "enforcing"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Set invalid template name after creation to bypass CRD validation
			generator.Spec.TemplateName = "nonexistent"

			_, err := reconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("Learning Mode Suggestions", func() {
		It("should build suggestions from observed traffic", func() {
			generator := createBasicGenerator(namespace, generatorName+"-suggest")
			generator.Spec.Duration = metav1.Duration{Duration: 1 * time.Second}
			generator.Status.ObservedTraffic = []securityv1.TrafficFlow{
				{
					SourceNamespace: "external-ns",
					DestNamespace:   namespace,
					Protocol:        "TCP",
					Port:            80,
				},
				{
					SourceNamespace: namespace,
					DestNamespace:   "db-ns",
					Protocol:        "TCP",
					Port:            5432,
				},
				{
					SourceNamespace: "monitoring-ns",
					DestNamespace:   namespace,
					Protocol:        "TCP",
					Port:            9090,
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Initial setup
			_, err := reconciler.handleLearningMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())

			// Re-fetch and set time to past
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: generatorName + "-suggest", Namespace: namespace,
			}, generator)).To(Succeed())
			generator.Status.LastAnalyzed = metav1.NewTime(time.Now().Add(-5 * time.Second))
			generator.Status.ObservedTraffic = []securityv1.TrafficFlow{
				{
					SourceNamespace: "external-ns",
					DestNamespace:   namespace,
					Protocol:        "TCP",
					Port:            80,
				},
				{
					SourceNamespace: namespace,
					DestNamespace:   "db-ns",
					Protocol:        "TCP",
					Port:            5432,
				},
			}
			Expect(k8sClient.Status().Update(ctx, generator)).To(Succeed())

			// Transition should build suggestions
			result, err := reconciler.handleLearningMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.Requeue).To(BeTrue())

			// Should have suggested namespaces
			Expect(generator.Status.SuggestedNamespaces).To(ContainElement("external-ns"))
			Expect(generator.Status.SuggestedNamespaces).To(ContainElement("db-ns"))
			// Own namespace should not be suggested
			Expect(generator.Status.SuggestedNamespaces).NotTo(ContainElement(namespace))

			// Should have suggested rules
			Expect(generator.Status.SuggestedRules).NotTo(BeEmpty())
		})

		It("should handle empty traffic gracefully", func() {
			generator := createBasicGenerator(namespace, generatorName+"-no-traffic")
			generator.Status.ObservedTraffic = nil

			reconciler.buildLearningSuggestions(generator)

			Expect(generator.Status.SuggestedNamespaces).To(BeEmpty())
			Expect(generator.Status.SuggestedRules).To(BeEmpty())
		})
	})

	Context("deleteNetworkPolicies with Cilium engine", func() {
		It("should delete cilium policies via deleteUnstructuredPolicy", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-del-cilium",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "cilium",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type: "deny",
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Mock: Delete returns NotFound (ignored by deleteUnstructuredPolicy)
			mockCl := &mockClient{
				Client:     k8sClient,
				noopDelete: true,
			}
			ciliumReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			err := ciliumReconciler.deleteNetworkPolicies(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return error when cilium delete fails with non-NotFound error", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-del-cilium-err",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "cilium",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type: "deny",
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			mockCl := &mockClient{
				Client:      k8sClient,
				deleteError: fmt.Errorf("cilium delete failed"),
			}
			ciliumReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			err := ciliumReconciler.deleteNetworkPolicies(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("cilium delete failed"))
		})
	})

	Context("deleteNetworkPolicies with Calico engine", func() {
		It("should delete calico policies via deleteUnstructuredPolicy", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-del-calico",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "calico",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type: "deny",
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			mockCl := &mockClient{
				Client:     k8sClient,
				noopDelete: true,
			}
			calicoReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			err := calicoReconciler.deleteNetworkPolicies(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return error when calico delete fails with non-NotFound error", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-del-calico-err",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "calico",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type: "deny",
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			mockCl := &mockClient{
				Client:      k8sClient,
				deleteError: fmt.Errorf("calico delete failed"),
			}
			calicoReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			err := calicoReconciler.deleteNetworkPolicies(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("calico delete failed"))
		})
	})

	Context("Reconcile with invalid mode via mock", func() {
		It("should return error for empty/invalid mode hitting default case", func() {
			// Create a valid generator in the API server
			generator := createBasicGenerator(namespace, generatorName+"-invalid-mode")
			generator.Spec.Mode = "enforcing"
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Use mock with noopGet: returns empty generator (Mode=""), hitting default switch case
			// noopStatusUpdate: so syncPhase doesn't fail
			// noopUpdate: so AddFinalizer doesn't fail
			mockCl := &mockClient{
				Client:           k8sClient,
				noopGet:          true,
				noopStatusUpdate: true,
				noopUpdate:       true,
			}
			mockReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err := mockReconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName + "-invalid-mode",
					Namespace: namespace,
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid mode"))
		})
	})

	Context("Reconcile Get non-NotFound error", func() {
		It("should return error when Get fails with non-NotFound error", func() {
			mockCl := &mockClient{
				Client:   k8sClient,
				getError: fmt.Errorf("api server unavailable"),
			}
			mockReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err := mockReconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      "any-name",
					Namespace: namespace,
				},
			})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("api server unavailable"))
		})
	})

	Context("Calico deletion on finalizer cleanup", func() {
		It("should clean up calico policies and remove finalizer on deletion", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-calico-del-fin",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "calico",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type: "deny",
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// First reconcile adds finalizer (use noop for calico apply parts)
			mockCl := &mockClient{
				Client:     k8sClient,
				noopDelete: true,
			}
			calicoReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			// Use real reconciler for first reconcile (adds finalizer, but calico apply will fail)
			// Instead, manually add finalizer
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: generatorName + "-calico-del-fin", Namespace: namespace,
			}, generator)).To(Succeed())
			generator.Finalizers = []string{finalizerName}
			Expect(k8sClient.Update(ctx, generator)).To(Succeed())

			// Delete the generator
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: generatorName + "-calico-del-fin", Namespace: namespace,
			}, generator)).To(Succeed())
			Expect(k8sClient.Delete(ctx, generator)).To(Succeed())

			// Reconcile with mock that allows calico delete (noopDelete)
			_, err := calicoReconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName + "-calico-del-fin",
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("Calico apply error in loop", func() {
		It("should return error when applyCalicoPolicy fails in loop", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-calico-loop-err",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "calico",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type:              "deny",
						AllowedNamespaces: []string{"ns1"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Mock: Get returns NotFound, Create fails
			mockCl := &mockClient{
				Client:      k8sClient,
				getError:    apierrors.NewNotFound(schema.GroupResource{Group: "crd.projectcalico.org", Resource: "networkpolicies"}, ""),
				createError: fmt.Errorf("calico create failed"),
			}
			calicoReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err := calicoReconciler.handleEnforcingMode(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("calico create failed"))
		})

		It("should return error when Get returns non-NotFound error in applyCalicoPolicy", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-calico-get-err",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "calico",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type:              "deny",
						AllowedNamespaces: []string{"ns1"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			mockCl := &mockClient{
				Client:   k8sClient,
				getError: fmt.Errorf("calico connection timeout"),
			}
			calicoReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err := calicoReconciler.handleEnforcingMode(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("calico connection timeout"))
		})

		It("should return error when status update fails after calico apply", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-calico-status-err",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "calico",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type:              "deny",
						AllowedNamespaces: []string{"ns1"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			mockCl := &mockClient{
				Client:            k8sClient,
				getError:          apierrors.NewNotFound(schema.GroupResource{Group: "crd.projectcalico.org", Resource: "networkpolicies"}, ""),
				noopCreate:        true,
				statusUpdateError: fmt.Errorf("calico status update failed"),
			}
			calicoReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err := calicoReconciler.handleEnforcingMode(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("calico status update failed"))
		})

		It("should update existing calico policy via noop mock", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-calico-upd",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "calico",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type:              "deny",
						AllowedNamespaces: []string{"ns1"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Mock: Get returns nil (existing found via noop), Update succeeds (noop)
			mockCl := &mockClient{
				Client:     k8sClient,
				noopGet:    true,
				noopUpdate: true,
			}
			calicoReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			result, err := calicoReconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(5 * time.Minute))
		})
	})

	Context("Cilium deletion on finalizer cleanup", func() {
		It("should clean up cilium policies and remove finalizer on deletion", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-cilium-del-fin",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "cilium",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type: "deny",
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			mockCl := &mockClient{
				Client:     k8sClient,
				noopDelete: true,
			}
			ciliumReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			// Manually add finalizer
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: generatorName + "-cilium-del-fin", Namespace: namespace,
			}, generator)).To(Succeed())
			generator.Finalizers = []string{finalizerName}
			Expect(k8sClient.Update(ctx, generator)).To(Succeed())

			// Delete the generator
			Expect(k8sClient.Get(ctx, types.NamespacedName{
				Name: generatorName + "-cilium-del-fin", Namespace: namespace,
			}, generator)).To(Succeed())
			Expect(k8sClient.Delete(ctx, generator)).To(Succeed())

			// Reconcile with mock that allows cilium delete
			_, err := ciliumReconciler.Reconcile(ctx, ctrl.Request{
				NamespacedName: types.NamespacedName{
					Name:      generatorName + "-cilium-del-fin",
					Namespace: namespace,
				},
			})
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("Calico Dry Run Status Error", func() {
		It("should return error when status update fails in calico dry-run", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-calico-dryrun-err",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "calico",
					DryRun:       true,
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type: "deny",
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			mockCl := &mockClient{Client: k8sClient, statusUpdateError: fmt.Errorf("calico dryrun status failed")}
			errReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err := errReconciler.handleEnforcingMode(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("calico dryrun status failed"))
		})
	})

	Context("Cilium Enforcing Success Path", func() {
		It("should successfully apply cilium policy with mock client", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-cilium-ok",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "cilium",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type:              "deny",
						AllowedNamespaces: []string{"ns1"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Mock: Get returns NotFound (no existing cilium policy), Create succeeds (noop)
			mockCl := &mockClient{
				Client:     k8sClient,
				getError:   apierrors.NewNotFound(schema.GroupResource{Group: "cilium.io", Resource: "ciliumnetworkpolicies"}, ""),
				noopCreate: true,
			}
			ciliumReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			result, err := ciliumReconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(5 * time.Minute))
		})

		It("should update existing cilium policy via noop mock", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-cilium-upd",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "cilium",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type:              "deny",
						AllowedNamespaces: []string{"ns1"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Mock: Get returns nil (existing found via noop), Update succeeds (noop)
			mockCl := &mockClient{
				Client:     k8sClient,
				noopGet:    true,
				noopUpdate: true,
			}
			ciliumReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			result, err := ciliumReconciler.handleEnforcingMode(ctx, generator)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(5 * time.Minute))
		})

		It("should handle cilium apply error in loop", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-cilium-loop-err",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "cilium",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type:              "deny",
						AllowedNamespaces: []string{"ns1"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Mock: Get returns NotFound, Create fails
			mockCl := &mockClient{
				Client:      k8sClient,
				getError:    apierrors.NewNotFound(schema.GroupResource{Group: "cilium.io", Resource: "ciliumnetworkpolicies"}, ""),
				createError: fmt.Errorf("cilium create failed"),
			}
			ciliumReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err := ciliumReconciler.handleEnforcingMode(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("cilium create failed"))
		})

		It("should return error when Get returns non-not-found error in applyCiliumPolicy", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-cilium-get-err",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "cilium",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type:              "deny",
						AllowedNamespaces: []string{"ns1"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Mock: Get returns a non-not-found error
			mockCl := &mockClient{
				Client:   k8sClient,
				getError: fmt.Errorf("connection timeout"),
			}
			ciliumReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err := ciliumReconciler.handleEnforcingMode(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("connection timeout"))
		})

		It("should return error when status update fails after cilium apply", func() {
			generator := &securityv1.NetworkPolicyGenerator{
				ObjectMeta: metav1.ObjectMeta{
					Name:      generatorName + "-cilium-status-err",
					Namespace: namespace,
				},
				Spec: securityv1.NetworkPolicyGeneratorSpec{
					Mode:         "enforcing",
					PolicyEngine: "cilium",
					Duration:     metav1.Duration{Duration: time.Minute},
					Policy: securityv1.PolicyConfig{
						Type:              "deny",
						AllowedNamespaces: []string{"ns1"},
					},
				},
			}
			Expect(k8sClient.Create(ctx, generator)).To(Succeed())

			// Mock: Get returns NotFound, Create succeeds (noop), Status update fails
			mockCl := &mockClient{
				Client:            k8sClient,
				getError:          apierrors.NewNotFound(schema.GroupResource{Group: "cilium.io", Resource: "ciliumnetworkpolicies"}, ""),
				noopCreate:        true,
				statusUpdateError: fmt.Errorf("cilium status update failed"),
			}
			ciliumReconciler := &NetworkPolicyGeneratorReconciler{
				Client:    mockCl,
				Scheme:    k8sClient.Scheme(),
				Generator: policy.NewGenerator(),
				Validator: policy.NewValidator(),
				Recorder:  record.NewFakeRecorder(100),
			}

			_, err := ciliumReconciler.handleEnforcingMode(ctx, generator)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("cilium status update failed"))
		})
	})
})
