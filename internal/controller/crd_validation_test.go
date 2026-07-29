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
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
)

// These specs exercise the CRD schema itself (defaults and CEL
// x-kubernetes-validations) against the envtest apiserver. They are the
// always-on counterpart to the opt-in validating webhook: the rules here hold
// even when the operator runs without --enable-webhooks.
var _ = Describe("NetworkPolicyGenerator CRD validation", func() {
	var namespace string

	BeforeEach(func() {
		var err error
		namespace, err = setupTestNamespace(ctx, k8sClient)
		Expect(err).NotTo(HaveOccurred())
	})

	// newGenerator returns a minimal spec that satisfies every CRD rule, so each
	// spec below can mutate exactly the one field under test.
	newGenerator := func(name string) *securityv1.NetworkPolicyGenerator {
		return &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				Mode:   "enforcing",
				Policy: securityv1.PolicyConfig{Type: "deny", AllowedNamespaces: []string{"ns-a"}},
			},
		}
	}

	Context("spec.mode", func() {
		It("defaults to learning when omitted", func() {
			gen := newGenerator("default-mode")
			gen.Spec.Mode = ""
			gen.Spec.Duration = metav1.Duration{Duration: time.Minute}

			Expect(k8sClient.Create(ctx, gen)).To(Succeed())
			Expect(gen.Spec.Mode).To(Equal("learning"),
				"an omitted mode must default instead of failing every reconcile with 'invalid mode'")
		})

		It("rejects a value outside the enum", func() {
			gen := newGenerator("bad-mode")
			gen.Spec.Mode = "auditing"

			err := k8sClient.Create(ctx, gen)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("spec.mode"))
		})
	})

	Context("learning mode requires a positive duration", func() {
		It("rejects learning mode with a zero duration", func() {
			gen := newGenerator("learning-no-duration")
			gen.Spec.Mode = "learning"

			err := k8sClient.Create(ctx, gen)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("must be positive when mode is 'learning'"),
				"a zero duration would transition straight to enforcing on the next reconcile")
		})

		It("accepts learning mode with a positive duration", func() {
			gen := newGenerator("learning-with-duration")
			gen.Spec.Mode = "learning"
			gen.Spec.Duration = metav1.Duration{Duration: 30 * time.Second}

			Expect(k8sClient.Create(ctx, gen)).To(Succeed())
		})

		It("does not require a duration in enforcing mode", func() {
			gen := newGenerator("enforcing-no-duration")

			Expect(k8sClient.Create(ctx, gen)).To(Succeed())
		})
	})

	Context("globalRules port vs namedPort", func() {
		rule := func(mutate func(*securityv1.GlobalRule)) securityv1.GlobalRule {
			r := securityv1.GlobalRule{Type: "allow", Protocol: "TCP", Direction: "ingress"}
			mutate(&r)
			return r
		}

		It("rejects a rule specifying both port and namedPort", func() {
			gen := newGenerator("rule-both-ports")
			gen.Spec.GlobalRules = []securityv1.GlobalRule{
				rule(func(r *securityv1.GlobalRule) { r.Port = 80; r.NamedPort = "http" }),
			}

			err := k8sClient.Create(ctx, gen)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("exactly one of port or namedPort"))
		})

		It("rejects a rule specifying neither port nor namedPort", func() {
			gen := newGenerator("rule-no-port")
			gen.Spec.GlobalRules = []securityv1.GlobalRule{rule(func(_ *securityv1.GlobalRule) {})}

			err := k8sClient.Create(ctx, gen)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("exactly one of port or namedPort"))
		})

		It("accepts a numeric port alone", func() {
			gen := newGenerator("rule-numeric-port")
			gen.Spec.GlobalRules = []securityv1.GlobalRule{
				rule(func(r *securityv1.GlobalRule) { r.Port = 8080 }),
			}

			Expect(k8sClient.Create(ctx, gen)).To(Succeed())
		})

		It("accepts a named port alone", func() {
			gen := newGenerator("rule-named-port")
			gen.Spec.GlobalRules = []securityv1.GlobalRule{
				rule(func(r *securityv1.GlobalRule) { r.NamedPort = "grpc" }),
			}

			Expect(k8sClient.Create(ctx, gen)).To(Succeed())
		})
	})

	Context("policy namespace overlap", func() {
		It("rejects a namespace listed as both allowed and denied", func() {
			gen := newGenerator("ns-overlap")
			gen.Spec.Policy.AllowedNamespaces = []string{"ns-a", "shared"}
			gen.Spec.Policy.DeniedNamespaces = []string{"shared", "ns-b"}

			err := k8sClient.Create(ctx, gen)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("cannot be listed in both"))
		})

		It("accepts disjoint allowed and denied namespace lists", func() {
			gen := newGenerator("ns-disjoint")
			gen.Spec.Policy.AllowedNamespaces = []string{"ns-a"}
			gen.Spec.Policy.DeniedNamespaces = []string{"ns-b"}

			Expect(k8sClient.Create(ctx, gen)).To(Succeed())
		})
	})

	Context("update path", func() {
		It("rejects an update that violates a CEL rule", func() {
			gen := newGenerator(fmt.Sprintf("update-guard-%d", time.Now().UnixNano()))
			Expect(k8sClient.Create(ctx, gen)).To(Succeed())

			// The reconciler writes status (and, in learning mode, spec) right after
			// create, so the local copy goes stale. Re-read inside the retry:
			// updating from the stale copy races into a 409 conflict instead of the
			// CEL rejection this spec is asserting.
			Eventually(func(g Gomega) {
				latest := &securityv1.NetworkPolicyGenerator{}
				g.Expect(k8sClient.Get(ctx, client.ObjectKeyFromObject(gen), latest)).To(Succeed())
				latest.Spec.Mode = "learning"
				latest.Spec.Duration = metav1.Duration{}

				err := k8sClient.Update(ctx, latest)
				g.Expect(err).To(HaveOccurred())
				g.Expect(err.Error()).To(ContainSubstring("must be positive when mode is 'learning'"))
			}, time.Second*10, time.Millisecond*250).Should(Succeed())
		})
	})
})
