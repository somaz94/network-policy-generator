package controller

import (
	"context"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
	"github.com/somaz94/network-policy-generator/internal/policy"
)

const (
	testUID  = "uid-1"
	specPort = "port"
)

func testGenerator(ns string) *securityv1.NetworkPolicyGenerator {
	return &securityv1.NetworkPolicyGenerator{
		ObjectMeta: metav1.ObjectMeta{Name: "gen", Namespace: ns, UID: types.UID(testUID)},
	}
}

func TestStampOwnershipSameNamespace(t *testing.T) {
	u := &unstructured.Unstructured{}
	u.SetNamespace("shop")
	stampOwnership(u, testGenerator("shop"))

	if refs := u.GetOwnerReferences(); len(refs) != 1 || refs[0].UID != testUID {
		t.Errorf("ownerReferences = %+v, want one pointing at the generator", refs)
	}
	if got := u.GetLabels()[policy.LabelGeneratorUID]; got != testUID {
		t.Errorf("uid label = %q, want uid-1", got)
	}
	if got := u.GetLabels()[policy.LabelManagedBy]; got != policy.ManagedByValue {
		t.Errorf("managed-by label = %q", got)
	}
	if got := u.GetAnnotations()[policy.AnnotationGenerator]; got != "shop/gen" {
		t.Errorf("generator annotation = %q, want shop/gen", got)
	}
}

func TestStampOwnershipOtherNamespaceHasNoOwnerReference(t *testing.T) {
	u := &unstructured.Unstructured{}
	u.SetNamespace("other")
	u.SetOwnerReferences([]metav1.OwnerReference{{Name: "stale"}})
	stampOwnership(u, testGenerator("shop"))

	if refs := u.GetOwnerReferences(); len(refs) != 0 {
		t.Errorf("ownerReferences = %+v, want none across namespaces", refs)
	}
	if got := u.GetLabels()[policy.LabelGeneratorUID]; got != testUID {
		t.Errorf("uid label = %q, want uid-1", got)
	}
}

func TestGeneratorForPolicy(t *testing.T) {
	np := &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{
		Annotations: map[string]string{policy.AnnotationGenerator: "shop/gen"},
	}}
	got := generatorForPolicy(context.Background(), np)
	if len(got) != 1 || got[0].Namespace != "shop" || got[0].Name != "gen" {
		t.Errorf("generatorForPolicy() = %+v, want shop/gen", got)
	}

	for _, ann := range []string{"", "no-slash", "/gen", "shop/"} {
		np.Annotations[policy.AnnotationGenerator] = ann
		if got := generatorForPolicy(context.Background(), np); got != nil {
			t.Errorf("generatorForPolicy(%q) = %+v, want nil", ann, got)
		}
	}
}

func TestSameManagedContent(t *testing.T) {
	existing := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{"labels": map[string]interface{}{"a": "1", "extra": "x"}},
		"spec":     map[string]interface{}{specPort: int64(80)},
	}}
	desired := &unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{"labels": map[string]interface{}{"a": "1"}},
		"spec":     map[string]interface{}{specPort: float64(80)},
	}}
	if !sameManagedContent(existing, desired) {
		t.Error("int64 and float64 80 with a superset of labels should match")
	}

	desired.SetLabels(map[string]string{"a": "2"})
	if sameManagedContent(existing, desired) {
		t.Error("a changed label must not match")
	}

	desired.SetLabels(map[string]string{"a": "1"})
	desired.Object["spec"] = map[string]interface{}{specPort: float64(443)}
	if sameManagedContent(existing, desired) {
		t.Error("a changed spec must not match")
	}
}

var _ = Describe("Generated policy ownership", func() {
	var (
		ctx        context.Context
		home       string
		denied     []string
		reconciler *NetworkPolicyGeneratorReconciler
		key        types.NamespacedName
	)

	reconcileOnce := func() {
		_, err := reconciler.Reconcile(ctx, reconcile.Request{NamespacedName: key})
		Expect(err).NotTo(HaveOccurred())
	}
	getPolicy := func(ns string) (*networkingv1.NetworkPolicy, error) {
		np := &networkingv1.NetworkPolicy{}
		err := k8sClient.Get(ctx, types.NamespacedName{Name: policy.PolicyName("owner-gen"), Namespace: ns}, np)
		return np, err
	}

	BeforeEach(func() {
		ctx = context.Background()
		var err error
		home, err = setupTestNamespace(ctx, k8sClient)
		Expect(err).NotTo(HaveOccurred())
		suffix := time.Now().UnixNano()
		denied = []string{fmt.Sprintf("denied-a-%d", suffix), fmt.Sprintf("denied-b-%d", suffix)}
		for _, ns := range denied {
			Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})).To(Succeed())
		}

		reconciler = &NetworkPolicyGeneratorReconciler{
			Client:    k8sClient,
			Scheme:    k8sClient.Scheme(),
			Generator: policy.NewGenerator(),
			Validator: policy.NewValidator(),
			Recorder:  record.NewFakeRecorder(100),
		}
		key = types.NamespacedName{Name: "owner-gen", Namespace: home}
		Expect(k8sClient.Create(ctx, &securityv1.NetworkPolicyGenerator{
			ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: home},
			Spec: securityv1.NetworkPolicyGeneratorSpec{
				Mode:   policy.ModeEnforcing,
				Policy: securityv1.PolicyConfig{Type: policy.PolicyTypeAllow, DeniedNamespaces: denied},
			},
		})).To(Succeed())
	})

	It("labels cross-namespace policies, prunes stale ones and cleans up on delete", func() {
		reconcileOnce() // adds the finalizer
		reconcileOnce()

		gen := &securityv1.NetworkPolicyGenerator{}
		Expect(k8sClient.Get(ctx, key, gen)).To(Succeed())
		for _, ns := range denied {
			np, err := getPolicy(ns)
			Expect(err).NotTo(HaveOccurred())
			Expect(np.OwnerReferences).To(BeEmpty(), "a cross-namespace ownerReference gets garbage collected")
			Expect(np.Labels).To(HaveKeyWithValue(policy.LabelGeneratorUID, string(gen.UID)))
			Expect(np.Annotations).To(HaveKeyWithValue(policy.AnnotationGenerator, home+"/owner-gen"))
		}

		By("reconciling again without a spec change")
		reconcileOnce()
		Expect(k8sClient.Get(ctx, key, gen)).To(Succeed())
		for _, entry := range gen.Status.PolicyDiff {
			Expect(entry.Action).To(Equal(policy.DiffActionUnchanged))
		}

		By("dropping one denied namespace")
		gen.Spec.Policy.DeniedNamespaces = denied[:1]
		Expect(k8sClient.Update(ctx, gen)).To(Succeed())
		reconcileOnce()
		_, err := getPolicy(denied[1])
		Expect(apierrors.IsNotFound(err)).To(BeTrue(), "the policy for the dropped namespace must be pruned")
		_, err = getPolicy(denied[0])
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Get(ctx, key, gen)).To(Succeed())
		Expect(gen.Status.PolicyDiff).To(ContainElement(HaveField("Action", policy.DiffActionDeleted)))

		By("deleting the generator")
		Expect(k8sClient.Delete(ctx, gen)).To(Succeed())
		reconcileOnce()
		_, err = getPolicy(denied[0])
		Expect(apierrors.IsNotFound(err)).To(BeTrue(), "the finalizer must remove the remaining policy")
	})
})
