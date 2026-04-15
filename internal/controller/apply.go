package controller

import (
	"context"
	"encoding/json"
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
	"github.com/somaz94/network-policy-generator/internal/policy"
)

// ownerReference creates a standard owner reference for the generator.
func ownerReference(g *securityv1.NetworkPolicyGenerator) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion:         securityv1.GroupVersion.String(),
		Kind:               "NetworkPolicyGenerator",
		Name:               g.Name,
		UID:                g.UID,
		Controller:         ptr.To(true),
		BlockOwnerDeletion: ptr.To(true),
	}
}

// gvkForEngine maps a policy engine name to its target GroupVersionKind.
func gvkForEngine(engineName string) schema.GroupVersionKind {
	switch engineName {
	case policy.EngineCilium:
		return schema.GroupVersionKind{
			Group:   policy.CiliumGroup,
			Version: policy.CiliumVersion,
			Kind:    policy.CiliumKind,
		}
	case policy.EngineCalico:
		return schema.GroupVersionKind{
			Group:   policy.CalicoGroup,
			Version: policy.CalicoVersion,
			Kind:    policy.CalicoKind,
		}
	default:
		return networkingv1.SchemeGroupVersion.WithKind("NetworkPolicy")
	}
}

// toUnstructured converts a runtime.Object into an *unstructured.Unstructured
// and forces the provided GVK, so typed objects without explicit TypeMeta still
// carry the correct apiVersion/kind before being sent to the API server.
func toUnstructured(obj runtime.Object, gvk schema.GroupVersionKind) (*unstructured.Unstructured, error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal object: %w", err)
	}
	u := &unstructured.Unstructured{}
	if err := json.Unmarshal(data, &u.Object); err != nil {
		return nil, fmt.Errorf("failed to unmarshal to unstructured: %w", err)
	}
	u.SetGroupVersionKind(gvk)
	return u, nil
}

// applyPolicyWithDiff creates or updates a policy object for any supported
// engine, returning the action performed ("Created" / "Updated").
func (r *NetworkPolicyGeneratorReconciler) applyPolicyWithDiff(
	ctx context.Context,
	g *securityv1.NetworkPolicyGenerator,
	obj runtime.Object,
	engineName string,
) (string, error) {
	u, err := toUnstructured(obj, gvkForEngine(engineName))
	if err != nil {
		return "", err
	}
	u.SetOwnerReferences([]metav1.OwnerReference{ownerReference(g)})

	action, err := r.createOrUpdateWithAction(ctx, u)
	if err != nil {
		return "", err
	}
	PolicyOperations.WithLabelValues(action).Inc()
	return action, nil
}

// createOrUpdateWithAction issues a Create or Update against the API server
// and reports which action it took.
func (r *NetworkPolicyGeneratorReconciler) createOrUpdateWithAction(
	ctx context.Context, u *unstructured.Unstructured,
) (string, error) {
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(u.GroupVersionKind())
	err := r.Get(ctx, client.ObjectKey{
		Name:      u.GetName(),
		Namespace: u.GetNamespace(),
	}, existing)

	if err != nil {
		if !apierrors.IsNotFound(err) {
			return "", err
		}
		if err := r.Create(ctx, u); err != nil {
			return "", err
		}
		return policy.DiffActionCreated, nil
	}

	u.SetResourceVersion(existing.GetResourceVersion())
	if err := r.Update(ctx, u); err != nil {
		return "", err
	}
	return policy.DiffActionUpdated, nil
}

// updateStatusAndRequeue stamps LastAnalyzed, persists status and returns a
// standard requeue result.
func (r *NetworkPolicyGeneratorReconciler) updateStatusAndRequeue(
	ctx context.Context, g *securityv1.NetworkPolicyGenerator,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	g.Status.LastAnalyzed = metav1.Now()
	if err := r.Status().Update(ctx, g); err != nil {
		log.Error(err, "failed to update generator status")
		return ctrl.Result{}, err
	}
	return ctrl.Result{RequeueAfter: policy.DefaultRequeueInterval}, nil
}
