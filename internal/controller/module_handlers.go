package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// handleLearningMode handles the learning mode logic
func (r *NetworkPolicyGeneratorReconciler) handleLearningMode(ctx context.Context, generator *securityv1.NetworkPolicyGenerator) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Learning mode initial setup (only once)
	if generator.Status.Phase == "" || generator.Status.LastAnalyzed.IsZero() {
		generator.Status.Phase = "Learning"
		generator.Status.LastAnalyzed = metav1.Now()
		if err := r.Status().Update(ctx, generator); err != nil {
			log.Error(err, "failed to update status")
			return ctrl.Result{}, err
		}
		log.Info("Initial Learning mode setup",
			"phase", generator.Status.Phase,
			"lastAnalyzed", generator.Status.LastAnalyzed.Format(time.RFC3339),
			"duration", generator.Spec.Duration.Duration)
		return ctrl.Result{RequeueAfter: generator.Spec.Duration.Duration}, nil
	}

	// Check if learning period has elapsed
	elapsed := time.Since(generator.Status.LastAnalyzed.Time)
	if elapsed >= generator.Spec.Duration.Duration {
		log.Info("Learning period completed, switching to Enforcing mode",
			"elapsed", elapsed.String(),
			"duration", generator.Spec.Duration.Duration)

		generator.Status.Phase = "Enforcing"
		if err := r.Status().Update(ctx, generator); err != nil {
			log.Error(err, "failed to update status to Enforcing")
			return ctrl.Result{}, err
		}

		generator.Spec.Mode = "enforcing"
		if err := r.Update(ctx, generator); err != nil {
			log.Error(err, "failed to update spec to Enforcing")
			return ctrl.Result{}, err
		}

		return ctrl.Result{Requeue: true}, nil
	}

	return ctrl.Result{RequeueAfter: generator.Spec.Duration.Duration - elapsed}, nil
}

// handleEnforcingMode handles the enforcing mode logic
func (r *NetworkPolicyGeneratorReconciler) handleEnforcingMode(ctx context.Context, generator *securityv1.NetworkPolicyGenerator) (ctrl.Result, error) {
	engineType := generator.Spec.PolicyEngine
	if engineType == "" {
		engineType = "kubernetes"
	}

	switch engineType {
	case "kubernetes":
		return r.handleKubernetesEnforcing(ctx, generator)
	case "cilium":
		return r.handleCiliumEnforcing(ctx, generator)
	default:
		return ctrl.Result{}, fmt.Errorf("unsupported policy engine: %s", engineType)
	}
}

// handleKubernetesEnforcing handles enforcing with standard Kubernetes NetworkPolicy
func (r *NetworkPolicyGeneratorReconciler) handleKubernetesEnforcing(ctx context.Context, generator *securityv1.NetworkPolicyGenerator) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	policies, err := r.Generator.GenerateNetworkPolicies(generator)
	if err != nil {
		log.Error(err, "failed to generate NetworkPolicies")
		return ctrl.Result{}, err
	}

	for _, p := range policies {
		if err := r.applyNetworkPolicy(ctx, generator, p); err != nil {
			log.Error(err, "failed to apply NetworkPolicy",
				"namespace", p.Namespace,
				"name", p.Name)
			return ctrl.Result{}, err
		}
	}

	generator.Status.LastAnalyzed = metav1.Now()
	if err := r.Status().Update(ctx, generator); err != nil {
		log.Error(err, "failed to update generator status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: time.Minute * 5}, nil
}

// handleCiliumEnforcing handles enforcing with CiliumNetworkPolicy
func (r *NetworkPolicyGeneratorReconciler) handleCiliumEnforcing(ctx context.Context, generator *securityv1.NetworkPolicyGenerator) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	engine := policy.NewCiliumEngine()
	objects, err := engine.GeneratePolicies(generator)
	if err != nil {
		log.Error(err, "failed to generate CiliumNetworkPolicies")
		return ctrl.Result{}, err
	}

	for _, obj := range objects {
		if err := r.applyCiliumPolicy(ctx, generator, obj); err != nil {
			log.Error(err, "failed to apply CiliumNetworkPolicy")
			return ctrl.Result{}, err
		}
	}

	generator.Status.LastAnalyzed = metav1.Now()
	if err := r.Status().Update(ctx, generator); err != nil {
		log.Error(err, "failed to update generator status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: time.Minute * 5}, nil
}

// applyCiliumPolicy creates or updates a CiliumNetworkPolicy using unstructured client
func (r *NetworkPolicyGeneratorReconciler) applyCiliumPolicy(ctx context.Context, generator *securityv1.NetworkPolicyGenerator, obj runtime.Object) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("failed to marshal CiliumNetworkPolicy: %w", err)
	}

	u := &unstructured.Unstructured{}
	if err := json.Unmarshal(data, &u.Object); err != nil {
		return fmt.Errorf("failed to unmarshal to unstructured: %w", err)
	}

	u.SetGroupVersionKind(ciliumGVK())

	// Set owner reference
	u.SetOwnerReferences([]metav1.OwnerReference{{
		APIVersion:         securityv1.GroupVersion.String(),
		Kind:               "NetworkPolicyGenerator",
		Name:               generator.Name,
		UID:                generator.UID,
		Controller:         ptr.To(true),
		BlockOwnerDeletion: ptr.To(true),
	}})

	// Try to get existing
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(ciliumGVK())
	err = r.Get(ctx, client.ObjectKey{
		Name:      u.GetName(),
		Namespace: u.GetNamespace(),
	}, existing)

	if err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		return r.Create(ctx, u)
	}

	u.SetResourceVersion(existing.GetResourceVersion())
	return r.Update(ctx, u)
}

// applyNetworkPolicy creates or updates a NetworkPolicy
func (r *NetworkPolicyGeneratorReconciler) applyNetworkPolicy(ctx context.Context, generator *securityv1.NetworkPolicyGenerator, np *networkingv1.NetworkPolicy) error {
	np.OwnerReferences = []metav1.OwnerReference{{
		APIVersion:         securityv1.GroupVersion.String(),
		Kind:               "NetworkPolicyGenerator",
		Name:               generator.Name,
		UID:                generator.UID,
		Controller:         ptr.To(true),
		BlockOwnerDeletion: ptr.To(true),
	}}

	existing := &networkingv1.NetworkPolicy{}
	err := r.Get(ctx, client.ObjectKey{Name: np.Name, Namespace: np.Namespace}, existing)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return err
		}
		return r.Create(ctx, np)
	}

	np.ResourceVersion = existing.ResourceVersion
	return r.Update(ctx, np)
}

func ciliumGVK() schema.GroupVersionKind {
	return schema.GroupVersionKind{
		Group:   "cilium.io",
		Version: "v2",
		Kind:    "CiliumNetworkPolicy",
	}
}
