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
		generator.Status.Phase = policy.PhaseLearning
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
		r.Recorder.Eventf(generator, "Normal", "LearningCompleted",
			"Learning period completed after %s, switching to Enforcing mode", elapsed.Round(time.Second))

		generator.Status.Phase = policy.PhaseEnforcing
		if err := r.Status().Update(ctx, generator); err != nil {
			log.Error(err, "failed to update status to Enforcing")
			return ctrl.Result{}, err
		}

		generator.Spec.Mode = policy.ModeEnforcing
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
		engineType = policy.EngineKubernetes
	}

	switch engineType {
	case policy.EngineKubernetes:
		return r.handleKubernetesEnforcing(ctx, generator)
	case policy.EngineCilium:
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
		r.Recorder.Eventf(generator, "Warning", "GenerationFailed", "Failed to generate NetworkPolicies: %v", err)
		log.Error(err, "failed to generate NetworkPolicies")
		return ctrl.Result{}, err
	}

	// Dry-run mode: store generated policies in status without applying
	if generator.Spec.DryRun {
		r.Recorder.Eventf(generator, "Normal", "DryRun",
			"Dry-run mode: generated %d policies without applying", len(policies))
		return r.handleDryRun(ctx, generator, policies)
	}

	var diffEntries []securityv1.PolicyDiffEntry
	for _, p := range policies {
		action, applyErr := r.applyNetworkPolicyWithDiff(ctx, generator, p)
		if applyErr != nil {
			r.Recorder.Eventf(generator, "Warning", "ApplyFailed",
				"Failed to apply NetworkPolicy %s/%s: %v", p.Namespace, p.Name, applyErr)
			log.Error(applyErr, "failed to apply NetworkPolicy",
				"namespace", p.Namespace,
				"name", p.Name)
			return ctrl.Result{}, applyErr
		}
		r.Recorder.Eventf(generator, "Normal", "Policy"+action,
			"NetworkPolicy %s/%s %s", p.Namespace, p.Name, action)
		diffEntries = append(diffEntries, securityv1.PolicyDiffEntry{
			PolicyName: p.Name,
			Namespace:  p.Namespace,
			Action:     action,
			Timestamp:  metav1.Now(),
		})
	}

	generator.Status.PolicyDiff = diffEntries
	generator.Status.AppliedPoliciesCount = len(policies)

	engineType := generator.Spec.PolicyEngine
	if engineType == "" {
		engineType = policy.EngineKubernetes
	}
	PoliciesApplied.WithLabelValues(generator.Name, generator.Namespace, engineType).Set(float64(len(policies)))

	return r.updateStatusAndRequeue(ctx, generator)
}

// handleCiliumEnforcing handles enforcing with CiliumNetworkPolicy
func (r *NetworkPolicyGeneratorReconciler) handleCiliumEnforcing(ctx context.Context, generator *securityv1.NetworkPolicyGenerator) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	engine := policy.NewCiliumEngine()
	objects, err := engine.GeneratePolicies(generator)
	if err != nil {
		r.Recorder.Eventf(generator, "Warning", "GenerationFailed", "Failed to generate CiliumNetworkPolicies: %v", err)
		log.Error(err, "failed to generate CiliumNetworkPolicies")
		return ctrl.Result{}, err
	}

	// Dry-run mode: store generated policies in status without applying
	if generator.Spec.DryRun {
		return r.handleDryRunObjects(ctx, generator, objects)
	}

	for _, obj := range objects {
		if err := r.applyCiliumPolicy(ctx, generator, obj); err != nil {
			r.Recorder.Eventf(generator, "Warning", "ApplyFailed", "Failed to apply CiliumNetworkPolicy: %v", err)
			log.Error(err, "failed to apply CiliumNetworkPolicy")
			return ctrl.Result{}, err
		}
	}
	r.Recorder.Eventf(generator, "Normal", "PoliciesApplied",
		"Applied %d CiliumNetworkPolicy resources", len(objects))

	generator.Status.AppliedPoliciesCount = len(objects)
	PoliciesApplied.WithLabelValues(generator.Name, generator.Namespace, policy.EngineCilium).Set(float64(len(objects)))

	return r.updateStatusAndRequeue(ctx, generator)
}

// updateStatusAndRequeue updates the generator status and returns a requeue result
func (r *NetworkPolicyGeneratorReconciler) updateStatusAndRequeue(ctx context.Context, generator *securityv1.NetworkPolicyGenerator) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	generator.Status.LastAnalyzed = metav1.Now()
	if err := r.Status().Update(ctx, generator); err != nil {
		log.Error(err, "failed to update generator status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: policy.DefaultRequeueInterval}, nil
}

// ownerReference creates a standard owner reference for the generator
func ownerReference(generator *securityv1.NetworkPolicyGenerator) metav1.OwnerReference {
	return metav1.OwnerReference{
		APIVersion:         securityv1.GroupVersion.String(),
		Kind:               "NetworkPolicyGenerator",
		Name:               generator.Name,
		UID:                generator.UID,
		Controller:         ptr.To(true),
		BlockOwnerDeletion: ptr.To(true),
	}
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
	u.SetOwnerReferences([]metav1.OwnerReference{ownerReference(generator)})

	return r.createOrUpdate(ctx, u)
}

// createOrUpdate handles the get-then-create-or-update pattern for unstructured objects
func (r *NetworkPolicyGeneratorReconciler) createOrUpdate(ctx context.Context, u *unstructured.Unstructured) error {
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(u.GroupVersionKind())
	err := r.Get(ctx, client.ObjectKey{
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

func ciliumGVK() schema.GroupVersionKind {
	return schema.GroupVersionKind{
		Group:   policy.CiliumGroup,
		Version: policy.CiliumVersion,
		Kind:    policy.CiliumKind,
	}
}

// handleDryRun stores generated Kubernetes NetworkPolicies in status without applying
func (r *NetworkPolicyGeneratorReconciler) handleDryRun(ctx context.Context, generator *securityv1.NetworkPolicyGenerator, policies []*networkingv1.NetworkPolicy) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.Info("Dry-run mode: generating policies without applying", "count", len(policies))
	DryRunTotal.Inc()

	var policyYAMLs []string
	for _, p := range policies {
		data, err := json.Marshal(p)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to marshal policy %s: %w", p.Name, err)
		}
		policyYAMLs = append(policyYAMLs, string(data))
	}

	generator.Status.GeneratedPolicies = policyYAMLs
	generator.Status.AppliedPoliciesCount = 0
	generator.Status.PolicyDiff = nil

	return r.updateStatusAndRequeue(ctx, generator)
}

// handleDryRunObjects stores generated runtime.Objects in status without applying
func (r *NetworkPolicyGeneratorReconciler) handleDryRunObjects(ctx context.Context, generator *securityv1.NetworkPolicyGenerator, objects []runtime.Object) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.Info("Dry-run mode: generating Cilium policies without applying", "count", len(objects))
	DryRunTotal.Inc()

	var policyYAMLs []string
	for _, obj := range objects {
		data, err := json.Marshal(obj)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to marshal Cilium policy: %w", err)
		}
		policyYAMLs = append(policyYAMLs, string(data))
	}

	generator.Status.GeneratedPolicies = policyYAMLs
	generator.Status.AppliedPoliciesCount = 0
	generator.Status.PolicyDiff = nil

	return r.updateStatusAndRequeue(ctx, generator)
}

// applyNetworkPolicyWithDiff creates or updates a NetworkPolicy and returns the action taken
func (r *NetworkPolicyGeneratorReconciler) applyNetworkPolicyWithDiff(ctx context.Context, generator *securityv1.NetworkPolicyGenerator, np *networkingv1.NetworkPolicy) (string, error) {
	np.OwnerReferences = []metav1.OwnerReference{ownerReference(generator)}

	existing := &networkingv1.NetworkPolicy{}
	err := r.Get(ctx, client.ObjectKey{Name: np.Name, Namespace: np.Namespace}, existing)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return "", err
		}
		if err := r.Create(ctx, np); err != nil {
			return "", err
		}
		PolicyOperations.WithLabelValues(policy.DiffActionCreated).Inc()
		return policy.DiffActionCreated, nil
	}

	np.ResourceVersion = existing.ResourceVersion
	if err := r.Update(ctx, np); err != nil {
		return "", err
	}
	PolicyOperations.WithLabelValues(policy.DiffActionUpdated).Inc()
	return policy.DiffActionUpdated, nil
}
