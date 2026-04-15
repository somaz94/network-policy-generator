package controller

import (
	"context"
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
	"github.com/somaz94/network-policy-generator/internal/policy"
)

// handleEnforcingMode resolves the policy engine from the spec and delegates
// to the generic enforcing handler. Templates are applied first so that any
// engine sees the merged spec.
func (r *NetworkPolicyGeneratorReconciler) handleEnforcingMode(
	ctx context.Context, generator *securityv1.NetworkPolicyGenerator,
) (ctrl.Result, error) {
	if generator.Spec.TemplateName != "" {
		if tmpl := policy.GetTemplate(generator.Spec.TemplateName); tmpl != nil {
			tmpl.Apply(&generator.Spec)
		}
	}

	engineType := generator.Spec.PolicyEngine
	if engineType == "" {
		engineType = policy.EngineKubernetes
	}

	engine, err := policy.NewPolicyEngine(engineType)
	if err != nil {
		return ctrl.Result{}, err
	}

	return r.handleEnforcing(ctx, generator, engine)
}

// handleEnforcing is the single code path that applies policies for any
// PolicyEngine backend. It records a PolicyDiff entry, a per-policy Kubernetes
// event and increments the PolicyOperations metric for every applied object,
// regardless of which engine produced it.
func (r *NetworkPolicyGeneratorReconciler) handleEnforcing(
	ctx context.Context,
	generator *securityv1.NetworkPolicyGenerator,
	engine policy.PolicyEngine,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	objects, err := engine.GeneratePolicies(generator)
	if err != nil {
		r.Recorder.Eventf(generator, "Warning", "GenerationFailed",
			"Failed to generate %s policies: %v", engine.EngineName(), err)
		log.Error(err, "failed to generate policies", "engine", engine.EngineName())
		return ctrl.Result{}, err
	}

	if generator.Spec.DryRun {
		r.Recorder.Eventf(generator, "Normal", "DryRun",
			"Dry-run mode: generated %d %s policies without applying",
			len(objects), engine.EngineName())
		return r.handleDryRun(ctx, generator, objects)
	}

	var diff []securityv1.PolicyDiffEntry
	for _, obj := range objects {
		accessor, accErr := meta.Accessor(obj)
		if accErr != nil {
			return ctrl.Result{}, fmt.Errorf("failed to access object metadata: %w", accErr)
		}

		action, applyErr := r.applyPolicyWithDiff(ctx, generator, obj, engine.EngineName())
		if applyErr != nil {
			r.Recorder.Eventf(generator, "Warning", "ApplyFailed",
				"Failed to apply %s policy %s/%s: %v",
				engine.EngineName(), accessor.GetNamespace(), accessor.GetName(), applyErr)
			log.Error(applyErr, "failed to apply policy",
				"engine", engine.EngineName(),
				"namespace", accessor.GetNamespace(),
				"name", accessor.GetName())
			return ctrl.Result{}, applyErr
		}

		r.Recorder.Eventf(generator, "Normal", "Policy"+action,
			"%s policy %s/%s %s",
			engine.EngineName(), accessor.GetNamespace(), accessor.GetName(), action)

		diff = append(diff, securityv1.PolicyDiffEntry{
			PolicyName: accessor.GetName(),
			Namespace:  accessor.GetNamespace(),
			Action:     action,
			Timestamp:  metav1.Now(),
		})
	}

	generator.Status.PolicyDiff = diff
	generator.Status.AppliedPoliciesCount = len(objects)
	PoliciesApplied.WithLabelValues(generator.Name, generator.Namespace, engine.EngineName()).
		Set(float64(len(objects)))

	return r.updateStatusAndRequeue(ctx, generator)
}

// handleDryRun serializes generated policies into status.GeneratedPolicies
// without touching the API server.
func (r *NetworkPolicyGeneratorReconciler) handleDryRun(
	ctx context.Context,
	generator *securityv1.NetworkPolicyGenerator,
	objects []runtime.Object,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.Info("Dry-run mode: generating policies without applying", "count", len(objects))
	DryRunTotal.Inc()

	yamls := make([]string, 0, len(objects))
	for _, obj := range objects {
		data, err := json.Marshal(obj)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to marshal policy: %w", err)
		}
		yamls = append(yamls, string(data))
	}

	generator.Status.GeneratedPolicies = yamls
	generator.Status.AppliedPoliciesCount = 0
	generator.Status.PolicyDiff = nil

	return r.updateStatusAndRequeue(ctx, generator)
}
