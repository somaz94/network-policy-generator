package controller

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
	"github.com/somaz94/network-policy-generator/internal/policy"
)

// handleLearningMode drives the learning phase: on the first pass it records
// the start timestamp and requeues; once the configured duration has elapsed
// it builds suggestions and transitions the generator into enforcing mode.
func (r *NetworkPolicyGeneratorReconciler) handleLearningMode(
	ctx context.Context, generator *securityv1.NetworkPolicyGenerator,
) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Initial setup for a freshly created generator.
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

	elapsed := time.Since(generator.Status.LastAnalyzed.Time)
	if elapsed >= generator.Spec.Duration.Duration {
		log.Info("Learning period completed, switching to Enforcing mode",
			"elapsed", elapsed.String(),
			"duration", generator.Spec.Duration.Duration)

		r.buildLearningSuggestions(generator)

		r.Recorder.Eventf(generator, "Normal", "LearningCompleted",
			"Learning period completed after %s, switching to Enforcing mode (suggested %d namespaces, %d rules)",
			elapsed.Round(time.Second),
			len(generator.Status.SuggestedNamespaces),
			len(generator.Status.SuggestedRules))

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

// buildLearningSuggestions analyzes observed traffic and populates
// status.SuggestedNamespaces and status.SuggestedRules for operators to
// inspect before enforcing the generated policies.
func (r *NetworkPolicyGeneratorReconciler) buildLearningSuggestions(
	generator *securityv1.NetworkPolicyGenerator,
) {
	traffic := generator.Status.ObservedTraffic

	nsSet := make(map[string]bool)
	for _, flow := range traffic {
		if flow.SourceNamespace != "" && flow.SourceNamespace != generator.Namespace {
			nsSet[flow.SourceNamespace] = true
		}
		if flow.DestNamespace != "" && flow.DestNamespace != generator.Namespace {
			nsSet[flow.DestNamespace] = true
		}
	}
	var suggestedNS []string
	for ns := range nsSet {
		suggestedNS = append(suggestedNS, ns)
	}
	generator.Status.SuggestedNamespaces = suggestedNS

	type ruleKey struct {
		Port      int32
		Protocol  string
		Direction string
	}
	ruleCounts := make(map[ruleKey]int)
	for _, flow := range traffic {
		if flow.Port > 0 && flow.Protocol != "" {
			if flow.DestNamespace == generator.Namespace {
				key := ruleKey{Port: flow.Port, Protocol: flow.Protocol, Direction: policy.DirectionIngress}
				ruleCounts[key]++
			}
			if flow.SourceNamespace == generator.Namespace {
				key := ruleKey{Port: flow.Port, Protocol: flow.Protocol, Direction: policy.DirectionEgress}
				ruleCounts[key]++
			}
		}
	}

	var suggestedRules []securityv1.SuggestedRule
	for key, count := range ruleCounts {
		suggestedRules = append(suggestedRules, securityv1.SuggestedRule{
			Port:      key.Port,
			Protocol:  key.Protocol,
			Direction: key.Direction,
			Count:     count,
		})
	}
	generator.Status.SuggestedRules = suggestedRules
}
