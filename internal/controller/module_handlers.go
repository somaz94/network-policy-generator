package controller

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// handleLearningMode handles the learning mode logic
func (r *NetworkPolicyGeneratorReconciler) handleLearningMode(ctx context.Context, generator *securityv1.NetworkPolicyGenerator) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Learning 모드 초기 설정 (처음 한번만)
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

	// 학습 기간이 지났는지 확인
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

	// Learning 모드 중에는 LastAnalyzed를 업데이트하지 않음
	log.Info("Still in Learning mode",
		"phase", generator.Status.Phase,
		"lastAnalyzed", generator.Status.LastAnalyzed.Format(time.RFC3339),
		"elapsed", elapsed.String(),
		"remaining", (generator.Spec.Duration.Duration - elapsed).String())

	// 남은 학습 시간만큼 대기
	remainingTime := generator.Spec.Duration.Duration - elapsed
	return ctrl.Result{RequeueAfter: remainingTime}, nil
}

// handleEnforcingMode handles the enforcing mode logic
func (r *NetworkPolicyGeneratorReconciler) handleEnforcingMode(ctx context.Context, generator *securityv1.NetworkPolicyGenerator) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Log current status
	log.Info("Operating in Enforcing mode",
		"phase", generator.Status.Phase,
		"lastAnalyzed", generator.Status.LastAnalyzed.Format(time.RFC3339))

	// Generate NetworkPolicies using the policy generator
	policies, err := r.Generator.GenerateNetworkPolicies(generator)
	if err != nil {
		log.Error(err, "failed to generate NetworkPolicies")
		return ctrl.Result{}, err
	}

	// Track existing policies to avoid deletion
	existingPolicies := make(map[string]bool)

	// Create or update each NetworkPolicy
	for _, policy := range policies {
		// Track this policy
		policyKey := fmt.Sprintf("%s/%s", policy.Namespace, policy.Name)
		existingPolicies[policyKey] = true

		// 기존 정책 확인
		existing := &networkingv1.NetworkPolicy{}
		err = r.Get(ctx, client.ObjectKey{
			Name:      policy.Name,
			Namespace: policy.Namespace,
		}, existing)

		// OwnerReferences 설정
		policy.OwnerReferences = []metav1.OwnerReference{
			{
				APIVersion:         securityv1.GroupVersion.String(),
				Kind:               "NetworkPolicyGenerator",
				Name:               generator.Name,
				UID:                generator.UID,
				Controller:         pointer.Bool(true),
				BlockOwnerDeletion: pointer.Bool(true),
			},
		}

		if err != nil {
			if !apierrors.IsNotFound(err) {
				log.Error(err, "failed to get NetworkPolicy")
				return ctrl.Result{}, err
			}
			// 정책이 없는 경우에만 새로 생성
			if err := r.Create(ctx, policy); err != nil {
				log.Error(err, "failed to create NetworkPolicy")
				return ctrl.Result{}, err
			}
			log.Info("Created new NetworkPolicy",
				"name", policy.Name,
				"namespace", policy.Namespace)
		} else {
			// 기존 정책이 있는 경우 업데이트
			policy.ResourceVersion = existing.ResourceVersion
			if err := r.Update(ctx, policy); err != nil {
				log.Error(err, "failed to update NetworkPolicy")
				return ctrl.Result{}, err
			}
			log.Info("Updated existing NetworkPolicy",
				"name", policy.Name,
				"namespace", policy.Namespace)
		}
	}

	// 상태 업데이트
	generator.Status.LastAnalyzed = metav1.Now()
	if err := r.Status().Update(ctx, generator); err != nil {
		log.Error(err, "failed to update generator status")
		return ctrl.Result{}, err
	}

	return ctrl.Result{
		RequeueAfter: time.Minute * 5,
	}, nil
}
