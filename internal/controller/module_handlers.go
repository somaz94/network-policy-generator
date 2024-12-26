package controller

import (
	"context"
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

	// Initialize status if not set
	if generator.Status.Phase != "Learning" {
		generator.Status.Phase = "Learning"
		if err := r.Status().Update(ctx, generator); err != nil {
			log.Error(err, "failed to update status")
			return ctrl.Result{}, err
		}
	}

	if generator.Status.LastAnalyzed.IsZero() {
		generator.Status.LastAnalyzed = metav1.Now()
		if err := r.Status().Update(ctx, generator); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Generate and apply NetworkPolicy even in learning mode
	policy, err := r.Generator.GenerateNetworkPolicy(generator)
	if err != nil {
		log.Error(err, "failed to generate NetworkPolicy")
		return ctrl.Result{}, err
	}

	networkPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generator.Name + "-generated",
			Namespace: generator.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: securityv1.GroupVersion.String(),
					Kind:       "NetworkPolicyGenerator",
					Name:       generator.Name,
					UID:        generator.UID,
					Controller: pointer.Bool(true),
				},
			},
		},
		Spec: policy.Spec,
	}

	// Create or update NetworkPolicy
	if err := r.Create(ctx, networkPolicy); err != nil {
		if apierrors.IsAlreadyExists(err) {
			if err := r.Update(ctx, networkPolicy); err != nil {
				log.Error(err, "failed to update NetworkPolicy")
				return ctrl.Result{}, err
			}
		} else {
			log.Error(err, "failed to create NetworkPolicy")
			return ctrl.Result{}, err
		}
	}

	elapsed := time.Since(generator.Status.LastAnalyzed.Time)
	if elapsed >= generator.Spec.Duration.Duration {
		log.Info("Learning period completed")

		// Get the latest version of the resource
		latest := &securityv1.NetworkPolicyGenerator{}
		if err := r.Get(ctx, client.ObjectKey{
			Name:      generator.Name,
			Namespace: generator.Namespace,
		}, latest); err != nil {
			return ctrl.Result{}, err
		}

		// Update status to Enforcing using the latest version
		latest.Status.Phase = "Enforcing"
		if err := r.Status().Update(ctx, latest); err != nil {
			log.Error(err, "failed to update status to Enforcing")
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}

	return ctrl.Result{
		RequeueAfter: time.Second,
	}, nil
}

// handleEnforcingMode handles the enforcing mode logic
func (r *NetworkPolicyGeneratorReconciler) handleEnforcingMode(ctx context.Context, generator *securityv1.NetworkPolicyGenerator) (ctrl.Result, error) {
	log := log.FromContext(ctx)

	// Generate NetworkPolicy using the policy generator
	policy, err := r.Generator.GenerateNetworkPolicy(generator)
	if err != nil {
		log.Error(err, "failed to generate NetworkPolicy")
		return ctrl.Result{}, err
	}

	networkPolicy := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      generator.Name + "-generated",
			Namespace: generator.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: securityv1.GroupVersion.String(),
					Kind:       "NetworkPolicyGenerator",
					Name:       generator.Name,
					UID:        generator.UID,
					Controller: pointer.Bool(true),
				},
			},
		},
		Spec: policy.Spec,
	}

	// Create or update NetworkPolicy
	if err := r.Create(ctx, networkPolicy); err != nil {
		if apierrors.IsAlreadyExists(err) {
			if err := r.Update(ctx, networkPolicy); err != nil {
				log.Error(err, "failed to update NetworkPolicy")
				return ctrl.Result{}, err
			}
		} else {
			log.Error(err, "failed to create NetworkPolicy")
			return ctrl.Result{}, err
		}
	}

	log.Info("Successfully reconciled NetworkPolicy",
		"name", networkPolicy.Name,
		"namespace", networkPolicy.Namespace)

	return ctrl.Result{}, nil
}
