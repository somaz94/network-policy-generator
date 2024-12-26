package controller

import (
	"context"
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	securityv1 "github.com/somaz94/network-policy-generator/api/v1"
	"github.com/somaz94/network-policy-generator/internal/policy"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// NetworkPolicyGeneratorReconciler reconciles a NetworkPolicyGenerator object
type NetworkPolicyGeneratorReconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Generator *policy.Generator
	Validator *policy.Validator
}

// NewReconciler creates a new NetworkPolicyGeneratorReconciler
func NewReconciler(client client.Client, scheme *runtime.Scheme) *NetworkPolicyGeneratorReconciler {
	return &NetworkPolicyGeneratorReconciler{
		Client:    client,
		Scheme:    scheme,
		Generator: policy.NewGenerator(),
		Validator: policy.NewValidator(),
	}
}

// +kubebuilder:rbac:groups=security.policy.io,resources=networkpolicygenerators,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.policy.io,resources=networkpolicygenerators/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.policy.io,resources=networkpolicygenerators/finalizers,verbs=update
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch

const (
	finalizerName = "security.policy.io/finalizer"
)

func (r *NetworkPolicyGeneratorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	generator := &securityv1.NetworkPolicyGenerator{}

	if err := r.Get(ctx, req.NamespacedName, generator); err != nil {
		if apierrors.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !generator.ObjectMeta.DeletionTimestamp.IsZero() {
		if containsString(generator.ObjectMeta.Finalizers, finalizerName) {
			if err := r.deleteNetworkPolicies(ctx, generator); err != nil {
				return ctrl.Result{}, err
			}
			generator.ObjectMeta.Finalizers = removeString(generator.ObjectMeta.Finalizers, finalizerName)
			if err := r.Update(ctx, generator); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Add finalizer if it doesn't exist
	if !containsString(generator.ObjectMeta.Finalizers, finalizerName) {
		generator.ObjectMeta.Finalizers = append(generator.ObjectMeta.Finalizers, finalizerName)
		if err := r.Update(ctx, generator); err != nil {
			return ctrl.Result{}, err
		}
	}

	switch generator.Spec.Mode {
	case "learning":
		return r.handleLearningMode(ctx, generator)
	case "enforcing":
		return r.handleEnforcingMode(ctx, generator)
	default:
		log.Info("Invalid mode specified", "mode", generator.Spec.Mode)
		return ctrl.Result{}, fmt.Errorf("invalid mode: %s", generator.Spec.Mode)
	}
}

// deleteNetworkPolicies deletes all NetworkPolicies created by this generator
func (r *NetworkPolicyGeneratorReconciler) deleteNetworkPolicies(ctx context.Context, generator *securityv1.NetworkPolicyGenerator) error {
	log := log.FromContext(ctx)

	// Get list of namespaces to clean up
	var namespacesToClean []string

	if generator.Spec.DefaultPolicy.Type == securityv1.PolicyAllow {
		// For allow policy, clean up denied namespaces
		namespacesToClean = generator.Spec.DeniedNamespaces
	} else {
		// For deny policy, clean up the generator's namespace
		namespacesToClean = []string{generator.Namespace}
	}

	// Delete NetworkPolicy in each namespace
	for _, ns := range namespacesToClean {
		policy := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      generator.Name + "-generated",
				Namespace: ns,
			},
		}

		if err := r.Delete(ctx, policy); err != nil {
			if !apierrors.IsNotFound(err) {
				log.Error(err, "failed to delete NetworkPolicy",
					"namespace", ns,
					"name", policy.Name)
				return err
			}
		}

		log.Info("Successfully deleted NetworkPolicy",
			"namespace", ns,
			"name", policy.Name)
	}

	return nil
}

// Helper functions
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func removeString(slice []string, s string) []string {
	var result []string
	for _, item := range slice {
		if item != s {
			result = append(result, item)
		}
	}
	return result
}

// SetupWithManager sets up the controller with the Manager
func (r *NetworkPolicyGeneratorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1.NetworkPolicyGenerator{}).
		Complete(r)
}
