package controller

import (
	"context"
	"fmt"
	"time"

	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
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
	Recorder  record.EventRecorder
}

// NewReconciler creates a new NetworkPolicyGeneratorReconciler
func NewReconciler(c client.Client, scheme *runtime.Scheme, recorder record.EventRecorder) *NetworkPolicyGeneratorReconciler {
	return &NetworkPolicyGeneratorReconciler{
		Client:    c,
		Scheme:    scheme,
		Generator: policy.NewGenerator(),
		Validator: policy.NewValidator(),
		Recorder:  recorder,
	}
}

// +kubebuilder:rbac:groups=security.policy.io,resources=networkpolicygenerators,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.policy.io,resources=networkpolicygenerators/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.policy.io,resources=networkpolicygenerators/finalizers,verbs=update
// +kubebuilder:rbac:groups=networking.k8s.io,resources=networkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=cilium.io,resources=ciliumnetworkpolicies,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

const (
	finalizerName = "security.policy.io/finalizer"
)

func (r *NetworkPolicyGeneratorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.Info("Starting reconciliation", "namespacedName", req.NamespacedName)
	startTime := time.Now()

	generator := &securityv1.NetworkPolicyGenerator{}
	if err := r.Get(ctx, req.NamespacedName, generator); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Error(err, "failed to get NetworkPolicyGenerator")
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Sync phase from mode
	if err := r.syncPhase(ctx, generator); err != nil {
		return ctrl.Result{}, err
	}

	// Handle deletion
	if !generator.ObjectMeta.DeletionTimestamp.IsZero() {
		return r.handleDeletion(ctx, generator)
	}

	// Add finalizer if it doesn't exist
	if !controllerutil.ContainsFinalizer(generator, finalizerName) {
		log.Info("Adding finalizer", "name", generator.Name, "namespace", generator.Namespace)
		controllerutil.AddFinalizer(generator, finalizerName)
		if err := r.Update(ctx, generator); err != nil {
			log.Error(err, "failed to add finalizer")
			return ctrl.Result{}, err
		}
	}

	// Track active generators
	GeneratorsActive.WithLabelValues(generator.Status.Phase).Set(1)

	// Handle mode
	var result ctrl.Result
	var err error

	switch generator.Spec.Mode {
	case policy.ModeLearning:
		log.Info("Handling learning mode", "name", generator.Name, "namespace", generator.Namespace)
		result, err = r.handleLearningMode(ctx, generator)
	case policy.ModeEnforcing:
		log.Info("Handling enforcing mode", "name", generator.Name, "namespace", generator.Namespace)
		result, err = r.handleEnforcingMode(ctx, generator)
	default:
		log.Error(nil, "Invalid mode specified", "mode", generator.Spec.Mode, "name", generator.Name)
		return ctrl.Result{}, fmt.Errorf("invalid mode: %s", generator.Spec.Mode)
	}

	// Record metrics
	duration := time.Since(startTime).Seconds()
	ReconcileDuration.WithLabelValues(generator.Spec.Mode).Observe(duration)

	if err != nil {
		ReconcileTotal.WithLabelValues("error").Inc()
		log.Error(err, "failed to handle mode", "mode", generator.Spec.Mode, "name", generator.Name)
		return ctrl.Result{}, err
	}
	ReconcileTotal.WithLabelValues("success").Inc()

	log.Info("Completed reconciliation",
		"name", generator.Name,
		"namespace", generator.Namespace,
		"phase", generator.Status.Phase,
		"requeue", result.RequeueAfter)

	return result, nil
}

// syncPhase updates the status phase to match the spec mode
func (r *NetworkPolicyGeneratorReconciler) syncPhase(ctx context.Context, generator *securityv1.NetworkPolicyGenerator) error {
	log := log.FromContext(ctx)

	oldPhase := generator.Status.Phase
	switch generator.Spec.Mode {
	case policy.ModeEnforcing:
		generator.Status.Phase = policy.PhaseEnforcing
	case policy.ModeLearning:
		generator.Status.Phase = policy.PhaseLearning
	}

	if oldPhase != generator.Status.Phase {
		log.Info("Phase changed", "oldPhase", oldPhase, "newPhase", generator.Status.Phase,
			"name", generator.Name, "namespace", generator.Namespace)
		r.Recorder.Eventf(generator, "Normal", "PhaseChanged",
			"Phase changed from %s to %s", oldPhase, generator.Status.Phase)
	}

	if err := r.Status().Update(ctx, generator); err != nil {
		log.Error(err, "failed to update status", "name", generator.Name, "phase", generator.Status.Phase)
		return err
	}

	return nil
}

// handleDeletion handles the deletion of a NetworkPolicyGenerator with finalizer cleanup
func (r *NetworkPolicyGeneratorReconciler) handleDeletion(ctx context.Context, generator *securityv1.NetworkPolicyGenerator) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.Info("Resource is being deleted", "name", generator.Name, "namespace", generator.Namespace)

	if controllerutil.ContainsFinalizer(generator, finalizerName) {
		if err := r.deleteNetworkPolicies(ctx, generator); err != nil {
			r.Recorder.Eventf(generator, "Warning", "CleanupFailed", "Failed to delete NetworkPolicies: %v", err)
			log.Error(err, "failed to delete NetworkPolicies")
			return ctrl.Result{}, err
		}
		r.Recorder.Event(generator, "Normal", "PoliciesDeleted", "All generated NetworkPolicies deleted")
		PolicyOperations.WithLabelValues("Deleted").Inc()
		PoliciesApplied.DeleteLabelValues(generator.Name, generator.Namespace, generator.Spec.PolicyEngine)
		controllerutil.RemoveFinalizer(generator, finalizerName)
		if err := r.Update(ctx, generator); err != nil {
			log.Error(err, "failed to remove finalizer")
			return ctrl.Result{}, err
		}
		log.Info("Successfully removed finalizer", "name", generator.Name, "namespace", generator.Namespace)
	}
	return ctrl.Result{}, nil
}

// deleteNetworkPolicies deletes all NetworkPolicies created by this generator
func (r *NetworkPolicyGeneratorReconciler) deleteNetworkPolicies(ctx context.Context, generator *securityv1.NetworkPolicyGenerator) error {
	log := log.FromContext(ctx)

	var namespacesToClean []string
	if generator.Spec.Policy.Type == policy.PolicyTypeAllow {
		namespacesToClean = generator.Spec.Policy.DeniedNamespaces
	} else {
		namespacesToClean = []string{generator.Namespace}
	}

	for _, ns := range namespacesToClean {
		np := &networkingv1.NetworkPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      policy.PolicyName(generator.Name),
				Namespace: ns,
			},
		}

		if err := r.Delete(ctx, np); err != nil {
			if !apierrors.IsNotFound(err) {
				log.Error(err, "failed to delete NetworkPolicy", "namespace", ns, "name", np.Name)
				return err
			}
		}

		log.Info("Successfully deleted NetworkPolicy", "namespace", ns, "name", np.Name)
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager
func (r *NetworkPolicyGeneratorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&securityv1.NetworkPolicyGenerator{}).
		Complete(r)
}
