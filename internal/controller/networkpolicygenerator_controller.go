package controller

import (
	"context"
	"fmt"

	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
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

	// Finalizer 처리
	if generator.ObjectMeta.DeletionTimestamp.IsZero() {
		// 오브젝트가 삭제되지 않은 상태
		if !containsString(generator.ObjectMeta.Finalizers, finalizerName) {
			// Finalizer 추가
			generator.ObjectMeta.Finalizers = append(generator.ObjectMeta.Finalizers, finalizerName)
			if err := r.Update(ctx, generator); err != nil {
				return ctrl.Result{}, err
			}
		}
	} else {
		// 오브젝트가 삭제 중인 상태
		if containsString(generator.ObjectMeta.Finalizers, finalizerName) {
			// 1. 연관된 NetworkPolicy 삭제
			if err := r.deleteNetworkPolicy(ctx, generator); err != nil {
				return ctrl.Result{}, err
			}

			// 2. Finalizer 제거
			generator.ObjectMeta.Finalizers = removeString(generator.ObjectMeta.Finalizers, finalizerName)
			// 3. 리소스 업데이트 (Finalizer 제거 반영)
			if err := r.Update(ctx, generator); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
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

// NetworkPolicy 삭제 함수
func (r *NetworkPolicyGeneratorReconciler) deleteNetworkPolicy(ctx context.Context, generator *securityv1.NetworkPolicyGenerator) error {
	networkPolicy := &networkingv1.NetworkPolicy{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      generator.Name + "-generated",
		Namespace: generator.Namespace,
	}, networkPolicy)

	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return err
	}

	return r.Delete(ctx, networkPolicy)
}

// Finalizer 유틸리티 함수들
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func removeString(slice []string, s string) []string {
	result := []string{}
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
