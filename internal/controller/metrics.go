package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	// ReconcileTotal counts total reconciliation attempts
	ReconcileTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "npg_reconcile_total",
			Help: "Total number of reconciliations by result",
		},
		[]string{"result"}, // "success", "error"
	)

	// PoliciesApplied tracks the number of currently applied policies per generator
	PoliciesApplied = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "npg_policies_applied",
			Help: "Number of applied network policies per generator",
		},
		[]string{"name", "namespace", "engine"},
	)

	// PolicyOperations counts policy create/update/delete operations
	PolicyOperations = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "npg_policy_operations_total",
			Help: "Total number of policy operations by action",
		},
		[]string{"action"}, // "Created", "Updated", "Deleted"
	)

	// GeneratorsActive tracks the number of active generators by phase
	GeneratorsActive = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "npg_generators_active",
			Help: "Number of active generators by phase",
		},
		[]string{"phase"}, // "Learning", "Enforcing"
	)

	// ReconcileDuration tracks reconciliation duration in seconds
	ReconcileDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "npg_reconcile_duration_seconds",
			Help:    "Duration of reconciliation in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"mode"},
	)

	// DryRunTotal counts dry-run executions
	DryRunTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "npg_dry_run_total",
			Help: "Total number of dry-run executions",
		},
	)

	// ValidationErrors counts webhook/validation errors
	ValidationErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "npg_validation_errors_total",
			Help: "Total number of validation errors by type",
		},
		[]string{"type"}, // "webhook", "reconcile"
	)
)

func init() {
	metrics.Registry.MustRegister(
		ReconcileTotal,
		PoliciesApplied,
		PolicyOperations,
		GeneratorsActive,
		ReconcileDuration,
		DryRunTotal,
		ValidationErrors,
	)
}
