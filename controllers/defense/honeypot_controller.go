/*
Copyright 2021.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package defense

import (
	"context"

	appv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	ref "k8s.io/client-go/tools/reference"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	defensev1 "scm.tensorsecurity.cn/tensorsecurity-rd/tensor-operator/apis/defense/v1"
)

// HoneypotReconciler reconciles a Honeypot object
type HoneypotReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=defense.security.cn,resources=honeypots,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=defense.security.cn,resources=honeypots/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=defense.security.cn,resources=honeypots/finalizers,verbs=update
//+kubebuilder:rbac:groups=core,resources=services,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=apps,resources=deployments,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the Honeypot object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.10.0/pkg/reconcile
func (r *HoneypotReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	honeypot := &defensev1.Honeypot{}
	err := r.Get(ctx, req.NamespacedName, honeypot)
	if err != nil {
		if errors.IsNotFound(err) {
			logger.Info("honeypot is deleted")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	honeypot = honeypot.DeepCopy()
	honeypot.Status.Active = nil
	deploy := &appv1.Deployment{}
	err = r.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: honeypot.Spec.WorkLoad}, deploy)
	if err != nil {
		if errors.IsNotFound(err) {
			err = r.createWorkload(ctx, honeypot.Spec.ClusterKey, honeypot.Namespace, honeypot.Spec.WorkLoad, honeypot)
			if err != nil {
				logger.Error(err, "falied to create honeypot deployment")
				return ctrl.Result{}, err
			}
		} else {
			logger.Error(err, "get deployment failed")
			return ctrl.Result{}, err
		}
	}
	deployRef, err := ref.GetReference(r.Scheme, deploy)
	if err != nil {
		logger.Error(err, "unabable to make reference to deployment", "deployment", deploy)
		return ctrl.Result{}, err
	}
	honeypot.Status.Active = append(honeypot.Status.Active, deployRef)

	svc := &corev1.Service{}
	err = r.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: honeypot.Spec.ServiceName}, svc)
	if err != nil {
		if errors.IsNotFound(err) {
			err = r.createService(ctx, honeypot.Spec.ClusterKey, honeypot.Namespace, honeypot.Spec.ServiceName, honeypot)
			if err != nil {
				logger.Error(err, "falied to create honeypot service")
				return ctrl.Result{}, err
			}
		} else {
			logger.Error(err, "get service failed")
			return ctrl.Result{}, err
		}
	}

	svcRef, err := ref.GetReference(r.Scheme, svc)
	if err != nil {
		logger.Error(err, "unabable to make reference to service", "service", svc)
		return ctrl.Result{}, err
	}
	honeypot.Status.Active = append(honeypot.Status.Active, svcRef)
	err = r.Status().Update(ctx, honeypot)
	if err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, nil
}

func (r *HoneypotReconciler) createWorkload(ctx context.Context, clusterKey, namespace, name string, honeypot *defensev1.Honeypot) error {
	var replica int32 = 1
	labelSelector := &metav1.LabelSelector{
		MatchLabels: map[string]string{"app": "honeypot"},
	}
	deploy := &appv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: appv1.DeploymentSpec{
			Replicas: &replica,
			Selector: labelSelector,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{"app": "honeypot"},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  "honeypot",
						Image: "docker.io/kennethreitz/httpbin",
						Ports: []corev1.ContainerPort{{
							ContainerPort: 80,
							Protocol:      corev1.ProtocolTCP,
						}},
					}},
				},
			},
		},
	}
	ctrl.SetControllerReference(honeypot, deploy, r.Scheme)
	return r.Create(ctx, deploy)
}

func (r *HoneypotReconciler) createService(ctx context.Context, clusterKey, namespace, name string, honeypot *defensev1.Honeypot) error {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "honeypot"},
			Ports: []corev1.ServicePort{{
				Protocol:   corev1.ProtocolTCP,
				Port:       8000,
				TargetPort: intstr.FromInt(80),
			}},
		},
	}
	ctrl.SetControllerReference(honeypot, svc, r.Scheme)
	return r.Create(ctx, svc)
}

// SetupWithManager sets up the controller with the Manager.
func (r *HoneypotReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&defensev1.Honeypot{}).
		Owns(&corev1.Service{}).
		Owns(&appv1.Deployment{}).
		Complete(r)
}
