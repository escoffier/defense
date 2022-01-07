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
	"fmt"

	appv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
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

const (
	labelKey      = "app"
	contanierName = "honeyspot"
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
	objRefs := honeypot.Status.Active
	honeypot.Status.Active = nil

	oldDeployRef := getObjRef(objRefs, "Deployment")
	oldSvcRef := getObjRef(objRefs, "Service")
	oldSecretRef := getObjRef(objRefs, "Secret")

	// secret := &corev1.Secret{}
	// err = r.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: req.Name}, secret)
	// if err != nil {
	// 	if errors.IsNotFound(err) {
	// 		return nil, err
	// 	}
	// 	return nil, err
	// }
	secret, err := r.buildSecrect(ctx, honeypot)
	if err != nil {
		return ctrl.Result{}, err
	}
	secretRef, err := ref.GetReference(r.Scheme, secret)
	if err != nil {
		logger.Error(err, "unabable to make reference to secret", "secret", secret)
		return ctrl.Result{}, err
	}

	honeypot.Status.Active = append(honeypot.Status.Active, secretRef)

	if oldSecretRef != nil {
		if oldSecretRef.Namespace != honeypot.Namespace || oldSecretRef.Name != honeypot.Name {
			oldSecret := corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: honeypot.Namespace,
					Name:      honeypot.Name,
				},
			}
			err = r.Delete(ctx, &oldSecret)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	deploy := &appv1.Deployment{}
	err = r.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: honeypot.Spec.WorkLoad}, deploy)
	if err != nil {
		if errors.IsNotFound(err) {
			deploy = r.buildDeployment(honeypot)
			err = r.Create(ctx, deploy)
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

	if oldDeployRef != nil {
		if oldDeployRef.Name != honeypot.Spec.WorkLoad || oldDeployRef.Namespace != req.Namespace {
			oldDeploy := &appv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Namespace: oldDeployRef.Namespace, Name: oldDeployRef.Name},
			}
			// r.Get(ctx, types.NamespacedName{Namespace: oldDeployRef.Namespace, Name: oldDeployRef.Name}, oldDeploy)
			err = r.Delete(ctx, oldDeploy)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	svc := &corev1.Service{}
	err = r.Get(ctx, types.NamespacedName{Namespace: req.Namespace, Name: honeypot.Spec.Service}, svc)
	if err != nil {
		if errors.IsNotFound(err) {
			// err = r.createService(ctx, honeypot.Spec.ClusterKey, honeypot.Namespace, honeypot.Spec.ServiceName, honeypot)
			svc = r.buildService(honeypot)
			err = r.Create(ctx, svc)
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

	if oldSvcRef != nil {
		if oldSvcRef.Name != honeypot.Spec.Service || oldSvcRef.Namespace != req.Namespace {
			oldSvc := corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Namespace: oldSvcRef.Namespace, Name: oldSvcRef.Name},
			}
			err = r.Delete(ctx, &oldSvc)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
	}

	logger.Info(honeypot.ResourceVersion)
	if !equality.Semantic.DeepEqual(svcRef, oldSvcRef) || !equality.Semantic.DeepEqual(deployRef, oldDeployRef) ||
		!equality.Semantic.DeepEqual(secretRef, oldSecretRef) {
		logger.Info("update Honeyspot status")
		err = r.Status().Update(ctx, honeypot)
		if err != nil {
			if errors.IsConflict(err) {
				newHoneypot := &defensev1.Honeypot{}
				err := r.Get(ctx, req.NamespacedName, newHoneypot)
				if err != nil {
					if errors.IsNotFound(err) {
						logger.Info("honeypot is deleted")
						return ctrl.Result{}, nil
					}
					return ctrl.Result{}, err
				}

			}
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{}, nil
}

func (r *HoneypotReconciler) buildDeployment(honeypot *defensev1.Honeypot) *appv1.Deployment {
	var replica int32 = 1
	labelSelector := &metav1.LabelSelector{
		MatchLabels: getLabel(honeypot),
	}

	var ports []corev1.ContainerPort
	for _, p := range honeypot.Spec.Ports {
		ports = append(ports, corev1.ContainerPort{
			ContainerPort: p.TargetPort,
		})
	}

	deploy := &appv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: honeypot.Namespace,
			Name:      honeypot.Spec.WorkLoad,
		},
		Spec: appv1.DeploymentSpec{
			Replicas: &replica,
			Selector: labelSelector,
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: getLabel(honeypot),
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{
						Name:  contanierName,
						Image: honeypot.Spec.Image,
						Ports: ports,
					}},
				},
			},
		},
	}
	ctrl.SetControllerReference(honeypot, deploy, r.Scheme)
	return deploy
}

func (r *HoneypotReconciler) buildService(honeypot *defensev1.Honeypot) *corev1.Service {

	var ports []corev1.ServicePort
	for _, p := range honeypot.Spec.Ports {
		ports = append(ports, corev1.ServicePort{
			Name:       fmt.Sprintf("%d", p.Port),
			Port:       p.Port,
			TargetPort: intstr.IntOrString{Type: 0, IntVal: p.TargetPort},
		})
	}

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      honeypot.Spec.Service,
			Namespace: honeypot.Namespace,
		},
		Spec: corev1.ServiceSpec{
			Selector: getLabel(honeypot),
			Ports:    ports,
		},
	}
	ctrl.SetControllerReference(honeypot, svc, r.Scheme)
	return svc
}

func (r *HoneypotReconciler) buildSecrect(ctx context.Context, honeypot *defensev1.Honeypot) (*corev1.Secret, error) {
	secretName := types.NamespacedName{Namespace: honeypot.Namespace, Name: honeypot.Name}
	secret := &corev1.Secret{}
	err := r.Get(ctx, secretName, secret)
	if err != nil {
		if errors.IsNotFound(err) {

			dockerCfg, err := dockerCfgJSONContent(honeypot.Spec.Secrets)
			if err != nil {
				return nil, err
			}
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: honeypot.Namespace,
					Name:      honeypot.Name,
				},
				Data: map[string][]byte{corev1.DockerConfigJsonKey: dockerCfg},
				Type: corev1.SecretTypeDockerConfigJson,
			}
			ctrl.SetControllerReference(honeypot, secret, r.Scheme)

			err = r.Create(ctx, secret)
			if err != nil {
				return nil, err
			}

			return secret, err
		}
		return nil, err
	}
	return secret, nil
}

func getObjRef(refers []*corev1.ObjectReference, kind string) *corev1.ObjectReference {
	for _, ref := range refers {
		if ref.Kind == kind {
			return ref
		}
	}
	return nil
}

func getLabel(honeypot *defensev1.Honeypot) map[string]string {
	return map[string]string{labelKey: fmt.Sprintf("%s-%s", honeypot.Name, honeypot.Spec.WorkLoad)}
}

// SetupWithManager sets up the controller with the Manager.
func (r *HoneypotReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&defensev1.Honeypot{}).
		Owns(&corev1.Service{}).
		Owns(&appv1.Deployment{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
