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

package v1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// HoneypotSpec defines the desired state of Honeypot
type HoneypotSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	ClusterKey string            `json:"clusterKey"`
	Service    string            `json:"service"`
	Ports      []ServicePort     `json:"ports"`
	WorkLoad   string            `json:"workload"`
	Image      string            `json:"image"`
	Secrets    []ImagePullSecret `json:"secrets"`
}

type ServicePort struct {
	Port       int32 `json:"port"`
	TargetPort int32 `json:"targetPort"`
}

type ImagePullSecret struct {
	UserName string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email,omitempty"`
	Server   string `json:"server"`
}

// HoneypotStatus defines the observed state of Honeypot
type HoneypotStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file
	Active []*corev1.ObjectReference `json:"active,omitempty"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Honeypot is the Schema for the honeypots API
type Honeypot struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   HoneypotSpec   `json:"spec,omitempty"`
	Status HoneypotStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// HoneypotList contains a list of Honeypot
type HoneypotList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Honeypot `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Honeypot{}, &HoneypotList{})
}
