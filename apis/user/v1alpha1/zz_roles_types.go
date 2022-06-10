/*
Copyright 2021 The Crossplane Authors.

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

// Code generated by terrajet. DO NOT EDIT.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	v1 "github.com/crossplane/crossplane-runtime/apis/common/v1"
)

type RolesObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type RolesParameters struct {

	// +kubebuilder:validation:Optional
	Exhaustive *bool `json:"exhaustive,omitempty" tf:"exhaustive,omitempty"`

	// +kubebuilder:validation:Required
	RealmID *string `json:"realmId" tf:"realm_id,omitempty"`

	// +kubebuilder:validation:Required
	RoleIds []*string `json:"roleIds" tf:"role_ids,omitempty"`

	// +kubebuilder:validation:Required
	UserID *string `json:"userId" tf:"user_id,omitempty"`
}

// RolesSpec defines the desired state of Roles
type RolesSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     RolesParameters `json:"forProvider"`
}

// RolesStatus defines the observed state of Roles.
type RolesStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        RolesObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// Roles is the Schema for the Roless API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloakjet}
type Roles struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              RolesSpec   `json:"spec"`
	Status            RolesStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RolesList contains a list of Roless
type RolesList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Roles `json:"items"`
}

// Repository type metadata.
var (
	Roles_Kind             = "Roles"
	Roles_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Roles_Kind}.String()
	Roles_KindAPIVersion   = Roles_Kind + "." + CRDGroupVersion.String()
	Roles_GroupVersionKind = CRDGroupVersion.WithKind(Roles_Kind)
)

func init() {
	SchemeBuilder.Register(&Roles{}, &RolesList{})
}