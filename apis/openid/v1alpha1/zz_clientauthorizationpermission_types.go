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

type ClientAuthorizationPermissionObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type ClientAuthorizationPermissionParameters struct {

	// +kubebuilder:validation:Optional
	DecisionStrategy *string `json:"decisionStrategy,omitempty" tf:"decision_strategy,omitempty"`

	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// +kubebuilder:validation:Optional
	Policies []*string `json:"policies,omitempty" tf:"policies,omitempty"`

	// +kubebuilder:validation:Required
	RealmID *string `json:"realmId" tf:"realm_id,omitempty"`

	// +kubebuilder:validation:Required
	ResourceServerID *string `json:"resourceServerId" tf:"resource_server_id,omitempty"`

	// +kubebuilder:validation:Optional
	Resources []*string `json:"resources,omitempty" tf:"resources,omitempty"`

	// +kubebuilder:validation:Optional
	Scopes []*string `json:"scopes,omitempty" tf:"scopes,omitempty"`

	// +kubebuilder:validation:Optional
	Type *string `json:"type,omitempty" tf:"type,omitempty"`
}

// ClientAuthorizationPermissionSpec defines the desired state of ClientAuthorizationPermission
type ClientAuthorizationPermissionSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     ClientAuthorizationPermissionParameters `json:"forProvider"`
}

// ClientAuthorizationPermissionStatus defines the observed state of ClientAuthorizationPermission.
type ClientAuthorizationPermissionStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        ClientAuthorizationPermissionObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// ClientAuthorizationPermission is the Schema for the ClientAuthorizationPermissions API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloakjet}
type ClientAuthorizationPermission struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ClientAuthorizationPermissionSpec   `json:"spec"`
	Status            ClientAuthorizationPermissionStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClientAuthorizationPermissionList contains a list of ClientAuthorizationPermissions
type ClientAuthorizationPermissionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClientAuthorizationPermission `json:"items"`
}

// Repository type metadata.
var (
	ClientAuthorizationPermission_Kind             = "ClientAuthorizationPermission"
	ClientAuthorizationPermission_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: ClientAuthorizationPermission_Kind}.String()
	ClientAuthorizationPermission_KindAPIVersion   = ClientAuthorizationPermission_Kind + "." + CRDGroupVersion.String()
	ClientAuthorizationPermission_GroupVersionKind = CRDGroupVersion.WithKind(ClientAuthorizationPermission_Kind)
)

func init() {
	SchemeBuilder.Register(&ClientAuthorizationPermission{}, &ClientAuthorizationPermissionList{})
}