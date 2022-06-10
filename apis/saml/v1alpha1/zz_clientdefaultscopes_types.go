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

type ClientDefaultScopesObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type ClientDefaultScopesParameters struct {

	// +kubebuilder:validation:Required
	ClientID *string `json:"clientId" tf:"client_id,omitempty"`

	// +kubebuilder:validation:Required
	DefaultScopes []*string `json:"defaultScopes" tf:"default_scopes,omitempty"`

	// +kubebuilder:validation:Required
	RealmID *string `json:"realmId" tf:"realm_id,omitempty"`
}

// ClientDefaultScopesSpec defines the desired state of ClientDefaultScopes
type ClientDefaultScopesSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     ClientDefaultScopesParameters `json:"forProvider"`
}

// ClientDefaultScopesStatus defines the observed state of ClientDefaultScopes.
type ClientDefaultScopesStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        ClientDefaultScopesObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// ClientDefaultScopes is the Schema for the ClientDefaultScopess API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloakjet}
type ClientDefaultScopes struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ClientDefaultScopesSpec   `json:"spec"`
	Status            ClientDefaultScopesStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClientDefaultScopesList contains a list of ClientDefaultScopess
type ClientDefaultScopesList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClientDefaultScopes `json:"items"`
}

// Repository type metadata.
var (
	ClientDefaultScopes_Kind             = "ClientDefaultScopes"
	ClientDefaultScopes_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: ClientDefaultScopes_Kind}.String()
	ClientDefaultScopes_KindAPIVersion   = ClientDefaultScopes_Kind + "." + CRDGroupVersion.String()
	ClientDefaultScopes_GroupVersionKind = CRDGroupVersion.WithKind(ClientDefaultScopes_Kind)
)

func init() {
	SchemeBuilder.Register(&ClientDefaultScopes{}, &ClientDefaultScopesList{})
}
