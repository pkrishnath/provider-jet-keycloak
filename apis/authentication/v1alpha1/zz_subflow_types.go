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

type SubflowObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type SubflowParameters struct {

	// +kubebuilder:validation:Required
	Alias *string `json:"alias" tf:"alias,omitempty"`

	// Might be needed to be set with certain custom subflow with specific authenticator, in general this will remain empty
	// +kubebuilder:validation:Optional
	Authenticator *string `json:"authenticator,omitempty" tf:"authenticator,omitempty"`

	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// +kubebuilder:validation:Required
	ParentFlowAlias *string `json:"parentFlowAlias" tf:"parent_flow_alias,omitempty"`

	// +kubebuilder:validation:Optional
	ProviderID *string `json:"providerId,omitempty" tf:"provider_id,omitempty"`

	// +kubebuilder:validation:Required
	RealmID *string `json:"realmId" tf:"realm_id,omitempty"`

	// +kubebuilder:validation:Optional
	Requirement *string `json:"requirement,omitempty" tf:"requirement,omitempty"`
}

// SubflowSpec defines the desired state of Subflow
type SubflowSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     SubflowParameters `json:"forProvider"`
}

// SubflowStatus defines the observed state of Subflow.
type SubflowStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        SubflowObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// Subflow is the Schema for the Subflows API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloakjet}
type Subflow struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SubflowSpec   `json:"spec"`
	Status            SubflowStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// SubflowList contains a list of Subflows
type SubflowList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Subflow `json:"items"`
}

// Repository type metadata.
var (
	Subflow_Kind             = "Subflow"
	Subflow_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Subflow_Kind}.String()
	Subflow_KindAPIVersion   = Subflow_Kind + "." + CRDGroupVersion.String()
	Subflow_GroupVersionKind = CRDGroupVersion.WithKind(Subflow_Kind)
)

func init() {
	SchemeBuilder.Register(&Subflow{}, &SubflowList{})
}