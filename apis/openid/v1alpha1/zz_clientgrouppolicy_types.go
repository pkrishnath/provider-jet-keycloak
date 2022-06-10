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

type ClientGroupPolicyObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type ClientGroupPolicyParameters struct {

	// +kubebuilder:validation:Required
	DecisionStrategy *string `json:"decisionStrategy" tf:"decision_strategy,omitempty"`

	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// +kubebuilder:validation:Required
	Groups []GroupsParameters `json:"groups" tf:"groups,omitempty"`

	// +kubebuilder:validation:Optional
	GroupsClaim *string `json:"groupsClaim,omitempty" tf:"groups_claim,omitempty"`

	// +kubebuilder:validation:Optional
	Logic *string `json:"logic,omitempty" tf:"logic,omitempty"`

	// +kubebuilder:validation:Required
	RealmID *string `json:"realmId" tf:"realm_id,omitempty"`

	// +kubebuilder:validation:Required
	ResourceServerID *string `json:"resourceServerId" tf:"resource_server_id,omitempty"`
}

type GroupsObservation struct {
}

type GroupsParameters struct {

	// +kubebuilder:validation:Required
	ExtendChildren *bool `json:"extendChildren" tf:"extend_children,omitempty"`

	// +kubebuilder:validation:Required
	ID *string `json:"id" tf:"id,omitempty"`

	// +kubebuilder:validation:Required
	Path *string `json:"path" tf:"path,omitempty"`
}

// ClientGroupPolicySpec defines the desired state of ClientGroupPolicy
type ClientGroupPolicySpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     ClientGroupPolicyParameters `json:"forProvider"`
}

// ClientGroupPolicyStatus defines the observed state of ClientGroupPolicy.
type ClientGroupPolicyStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        ClientGroupPolicyObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// ClientGroupPolicy is the Schema for the ClientGroupPolicys API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloakjet}
type ClientGroupPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ClientGroupPolicySpec   `json:"spec"`
	Status            ClientGroupPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClientGroupPolicyList contains a list of ClientGroupPolicys
type ClientGroupPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClientGroupPolicy `json:"items"`
}

// Repository type metadata.
var (
	ClientGroupPolicy_Kind             = "ClientGroupPolicy"
	ClientGroupPolicy_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: ClientGroupPolicy_Kind}.String()
	ClientGroupPolicy_KindAPIVersion   = ClientGroupPolicy_Kind + "." + CRDGroupVersion.String()
	ClientGroupPolicy_GroupVersionKind = CRDGroupVersion.WithKind(ClientGroupPolicy_Kind)
)

func init() {
	SchemeBuilder.Register(&ClientGroupPolicy{}, &ClientGroupPolicyList{})
}
