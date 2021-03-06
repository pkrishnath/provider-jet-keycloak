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

type ManageMembersScopeObservation struct {
}

type ManageMembersScopeParameters struct {

	// +kubebuilder:validation:Optional
	DecisionStrategy *string `json:"decisionStrategy,omitempty" tf:"decision_strategy,omitempty"`

	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// +kubebuilder:validation:Optional
	Policies []*string `json:"policies,omitempty" tf:"policies,omitempty"`
}

type ManageMembershipScopeObservation struct {
}

type ManageMembershipScopeParameters struct {

	// +kubebuilder:validation:Optional
	DecisionStrategy *string `json:"decisionStrategy,omitempty" tf:"decision_strategy,omitempty"`

	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// +kubebuilder:validation:Optional
	Policies []*string `json:"policies,omitempty" tf:"policies,omitempty"`
}

type ManageScopeObservation struct {
}

type ManageScopeParameters struct {

	// +kubebuilder:validation:Optional
	DecisionStrategy *string `json:"decisionStrategy,omitempty" tf:"decision_strategy,omitempty"`

	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// +kubebuilder:validation:Optional
	Policies []*string `json:"policies,omitempty" tf:"policies,omitempty"`
}

type PermissionsObservation struct {
	AuthorizationResourceServerID *string `json:"authorizationResourceServerId,omitempty" tf:"authorization_resource_server_id,omitempty"`

	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type PermissionsParameters struct {

	// +kubebuilder:validation:Required
	GroupID *string `json:"groupId" tf:"group_id,omitempty"`

	// +kubebuilder:validation:Optional
	ManageMembersScope []ManageMembersScopeParameters `json:"manageMembersScope,omitempty" tf:"manage_members_scope,omitempty"`

	// +kubebuilder:validation:Optional
	ManageMembershipScope []ManageMembershipScopeParameters `json:"manageMembershipScope,omitempty" tf:"manage_membership_scope,omitempty"`

	// +kubebuilder:validation:Optional
	ManageScope []ManageScopeParameters `json:"manageScope,omitempty" tf:"manage_scope,omitempty"`

	// +kubebuilder:validation:Required
	RealmID *string `json:"realmId" tf:"realm_id,omitempty"`

	// +kubebuilder:validation:Optional
	ViewMembersScope []ViewMembersScopeParameters `json:"viewMembersScope,omitempty" tf:"view_members_scope,omitempty"`

	// +kubebuilder:validation:Optional
	ViewScope []ViewScopeParameters `json:"viewScope,omitempty" tf:"view_scope,omitempty"`
}

type ViewMembersScopeObservation struct {
}

type ViewMembersScopeParameters struct {

	// +kubebuilder:validation:Optional
	DecisionStrategy *string `json:"decisionStrategy,omitempty" tf:"decision_strategy,omitempty"`

	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// +kubebuilder:validation:Optional
	Policies []*string `json:"policies,omitempty" tf:"policies,omitempty"`
}

type ViewScopeObservation struct {
}

type ViewScopeParameters struct {

	// +kubebuilder:validation:Optional
	DecisionStrategy *string `json:"decisionStrategy,omitempty" tf:"decision_strategy,omitempty"`

	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// +kubebuilder:validation:Optional
	Policies []*string `json:"policies,omitempty" tf:"policies,omitempty"`
}

// PermissionsSpec defines the desired state of Permissions
type PermissionsSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     PermissionsParameters `json:"forProvider"`
}

// PermissionsStatus defines the observed state of Permissions.
type PermissionsStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        PermissionsObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// Permissions is the Schema for the Permissionss API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloakjet}
type Permissions struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              PermissionsSpec   `json:"spec"`
	Status            PermissionsStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// PermissionsList contains a list of Permissionss
type PermissionsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Permissions `json:"items"`
}

// Repository type metadata.
var (
	Permissions_Kind             = "Permissions"
	Permissions_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Permissions_Kind}.String()
	Permissions_KindAPIVersion   = Permissions_Kind + "." + CRDGroupVersion.String()
	Permissions_GroupVersionKind = CRDGroupVersion.WithKind(Permissions_Kind)
)

func init() {
	SchemeBuilder.Register(&Permissions{}, &PermissionsList{})
}
