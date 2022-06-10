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

type ClientPermissionsObservation struct {
	AuthorizationResourceServerID *string `json:"authorizationResourceServerId,omitempty" tf:"authorization_resource_server_id,omitempty"`

	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type ClientPermissionsParameters struct {

	// +kubebuilder:validation:Required
	ClientID *string `json:"clientId" tf:"client_id,omitempty"`

	// +kubebuilder:validation:Optional
	ConfigureScope []ConfigureScopeParameters `json:"configureScope,omitempty" tf:"configure_scope,omitempty"`

	// +kubebuilder:validation:Optional
	ManageScope []ManageScopeParameters `json:"manageScope,omitempty" tf:"manage_scope,omitempty"`

	// +kubebuilder:validation:Optional
	MapRolesClientScopeScope []MapRolesClientScopeScopeParameters `json:"mapRolesClientScopeScope,omitempty" tf:"map_roles_client_scope_scope,omitempty"`

	// +kubebuilder:validation:Optional
	MapRolesCompositeScope []MapRolesCompositeScopeParameters `json:"mapRolesCompositeScope,omitempty" tf:"map_roles_composite_scope,omitempty"`

	// +kubebuilder:validation:Optional
	MapRolesScope []MapRolesScopeParameters `json:"mapRolesScope,omitempty" tf:"map_roles_scope,omitempty"`

	// +kubebuilder:validation:Required
	RealmID *string `json:"realmId" tf:"realm_id,omitempty"`

	// +kubebuilder:validation:Optional
	TokenExchangeScope []TokenExchangeScopeParameters `json:"tokenExchangeScope,omitempty" tf:"token_exchange_scope,omitempty"`

	// +kubebuilder:validation:Optional
	ViewScope []ViewScopeParameters `json:"viewScope,omitempty" tf:"view_scope,omitempty"`
}

type ConfigureScopeObservation struct {
}

type ConfigureScopeParameters struct {

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

type MapRolesClientScopeScopeObservation struct {
}

type MapRolesClientScopeScopeParameters struct {

	// +kubebuilder:validation:Optional
	DecisionStrategy *string `json:"decisionStrategy,omitempty" tf:"decision_strategy,omitempty"`

	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// +kubebuilder:validation:Optional
	Policies []*string `json:"policies,omitempty" tf:"policies,omitempty"`
}

type MapRolesCompositeScopeObservation struct {
}

type MapRolesCompositeScopeParameters struct {

	// +kubebuilder:validation:Optional
	DecisionStrategy *string `json:"decisionStrategy,omitempty" tf:"decision_strategy,omitempty"`

	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// +kubebuilder:validation:Optional
	Policies []*string `json:"policies,omitempty" tf:"policies,omitempty"`
}

type MapRolesScopeObservation struct {
}

type MapRolesScopeParameters struct {

	// +kubebuilder:validation:Optional
	DecisionStrategy *string `json:"decisionStrategy,omitempty" tf:"decision_strategy,omitempty"`

	// +kubebuilder:validation:Optional
	Description *string `json:"description,omitempty" tf:"description,omitempty"`

	// +kubebuilder:validation:Optional
	Policies []*string `json:"policies,omitempty" tf:"policies,omitempty"`
}

type TokenExchangeScopeObservation struct {
}

type TokenExchangeScopeParameters struct {

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

// ClientPermissionsSpec defines the desired state of ClientPermissions
type ClientPermissionsSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     ClientPermissionsParameters `json:"forProvider"`
}

// ClientPermissionsStatus defines the observed state of ClientPermissions.
type ClientPermissionsStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        ClientPermissionsObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// ClientPermissions is the Schema for the ClientPermissionss API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloakjet}
type ClientPermissions struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ClientPermissionsSpec   `json:"spec"`
	Status            ClientPermissionsStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClientPermissionsList contains a list of ClientPermissionss
type ClientPermissionsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ClientPermissions `json:"items"`
}

// Repository type metadata.
var (
	ClientPermissions_Kind             = "ClientPermissions"
	ClientPermissions_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: ClientPermissions_Kind}.String()
	ClientPermissions_KindAPIVersion   = ClientPermissions_Kind + "." + CRDGroupVersion.String()
	ClientPermissions_GroupVersionKind = CRDGroupVersion.WithKind(ClientPermissions_Kind)
)

func init() {
	SchemeBuilder.Register(&ClientPermissions{}, &ClientPermissionsList{})
}
