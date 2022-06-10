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

type UserPropertyProtocolMapperObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type UserPropertyProtocolMapperParameters struct {

	// Indicates if the property should be a claim in the access token.
	// +kubebuilder:validation:Optional
	AddToAccessToken *bool `json:"addToAccessToken,omitempty" tf:"add_to_access_token,omitempty"`

	// Indicates if the property should be a claim in the id token.
	// +kubebuilder:validation:Optional
	AddToIDToken *bool `json:"addToIdToken,omitempty" tf:"add_to_id_token,omitempty"`

	// Indicates if the property should appear in the userinfo response body.
	// +kubebuilder:validation:Optional
	AddToUserinfo *bool `json:"addToUserinfo,omitempty" tf:"add_to_userinfo,omitempty"`

	// +kubebuilder:validation:Required
	ClaimName *string `json:"claimName" tf:"claim_name,omitempty"`

	// Claim type used when serializing tokens.
	// +kubebuilder:validation:Optional
	ClaimValueType *string `json:"claimValueType,omitempty" tf:"claim_value_type,omitempty"`

	// The mapper's associated client. Cannot be used at the same time as client_scope_id.
	// +kubebuilder:validation:Optional
	ClientID *string `json:"clientId,omitempty" tf:"client_id,omitempty"`

	// The mapper's associated client scope. Cannot be used at the same time as client_id.
	// +kubebuilder:validation:Optional
	ClientScopeID *string `json:"clientScopeId,omitempty" tf:"client_scope_id,omitempty"`

	// The realm id where the associated client or client scope exists.
	// +kubebuilder:validation:Required
	RealmID *string `json:"realmId" tf:"realm_id,omitempty"`

	// +kubebuilder:validation:Required
	UserProperty *string `json:"userProperty" tf:"user_property,omitempty"`
}

// UserPropertyProtocolMapperSpec defines the desired state of UserPropertyProtocolMapper
type UserPropertyProtocolMapperSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     UserPropertyProtocolMapperParameters `json:"forProvider"`
}

// UserPropertyProtocolMapperStatus defines the observed state of UserPropertyProtocolMapper.
type UserPropertyProtocolMapperStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        UserPropertyProtocolMapperObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// UserPropertyProtocolMapper is the Schema for the UserPropertyProtocolMappers API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloakjet}
type UserPropertyProtocolMapper struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              UserPropertyProtocolMapperSpec   `json:"spec"`
	Status            UserPropertyProtocolMapperStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// UserPropertyProtocolMapperList contains a list of UserPropertyProtocolMappers
type UserPropertyProtocolMapperList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []UserPropertyProtocolMapper `json:"items"`
}

// Repository type metadata.
var (
	UserPropertyProtocolMapper_Kind             = "UserPropertyProtocolMapper"
	UserPropertyProtocolMapper_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: UserPropertyProtocolMapper_Kind}.String()
	UserPropertyProtocolMapper_KindAPIVersion   = UserPropertyProtocolMapper_Kind + "." + CRDGroupVersion.String()
	UserPropertyProtocolMapper_GroupVersionKind = CRDGroupVersion.WithKind(UserPropertyProtocolMapper_Kind)
)

func init() {
	SchemeBuilder.Register(&UserPropertyProtocolMapper{}, &UserPropertyProtocolMapperList{})
}