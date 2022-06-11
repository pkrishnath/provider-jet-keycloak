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

type AttributeIdentityProviderMapperObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type AttributeIdentityProviderMapperParameters struct {

	// OIDC Claim
	// +kubebuilder:validation:Optional
	AttributeName *string `json:"attributeName,omitempty" tf:"attribute_name,omitempty"`

	// User Attribute
	// +kubebuilder:validation:Optional
	AttributeValue *string `json:"attributeValue,omitempty" tf:"attribute_value,omitempty"`

	// +kubebuilder:validation:Optional
	ExtraConfig map[string]*string `json:"extraConfig,omitempty" tf:"extra_config,omitempty"`

	// IDP Alias
	// +kubebuilder:validation:Required
	IdentityProviderAlias *string `json:"identityProviderAlias" tf:"identity_provider_alias,omitempty"`

	// Realm Name
	// +kubebuilder:validation:Required
	Realm *string `json:"realm" tf:"realm,omitempty"`

	// Is Attribute Related To a User Session
	// +kubebuilder:validation:Required
	UserSession *bool `json:"userSession" tf:"user_session,omitempty"`
}

// AttributeIdentityProviderMapperSpec defines the desired state of AttributeIdentityProviderMapper
type AttributeIdentityProviderMapperSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     AttributeIdentityProviderMapperParameters `json:"forProvider"`
}

// AttributeIdentityProviderMapperStatus defines the observed state of AttributeIdentityProviderMapper.
type AttributeIdentityProviderMapperStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        AttributeIdentityProviderMapperObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// AttributeIdentityProviderMapper is the Schema for the AttributeIdentityProviderMappers API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloakjet}
type AttributeIdentityProviderMapper struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AttributeIdentityProviderMapperSpec   `json:"spec"`
	Status            AttributeIdentityProviderMapperStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AttributeIdentityProviderMapperList contains a list of AttributeIdentityProviderMappers
type AttributeIdentityProviderMapperList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AttributeIdentityProviderMapper `json:"items"`
}

// Repository type metadata.
var (
	AttributeIdentityProviderMapper_Kind             = "AttributeIdentityProviderMapper"
	AttributeIdentityProviderMapper_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: AttributeIdentityProviderMapper_Kind}.String()
	AttributeIdentityProviderMapper_KindAPIVersion   = AttributeIdentityProviderMapper_Kind + "." + CRDGroupVersion.String()
	AttributeIdentityProviderMapper_GroupVersionKind = CRDGroupVersion.WithKind(AttributeIdentityProviderMapper_Kind)
)

func init() {
	SchemeBuilder.Register(&AttributeIdentityProviderMapper{}, &AttributeIdentityProviderMapperList{})
}
