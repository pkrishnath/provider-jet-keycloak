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

type ImporterIdentityProviderMapperObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type ImporterIdentityProviderMapperParameters struct {

	// Attribute Friendly Name
	// +kubebuilder:validation:Optional
	AttributeFriendlyName *string `json:"attributeFriendlyName,omitempty" tf:"attribute_friendly_name,omitempty"`

	// Attribute Name
	// +kubebuilder:validation:Optional
	AttributeName *string `json:"attributeName,omitempty" tf:"attribute_name,omitempty"`

	// Claim Name
	// +kubebuilder:validation:Optional
	ClaimName *string `json:"claimName,omitempty" tf:"claim_name,omitempty"`

	// +kubebuilder:validation:Optional
	ExtraConfig map[string]*string `json:"extraConfig,omitempty" tf:"extra_config,omitempty"`

	// IDP Alias
	// +kubebuilder:validation:Required
	IdentityProviderAlias *string `json:"identityProviderAlias" tf:"identity_provider_alias,omitempty"`

	// Realm Name
	// +kubebuilder:validation:Required
	Realm *string `json:"realm" tf:"realm,omitempty"`

	// User Attribute
	// +kubebuilder:validation:Required
	UserAttribute *string `json:"userAttribute" tf:"user_attribute,omitempty"`
}

// ImporterIdentityProviderMapperSpec defines the desired state of ImporterIdentityProviderMapper
type ImporterIdentityProviderMapperSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     ImporterIdentityProviderMapperParameters `json:"forProvider"`
}

// ImporterIdentityProviderMapperStatus defines the observed state of ImporterIdentityProviderMapper.
type ImporterIdentityProviderMapperStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        ImporterIdentityProviderMapperObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// ImporterIdentityProviderMapper is the Schema for the ImporterIdentityProviderMappers API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloakjet}
type ImporterIdentityProviderMapper struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ImporterIdentityProviderMapperSpec   `json:"spec"`
	Status            ImporterIdentityProviderMapperStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ImporterIdentityProviderMapperList contains a list of ImporterIdentityProviderMappers
type ImporterIdentityProviderMapperList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ImporterIdentityProviderMapper `json:"items"`
}

// Repository type metadata.
var (
	ImporterIdentityProviderMapper_Kind             = "ImporterIdentityProviderMapper"
	ImporterIdentityProviderMapper_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: ImporterIdentityProviderMapper_Kind}.String()
	ImporterIdentityProviderMapper_KindAPIVersion   = ImporterIdentityProviderMapper_Kind + "." + CRDGroupVersion.String()
	ImporterIdentityProviderMapper_GroupVersionKind = CRDGroupVersion.WithKind(ImporterIdentityProviderMapper_Kind)
)

func init() {
	SchemeBuilder.Register(&ImporterIdentityProviderMapper{}, &ImporterIdentityProviderMapperList{})
}
