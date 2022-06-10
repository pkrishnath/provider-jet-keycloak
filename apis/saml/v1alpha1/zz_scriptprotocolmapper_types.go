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

type ScriptProtocolMapperObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type ScriptProtocolMapperParameters struct {

	// +kubebuilder:validation:Optional
	ClientID *string `json:"clientId,omitempty" tf:"client_id,omitempty"`

	// +kubebuilder:validation:Optional
	ClientScopeID *string `json:"clientScopeId,omitempty" tf:"client_scope_id,omitempty"`

	// +kubebuilder:validation:Optional
	FriendlyName *string `json:"friendlyName,omitempty" tf:"friendly_name,omitempty"`

	// +kubebuilder:validation:Required
	RealmID *string `json:"realmId" tf:"realm_id,omitempty"`

	// +kubebuilder:validation:Required
	SAMLAttributeName *string `json:"samlAttributeName" tf:"saml_attribute_name,omitempty"`

	// +kubebuilder:validation:Required
	SAMLAttributeNameFormat *string `json:"samlAttributeNameFormat" tf:"saml_attribute_name_format,omitempty"`

	// +kubebuilder:validation:Required
	Script *string `json:"script" tf:"script,omitempty"`

	// +kubebuilder:validation:Optional
	SingleValueAttribute *bool `json:"singleValueAttribute,omitempty" tf:"single_value_attribute,omitempty"`
}

// ScriptProtocolMapperSpec defines the desired state of ScriptProtocolMapper
type ScriptProtocolMapperSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     ScriptProtocolMapperParameters `json:"forProvider"`
}

// ScriptProtocolMapperStatus defines the observed state of ScriptProtocolMapper.
type ScriptProtocolMapperStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        ScriptProtocolMapperObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// ScriptProtocolMapper is the Schema for the ScriptProtocolMappers API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloakjet}
type ScriptProtocolMapper struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ScriptProtocolMapperSpec   `json:"spec"`
	Status            ScriptProtocolMapperStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ScriptProtocolMapperList contains a list of ScriptProtocolMappers
type ScriptProtocolMapperList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ScriptProtocolMapper `json:"items"`
}

// Repository type metadata.
var (
	ScriptProtocolMapper_Kind             = "ScriptProtocolMapper"
	ScriptProtocolMapper_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: ScriptProtocolMapper_Kind}.String()
	ScriptProtocolMapper_KindAPIVersion   = ScriptProtocolMapper_Kind + "." + CRDGroupVersion.String()
	ScriptProtocolMapper_GroupVersionKind = CRDGroupVersion.WithKind(ScriptProtocolMapper_Kind)
)

func init() {
	SchemeBuilder.Register(&ScriptProtocolMapper{}, &ScriptProtocolMapperList{})
}
