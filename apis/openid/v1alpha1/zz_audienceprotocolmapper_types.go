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

type AudienceProtocolMapperObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type AudienceProtocolMapperParameters struct {

	// Indicates if this claim should be added to the access token.
	// +kubebuilder:validation:Optional
	AddToAccessToken *bool `json:"addToAccessToken,omitempty" tf:"add_to_access_token,omitempty"`

	// Indicates if this claim should be added to the id token.
	// +kubebuilder:validation:Optional
	AddToIDToken *bool `json:"addToIdToken,omitempty" tf:"add_to_id_token,omitempty"`

	// The mapper's associated client. Cannot be used at the same time as client_scope_id.
	// +kubebuilder:validation:Optional
	ClientID *string `json:"clientId,omitempty" tf:"client_id,omitempty"`

	// The mapper's associated client scope. Cannot be used at the same time as client_id.
	// +kubebuilder:validation:Optional
	ClientScopeID *string `json:"clientScopeId,omitempty" tf:"client_scope_id,omitempty"`

	// A client ID to include within the token's `aud` claim. Cannot be used with included_custom_audience
	// +kubebuilder:validation:Optional
	IncludedClientAudience *string `json:"includedClientAudience,omitempty" tf:"included_client_audience,omitempty"`

	// A custom audience to include within the token's `aud` claim.  Cannot be used with included_custom_audience
	// +kubebuilder:validation:Optional
	IncludedCustomAudience *string `json:"includedCustomAudience,omitempty" tf:"included_custom_audience,omitempty"`

	// The realm id where the associated client or client scope exists.
	// +kubebuilder:validation:Required
	RealmID *string `json:"realmId" tf:"realm_id,omitempty"`
}

// AudienceProtocolMapperSpec defines the desired state of AudienceProtocolMapper
type AudienceProtocolMapperSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     AudienceProtocolMapperParameters `json:"forProvider"`
}

// AudienceProtocolMapperStatus defines the observed state of AudienceProtocolMapper.
type AudienceProtocolMapperStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        AudienceProtocolMapperObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// AudienceProtocolMapper is the Schema for the AudienceProtocolMappers API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloakjet}
type AudienceProtocolMapper struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AudienceProtocolMapperSpec   `json:"spec"`
	Status            AudienceProtocolMapperStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AudienceProtocolMapperList contains a list of AudienceProtocolMappers
type AudienceProtocolMapperList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AudienceProtocolMapper `json:"items"`
}

// Repository type metadata.
var (
	AudienceProtocolMapper_Kind             = "AudienceProtocolMapper"
	AudienceProtocolMapper_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: AudienceProtocolMapper_Kind}.String()
	AudienceProtocolMapper_KindAPIVersion   = AudienceProtocolMapper_Kind + "." + CRDGroupVersion.String()
	AudienceProtocolMapper_GroupVersionKind = CRDGroupVersion.WithKind(AudienceProtocolMapper_Kind)
)

func init() {
	SchemeBuilder.Register(&AudienceProtocolMapper{}, &AudienceProtocolMapperList{})
}