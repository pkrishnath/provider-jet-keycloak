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

type KeystoreEcdsaGeneratedObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type KeystoreEcdsaGeneratedParameters struct {

	// Set if the keys can be used for signing
	// +kubebuilder:validation:Optional
	Active *bool `json:"active,omitempty" tf:"active,omitempty"`

	// Elliptic Curve used in ECDSA
	// +kubebuilder:validation:Optional
	EllipticCurveKey *string `json:"ellipticCurveKey,omitempty" tf:"elliptic_curve_key,omitempty"`

	// Set if the keys are enabled
	// +kubebuilder:validation:Optional
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// Priority for the provider
	// +kubebuilder:validation:Optional
	Priority *float64 `json:"priority,omitempty" tf:"priority,omitempty"`

	// +kubebuilder:validation:Required
	RealmID *string `json:"realmId" tf:"realm_id,omitempty"`
}

// KeystoreEcdsaGeneratedSpec defines the desired state of KeystoreEcdsaGenerated
type KeystoreEcdsaGeneratedSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     KeystoreEcdsaGeneratedParameters `json:"forProvider"`
}

// KeystoreEcdsaGeneratedStatus defines the observed state of KeystoreEcdsaGenerated.
type KeystoreEcdsaGeneratedStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        KeystoreEcdsaGeneratedObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// KeystoreEcdsaGenerated is the Schema for the KeystoreEcdsaGenerateds API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloakjet}
type KeystoreEcdsaGenerated struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              KeystoreEcdsaGeneratedSpec   `json:"spec"`
	Status            KeystoreEcdsaGeneratedStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KeystoreEcdsaGeneratedList contains a list of KeystoreEcdsaGenerateds
type KeystoreEcdsaGeneratedList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeystoreEcdsaGenerated `json:"items"`
}

// Repository type metadata.
var (
	KeystoreEcdsaGenerated_Kind             = "KeystoreEcdsaGenerated"
	KeystoreEcdsaGenerated_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: KeystoreEcdsaGenerated_Kind}.String()
	KeystoreEcdsaGenerated_KindAPIVersion   = KeystoreEcdsaGenerated_Kind + "." + CRDGroupVersion.String()
	KeystoreEcdsaGenerated_GroupVersionKind = CRDGroupVersion.WithKind(KeystoreEcdsaGenerated_Kind)
)

func init() {
	SchemeBuilder.Register(&KeystoreEcdsaGenerated{}, &KeystoreEcdsaGeneratedList{})
}
