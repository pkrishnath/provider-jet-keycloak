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

type KeystoreRsaObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type KeystoreRsaParameters struct {

	// Set if the keys can be used for signing
	// +kubebuilder:validation:Optional
	Active *bool `json:"active,omitempty" tf:"active,omitempty"`

	// Intended algorithm for the key
	// +kubebuilder:validation:Optional
	Algorithm *string `json:"algorithm,omitempty" tf:"algorithm,omitempty"`

	// X509 Certificate encoded in PEM format
	// +kubebuilder:validation:Required
	Certificate *string `json:"certificate" tf:"certificate,omitempty"`

	// Set if the keys are enabled
	// +kubebuilder:validation:Optional
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// Priority for the provider
	// +kubebuilder:validation:Optional
	Priority *float64 `json:"priority,omitempty" tf:"priority,omitempty"`

	// Private RSA Key encoded in PEM format
	// +kubebuilder:validation:Required
	PrivateKey *string `json:"privateKey" tf:"private_key,omitempty"`

	// +kubebuilder:validation:Required
	RealmID *string `json:"realmId" tf:"realm_id,omitempty"`
}

// KeystoreRsaSpec defines the desired state of KeystoreRsa
type KeystoreRsaSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     KeystoreRsaParameters `json:"forProvider"`
}

// KeystoreRsaStatus defines the observed state of KeystoreRsa.
type KeystoreRsaStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        KeystoreRsaObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// KeystoreRsa is the Schema for the KeystoreRsas API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloakjet}
type KeystoreRsa struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              KeystoreRsaSpec   `json:"spec"`
	Status            KeystoreRsaStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KeystoreRsaList contains a list of KeystoreRsas
type KeystoreRsaList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []KeystoreRsa `json:"items"`
}

// Repository type metadata.
var (
	KeystoreRsa_Kind             = "KeystoreRsa"
	KeystoreRsa_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: KeystoreRsa_Kind}.String()
	KeystoreRsa_KindAPIVersion   = KeystoreRsa_Kind + "." + CRDGroupVersion.String()
	KeystoreRsa_GroupVersionKind = CRDGroupVersion.WithKind(KeystoreRsa_Kind)
)

func init() {
	SchemeBuilder.Register(&KeystoreRsa{}, &KeystoreRsaList{})
}