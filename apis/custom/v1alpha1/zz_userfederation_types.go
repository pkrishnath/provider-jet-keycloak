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

type UserFederationObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type UserFederationParameters struct {

	// +kubebuilder:validation:Optional
	CachePolicy *string `json:"cachePolicy,omitempty" tf:"cache_policy,omitempty"`

	// How frequently Keycloak should sync changed users, in seconds. Omit this property to disable periodic changed users sync.
	// +kubebuilder:validation:Optional
	ChangedSyncPeriod *float64 `json:"changedSyncPeriod,omitempty" tf:"changed_sync_period,omitempty"`

	// +kubebuilder:validation:Optional
	Config map[string]*string `json:"config,omitempty" tf:"config,omitempty"`

	// When false, this provider will not be used when performing queries for users.
	// +kubebuilder:validation:Optional
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// How frequently Keycloak should sync all users, in seconds. Omit this property to disable periodic full sync.
	// +kubebuilder:validation:Optional
	FullSyncPeriod *float64 `json:"fullSyncPeriod,omitempty" tf:"full_sync_period,omitempty"`

	// The parent_id of the generated component. will use realm_id if not specified.
	// +kubebuilder:validation:Optional
	ParentID *string `json:"parentId,omitempty" tf:"parent_id,omitempty"`

	// Priority of this provider when looking up users. Lower values are first.
	// +kubebuilder:validation:Optional
	Priority *float64 `json:"priority,omitempty" tf:"priority,omitempty"`

	// The unique ID of the custom provider, specified in the `getId` implementation for the UserStorageProviderFactory interface
	// +kubebuilder:validation:Required
	ProviderID *string `json:"providerId" tf:"provider_id,omitempty"`

	// The realm (name) this provider will provide user federation for.
	// +kubebuilder:validation:Required
	RealmID *string `json:"realmId" tf:"realm_id,omitempty"`
}

// UserFederationSpec defines the desired state of UserFederation
type UserFederationSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     UserFederationParameters `json:"forProvider"`
}

// UserFederationStatus defines the observed state of UserFederation.
type UserFederationStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        UserFederationObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// UserFederation is the Schema for the UserFederations API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloakjet}
type UserFederation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              UserFederationSpec   `json:"spec"`
	Status            UserFederationStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// UserFederationList contains a list of UserFederations
type UserFederationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []UserFederation `json:"items"`
}

// Repository type metadata.
var (
	UserFederation_Kind             = "UserFederation"
	UserFederation_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: UserFederation_Kind}.String()
	UserFederation_KindAPIVersion   = UserFederation_Kind + "." + CRDGroupVersion.String()
	UserFederation_GroupVersionKind = CRDGroupVersion.WithKind(UserFederation_Kind)
)

func init() {
	SchemeBuilder.Register(&UserFederation{}, &UserFederationList{})
}