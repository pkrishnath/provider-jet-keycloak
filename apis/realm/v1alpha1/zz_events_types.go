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

type EventsObservation struct {
	ID *string `json:"id,omitempty" tf:"id,omitempty"`
}

type EventsParameters struct {

	// +kubebuilder:validation:Optional
	AdminEventsDetailsEnabled *bool `json:"adminEventsDetailsEnabled,omitempty" tf:"admin_events_details_enabled,omitempty"`

	// +kubebuilder:validation:Optional
	AdminEventsEnabled *bool `json:"adminEventsEnabled,omitempty" tf:"admin_events_enabled,omitempty"`

	// +kubebuilder:validation:Optional
	EnabledEventTypes []*string `json:"enabledEventTypes,omitempty" tf:"enabled_event_types,omitempty"`

	// +kubebuilder:validation:Optional
	EventsEnabled *bool `json:"eventsEnabled,omitempty" tf:"events_enabled,omitempty"`

	// +kubebuilder:validation:Optional
	EventsExpiration *float64 `json:"eventsExpiration,omitempty" tf:"events_expiration,omitempty"`

	// +kubebuilder:validation:Optional
	EventsListeners []*string `json:"eventsListeners,omitempty" tf:"events_listeners,omitempty"`

	// +kubebuilder:validation:Required
	RealmID *string `json:"realmId" tf:"realm_id,omitempty"`
}

// EventsSpec defines the desired state of Events
type EventsSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     EventsParameters `json:"forProvider"`
}

// EventsStatus defines the observed state of Events.
type EventsStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        EventsObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// Events is the Schema for the Eventss API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloakjet}
type Events struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              EventsSpec   `json:"spec"`
	Status            EventsStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// EventsList contains a list of Eventss
type EventsList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Events `json:"items"`
}

// Repository type metadata.
var (
	Events_Kind             = "Events"
	Events_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: Events_Kind}.String()
	Events_KindAPIVersion   = Events_Kind + "." + CRDGroupVersion.String()
	Events_GroupVersionKind = CRDGroupVersion.WithKind(Events_Kind)
)

func init() {
	SchemeBuilder.Register(&Events{}, &EventsList{})
}
