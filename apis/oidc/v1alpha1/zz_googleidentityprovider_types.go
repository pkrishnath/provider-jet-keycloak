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

type GoogleIdentityProviderObservation struct {
	Alias *string `json:"alias,omitempty" tf:"alias,omitempty"`

	DisplayName *string `json:"displayName,omitempty" tf:"display_name,omitempty"`

	ID *string `json:"id,omitempty" tf:"id,omitempty"`

	InternalID *string `json:"internalId,omitempty" tf:"internal_id,omitempty"`
}

type GoogleIdentityProviderParameters struct {

	// This is just used together with Identity Provider Authenticator or when kc_idp_hint points to this identity provider. In case that client sends a request with prompt=none and user is not yet authenticated, the error will not be directly returned to client, but the request with prompt=none will be forwarded to this identity provider.
	// +kubebuilder:validation:Optional
	AcceptsPromptNoneForwardFromClient *bool `json:"acceptsPromptNoneForwardFromClient,omitempty" tf:"accepts_prompt_none_forward_from_client,omitempty"`

	// Enable/disable if new users can read any stored tokens. This assigns the broker.read-token role.
	// +kubebuilder:validation:Optional
	AddReadTokenRoleOnCreate *bool `json:"addReadTokenRoleOnCreate,omitempty" tf:"add_read_token_role_on_create,omitempty"`

	// Enable/disable authenticate users by default.
	// +kubebuilder:validation:Optional
	AuthenticateByDefault *bool `json:"authenticateByDefault,omitempty" tf:"authenticate_by_default,omitempty"`

	// Client ID.
	// +kubebuilder:validation:Required
	ClientID *string `json:"clientId" tf:"client_id,omitempty"`

	// Client Secret.
	// +kubebuilder:validation:Required
	ClientSecretSecretRef v1.SecretKeySelector `json:"clientSecretSecretRef" tf:"-"`

	// The scopes to be sent when asking for authorization. See the documentation for possible values, separator and default value'. Default: 'openid profile email'
	// +kubebuilder:validation:Optional
	DefaultScopes *string `json:"defaultScopes,omitempty" tf:"default_scopes,omitempty"`

	// Disable usage of User Info service to obtain additional user information?  Default is to use this OIDC service.
	// +kubebuilder:validation:Optional
	DisableUserInfo *bool `json:"disableUserInfo,omitempty" tf:"disable_user_info,omitempty"`

	// Enable/disable this identity provider.
	// +kubebuilder:validation:Optional
	Enabled *bool `json:"enabled,omitempty" tf:"enabled,omitempty"`

	// +kubebuilder:validation:Optional
	ExtraConfig map[string]*string `json:"extraConfig,omitempty" tf:"extra_config,omitempty"`

	// Alias of authentication flow, which is triggered after first login with this identity provider. Term 'First Login' means that there is not yet existing Keycloak account linked with the authenticated identity provider account.
	// +kubebuilder:validation:Optional
	FirstBrokerLoginFlowAlias *string `json:"firstBrokerLoginFlowAlias,omitempty" tf:"first_broker_login_flow_alias,omitempty"`

	// GUI Order
	// +kubebuilder:validation:Optional
	GuiOrder *string `json:"guiOrder,omitempty" tf:"gui_order,omitempty"`

	// Hide On Login Page.
	// +kubebuilder:validation:Optional
	HideOnLoginPage *bool `json:"hideOnLoginPage,omitempty" tf:"hide_on_login_page,omitempty"`

	// Set 'hd' query parameter when logging in with Google. Google will list accounts only for this domain. Keycloak validates that the returned identity token has a claim for this domain. When '*' is entered, any hosted account can be used.
	// +kubebuilder:validation:Optional
	HostedDomain *string `json:"hostedDomain,omitempty" tf:"hosted_domain,omitempty"`

	// If true, users cannot log in through this provider.  They can only link to this provider.  This is useful if you don't want to allow login from the provider, but want to integrate with a provider
	// +kubebuilder:validation:Optional
	LinkOnly *bool `json:"linkOnly,omitempty" tf:"link_only,omitempty"`

	// Alias of authentication flow, which is triggered after each login with this identity provider. Useful if you want additional verification of each user authenticated with this identity provider (for example OTP). Leave this empty if you don't want any additional authenticators to be triggered after login with this identity provider. Also note, that authenticator implementations must assume that user is already set in ClientSession as identity provider already set it.
	// +kubebuilder:validation:Optional
	PostBrokerLoginFlowAlias *string `json:"postBrokerLoginFlowAlias,omitempty" tf:"post_broker_login_flow_alias,omitempty"`

	// provider id, is always google, unless you have a extended custom implementation
	// +kubebuilder:validation:Optional
	ProviderID *string `json:"providerId,omitempty" tf:"provider_id,omitempty"`

	// Realm Name
	// +kubebuilder:validation:Required
	Realm *string `json:"realm" tf:"realm,omitempty"`

	// Set 'access_type' query parameter to 'offline' when redirecting to google authorization endpoint, to get a refresh token back. Useful if planning to use Token Exchange to retrieve Google token to access Google APIs when the user is not at the browser.
	// +kubebuilder:validation:Optional
	RequestRefreshToken *bool `json:"requestRefreshToken,omitempty" tf:"request_refresh_token,omitempty"`

	// Enable/disable if tokens must be stored after authenticating users.
	// +kubebuilder:validation:Optional
	StoreToken *bool `json:"storeToken,omitempty" tf:"store_token,omitempty"`

	// Sync Mode
	// +kubebuilder:validation:Optional
	SyncMode *string `json:"syncMode,omitempty" tf:"sync_mode,omitempty"`

	// If enabled then email provided by this provider is not verified even if verification is enabled for the realm.
	// +kubebuilder:validation:Optional
	TrustEmail *bool `json:"trustEmail,omitempty" tf:"trust_email,omitempty"`

	// Set 'userIp' query parameter when invoking on Google's User Info service.  This will use the user's ip address.  Useful if Google is throttling access to the User Info service.
	// +kubebuilder:validation:Optional
	UseUserIPParam *bool `json:"useUserIpParam,omitempty" tf:"use_user_ip_param,omitempty"`
}

// GoogleIdentityProviderSpec defines the desired state of GoogleIdentityProvider
type GoogleIdentityProviderSpec struct {
	v1.ResourceSpec `json:",inline"`
	ForProvider     GoogleIdentityProviderParameters `json:"forProvider"`
}

// GoogleIdentityProviderStatus defines the observed state of GoogleIdentityProvider.
type GoogleIdentityProviderStatus struct {
	v1.ResourceStatus `json:",inline"`
	AtProvider        GoogleIdentityProviderObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// GoogleIdentityProvider is the Schema for the GoogleIdentityProviders API
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="EXTERNAL-NAME",type="string",JSONPath=".metadata.annotations.crossplane\\.io/external-name"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Cluster,categories={crossplane,managed,keycloakjet}
type GoogleIdentityProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              GoogleIdentityProviderSpec   `json:"spec"`
	Status            GoogleIdentityProviderStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GoogleIdentityProviderList contains a list of GoogleIdentityProviders
type GoogleIdentityProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GoogleIdentityProvider `json:"items"`
}

// Repository type metadata.
var (
	GoogleIdentityProvider_Kind             = "GoogleIdentityProvider"
	GoogleIdentityProvider_GroupKind        = schema.GroupKind{Group: CRDGroup, Kind: GoogleIdentityProvider_Kind}.String()
	GoogleIdentityProvider_KindAPIVersion   = GoogleIdentityProvider_Kind + "." + CRDGroupVersion.String()
	GoogleIdentityProvider_GroupVersionKind = CRDGroupVersion.WithKind(GoogleIdentityProvider_Kind)
)

func init() {
	SchemeBuilder.Register(&GoogleIdentityProvider{}, &GoogleIdentityProviderList{})
}
