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

package controller

import (
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/crossplane/terrajet/pkg/controller"

	importeridentityprovidermapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/attribute/importeridentityprovidermapper"
	toroleidentityprovidermapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/attribute/toroleidentityprovidermapper"
	bindings "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/authentication/bindings"
	execution "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/authentication/execution"
	executionconfig "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/authentication/executionconfig"
	flow "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/authentication/flow"
	subflow "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/authentication/subflow"
	identityprovidermapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/custom/identityprovidermapper"
	userfederation "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/custom/userfederation"
	groups "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/default/groups"
	roles "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/default/roles"
	clientprotocolmapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/generic/clientprotocolmapper"
	clientrolemapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/generic/clientrolemapper"
	memberships "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/group/memberships"
	permissions "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/group/permissions"
	rolesgroup "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/group/roles"
	attributeidentityprovidermapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/hardcoded/attributeidentityprovidermapper"
	roleidentityprovidermapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/hardcoded/roleidentityprovidermapper"
	providertokenexchangescopepermission "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/identity/providertokenexchangescopepermission"
	group "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/keycloak/group"
	realm "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/keycloak/realm"
	role "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/keycloak/role"
	user "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/keycloak/user"
	fullnamemapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/ldap/fullnamemapper"
	groupmapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/ldap/groupmapper"
	hardcodedgroupmapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/ldap/hardcodedgroupmapper"
	hardcodedrolemapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/ldap/hardcodedrolemapper"
	msadldsuseraccountcontrolmapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/ldap/msadldsuseraccountcontrolmapper"
	msaduseraccountcontrolmapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/ldap/msaduseraccountcontrolmapper"
	rolemapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/ldap/rolemapper"
	userattributemapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/ldap/userattributemapper"
	userfederationldap "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/ldap/userfederation"
	googleidentityprovider "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/oidc/googleidentityprovider"
	identityprovider "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/oidc/identityprovider"
	audienceprotocolmapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/audienceprotocolmapper"
	audienceresolveprotocolmapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/audienceresolveprotocolmapper"
	client "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/client"
	clientaggregatepolicy "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/clientaggregatepolicy"
	clientauthorizationpermission "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/clientauthorizationpermission"
	clientauthorizationresource "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/clientauthorizationresource"
	clientauthorizationscope "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/clientauthorizationscope"
	clientclientpolicy "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/clientclientpolicy"
	clientdefaultscopes "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/clientdefaultscopes"
	clientgrouppolicy "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/clientgrouppolicy"
	clientjspolicy "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/clientjspolicy"
	clientoptionalscopes "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/clientoptionalscopes"
	clientpermissions "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/clientpermissions"
	clientrolepolicy "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/clientrolepolicy"
	clientscope "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/clientscope"
	clientserviceaccountrealmrole "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/clientserviceaccountrealmrole"
	clientserviceaccountrole "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/clientserviceaccountrole"
	clienttimepolicy "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/clienttimepolicy"
	clientuserpolicy "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/clientuserpolicy"
	fullnameprotocolmapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/fullnameprotocolmapper"
	groupmembershipprotocolmapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/groupmembershipprotocolmapper"
	hardcodedclaimprotocolmapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/hardcodedclaimprotocolmapper"
	hardcodedroleprotocolmapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/hardcodedroleprotocolmapper"
	scriptprotocolmapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/scriptprotocolmapper"
	userattributeprotocolmapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/userattributeprotocolmapper"
	userclientroleprotocolmapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/userclientroleprotocolmapper"
	userpropertyprotocolmapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/userpropertyprotocolmapper"
	userrealmroleprotocolmapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/userrealmroleprotocolmapper"
	usersessionnoteprotocolmapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/openid/usersessionnoteprotocolmapper"
	providerconfig "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/providerconfig"
	events "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/realm/events"
	keystoreaesgenerated "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/realm/keystoreaesgenerated"
	keystoreecdsagenerated "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/realm/keystoreecdsagenerated"
	keystorehmacgenerated "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/realm/keystorehmacgenerated"
	keystorejavakeystore "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/realm/keystorejavakeystore"
	keystorersa "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/realm/keystorersa"
	keystorersagenerated "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/realm/keystorersagenerated"
	userprofile "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/realm/userprofile"
	action "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/required/action"
	clientsaml "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/saml/client"
	clientdefaultscopessaml "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/saml/clientdefaultscopes"
	clientscopesaml "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/saml/clientscope"
	identityprovidersaml "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/saml/identityprovider"
	scriptprotocolmappersaml "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/saml/scriptprotocolmapper"
	userattributeprotocolmappersaml "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/saml/userattributeprotocolmapper"
	userpropertyprotocolmappersaml "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/saml/userpropertyprotocolmapper"
	groupsuser "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/user/groups"
	rolesuser "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/user/roles"
	templateimporteridentityprovidermapper "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/user/templateimporteridentityprovidermapper"
	permissionsusers "github.com/crossplane-contrib/provider-jet-keycloak/internal/controller/users/permissions"
)

// Setup creates all controllers with the supplied logger and adds them to
// the supplied manager.
func Setup(mgr ctrl.Manager, o controller.Options) error {
	for _, setup := range []func(ctrl.Manager, controller.Options) error{
		importeridentityprovidermapper.Setup,
		toroleidentityprovidermapper.Setup,
		bindings.Setup,
		execution.Setup,
		executionconfig.Setup,
		flow.Setup,
		subflow.Setup,
		identityprovidermapper.Setup,
		userfederation.Setup,
		groups.Setup,
		roles.Setup,
		clientprotocolmapper.Setup,
		clientrolemapper.Setup,
		memberships.Setup,
		permissions.Setup,
		rolesgroup.Setup,
		attributeidentityprovidermapper.Setup,
		roleidentityprovidermapper.Setup,
		providertokenexchangescopepermission.Setup,
		group.Setup,
		realm.Setup,
		role.Setup,
		user.Setup,
		fullnamemapper.Setup,
		groupmapper.Setup,
		hardcodedgroupmapper.Setup,
		hardcodedrolemapper.Setup,
		msadldsuseraccountcontrolmapper.Setup,
		msaduseraccountcontrolmapper.Setup,
		rolemapper.Setup,
		userattributemapper.Setup,
		userfederationldap.Setup,
		googleidentityprovider.Setup,
		identityprovider.Setup,
		audienceprotocolmapper.Setup,
		audienceresolveprotocolmapper.Setup,
		client.Setup,
		clientaggregatepolicy.Setup,
		clientauthorizationpermission.Setup,
		clientauthorizationresource.Setup,
		clientauthorizationscope.Setup,
		clientclientpolicy.Setup,
		clientdefaultscopes.Setup,
		clientgrouppolicy.Setup,
		clientjspolicy.Setup,
		clientoptionalscopes.Setup,
		clientpermissions.Setup,
		clientrolepolicy.Setup,
		clientscope.Setup,
		clientserviceaccountrealmrole.Setup,
		clientserviceaccountrole.Setup,
		clienttimepolicy.Setup,
		clientuserpolicy.Setup,
		fullnameprotocolmapper.Setup,
		groupmembershipprotocolmapper.Setup,
		hardcodedclaimprotocolmapper.Setup,
		hardcodedroleprotocolmapper.Setup,
		scriptprotocolmapper.Setup,
		userattributeprotocolmapper.Setup,
		userclientroleprotocolmapper.Setup,
		userpropertyprotocolmapper.Setup,
		userrealmroleprotocolmapper.Setup,
		usersessionnoteprotocolmapper.Setup,
		providerconfig.Setup,
		events.Setup,
		keystoreaesgenerated.Setup,
		keystoreecdsagenerated.Setup,
		keystorehmacgenerated.Setup,
		keystorejavakeystore.Setup,
		keystorersa.Setup,
		keystorersagenerated.Setup,
		userprofile.Setup,
		action.Setup,
		clientsaml.Setup,
		clientdefaultscopessaml.Setup,
		clientscopesaml.Setup,
		identityprovidersaml.Setup,
		scriptprotocolmappersaml.Setup,
		userattributeprotocolmappersaml.Setup,
		userpropertyprotocolmappersaml.Setup,
		groupsuser.Setup,
		rolesuser.Setup,
		templateimporteridentityprovidermapper.Setup,
		permissionsusers.Setup,
	} {
		if err := setup(mgr, o); err != nil {
			return err
		}
	}
	return nil
}
