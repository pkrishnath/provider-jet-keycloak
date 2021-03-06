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
	"github.com/pkg/errors"

	"github.com/crossplane/terrajet/pkg/resource"
	"github.com/crossplane/terrajet/pkg/resource/json"
)

// GetTerraformResourceType returns Terraform resource type for this FullNameMapper
func (mg *FullNameMapper) GetTerraformResourceType() string {
	return "keycloak_ldap_full_name_mapper"
}

// GetConnectionDetailsMapping for this FullNameMapper
func (tr *FullNameMapper) GetConnectionDetailsMapping() map[string]string {
	return nil
}

// GetObservation of this FullNameMapper
func (tr *FullNameMapper) GetObservation() (map[string]interface{}, error) {
	o, err := json.TFParser.Marshal(tr.Status.AtProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(o, &base)
}

// SetObservation for this FullNameMapper
func (tr *FullNameMapper) SetObservation(obs map[string]interface{}) error {
	p, err := json.TFParser.Marshal(obs)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Status.AtProvider)
}

// GetID returns ID of underlying Terraform resource of this FullNameMapper
func (tr *FullNameMapper) GetID() string {
	if tr.Status.AtProvider.ID == nil {
		return ""
	}
	return *tr.Status.AtProvider.ID
}

// GetParameters of this FullNameMapper
func (tr *FullNameMapper) GetParameters() (map[string]interface{}, error) {
	p, err := json.TFParser.Marshal(tr.Spec.ForProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(p, &base)
}

// SetParameters for this FullNameMapper
func (tr *FullNameMapper) SetParameters(params map[string]interface{}) error {
	p, err := json.TFParser.Marshal(params)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Spec.ForProvider)
}

// LateInitialize this FullNameMapper using its observed tfState.
// returns True if there are any spec changes for the resource.
func (tr *FullNameMapper) LateInitialize(attrs []byte) (bool, error) {
	params := &FullNameMapperParameters{}
	if err := json.TFParser.Unmarshal(attrs, params); err != nil {
		return false, errors.Wrap(err, "failed to unmarshal Terraform state parameters for late-initialization")
	}
	opts := []resource.GenericLateInitializerOption{resource.WithZeroValueJSONOmitEmptyFilter(resource.CNameWildcard)}

	li := resource.NewGenericLateInitializer(opts...)
	return li.LateInitialize(&tr.Spec.ForProvider, params)
}

// GetTerraformSchemaVersion returns the associated Terraform schema version
func (tr *FullNameMapper) GetTerraformSchemaVersion() int {
	return 0
}

// GetTerraformResourceType returns Terraform resource type for this GroupMapper
func (mg *GroupMapper) GetTerraformResourceType() string {
	return "keycloak_ldap_group_mapper"
}

// GetConnectionDetailsMapping for this GroupMapper
func (tr *GroupMapper) GetConnectionDetailsMapping() map[string]string {
	return nil
}

// GetObservation of this GroupMapper
func (tr *GroupMapper) GetObservation() (map[string]interface{}, error) {
	o, err := json.TFParser.Marshal(tr.Status.AtProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(o, &base)
}

// SetObservation for this GroupMapper
func (tr *GroupMapper) SetObservation(obs map[string]interface{}) error {
	p, err := json.TFParser.Marshal(obs)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Status.AtProvider)
}

// GetID returns ID of underlying Terraform resource of this GroupMapper
func (tr *GroupMapper) GetID() string {
	if tr.Status.AtProvider.ID == nil {
		return ""
	}
	return *tr.Status.AtProvider.ID
}

// GetParameters of this GroupMapper
func (tr *GroupMapper) GetParameters() (map[string]interface{}, error) {
	p, err := json.TFParser.Marshal(tr.Spec.ForProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(p, &base)
}

// SetParameters for this GroupMapper
func (tr *GroupMapper) SetParameters(params map[string]interface{}) error {
	p, err := json.TFParser.Marshal(params)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Spec.ForProvider)
}

// LateInitialize this GroupMapper using its observed tfState.
// returns True if there are any spec changes for the resource.
func (tr *GroupMapper) LateInitialize(attrs []byte) (bool, error) {
	params := &GroupMapperParameters{}
	if err := json.TFParser.Unmarshal(attrs, params); err != nil {
		return false, errors.Wrap(err, "failed to unmarshal Terraform state parameters for late-initialization")
	}
	opts := []resource.GenericLateInitializerOption{resource.WithZeroValueJSONOmitEmptyFilter(resource.CNameWildcard)}

	li := resource.NewGenericLateInitializer(opts...)
	return li.LateInitialize(&tr.Spec.ForProvider, params)
}

// GetTerraformSchemaVersion returns the associated Terraform schema version
func (tr *GroupMapper) GetTerraformSchemaVersion() int {
	return 0
}

// GetTerraformResourceType returns Terraform resource type for this HardcodedGroupMapper
func (mg *HardcodedGroupMapper) GetTerraformResourceType() string {
	return "keycloak_ldap_hardcoded_group_mapper"
}

// GetConnectionDetailsMapping for this HardcodedGroupMapper
func (tr *HardcodedGroupMapper) GetConnectionDetailsMapping() map[string]string {
	return nil
}

// GetObservation of this HardcodedGroupMapper
func (tr *HardcodedGroupMapper) GetObservation() (map[string]interface{}, error) {
	o, err := json.TFParser.Marshal(tr.Status.AtProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(o, &base)
}

// SetObservation for this HardcodedGroupMapper
func (tr *HardcodedGroupMapper) SetObservation(obs map[string]interface{}) error {
	p, err := json.TFParser.Marshal(obs)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Status.AtProvider)
}

// GetID returns ID of underlying Terraform resource of this HardcodedGroupMapper
func (tr *HardcodedGroupMapper) GetID() string {
	if tr.Status.AtProvider.ID == nil {
		return ""
	}
	return *tr.Status.AtProvider.ID
}

// GetParameters of this HardcodedGroupMapper
func (tr *HardcodedGroupMapper) GetParameters() (map[string]interface{}, error) {
	p, err := json.TFParser.Marshal(tr.Spec.ForProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(p, &base)
}

// SetParameters for this HardcodedGroupMapper
func (tr *HardcodedGroupMapper) SetParameters(params map[string]interface{}) error {
	p, err := json.TFParser.Marshal(params)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Spec.ForProvider)
}

// LateInitialize this HardcodedGroupMapper using its observed tfState.
// returns True if there are any spec changes for the resource.
func (tr *HardcodedGroupMapper) LateInitialize(attrs []byte) (bool, error) {
	params := &HardcodedGroupMapperParameters{}
	if err := json.TFParser.Unmarshal(attrs, params); err != nil {
		return false, errors.Wrap(err, "failed to unmarshal Terraform state parameters for late-initialization")
	}
	opts := []resource.GenericLateInitializerOption{resource.WithZeroValueJSONOmitEmptyFilter(resource.CNameWildcard)}

	li := resource.NewGenericLateInitializer(opts...)
	return li.LateInitialize(&tr.Spec.ForProvider, params)
}

// GetTerraformSchemaVersion returns the associated Terraform schema version
func (tr *HardcodedGroupMapper) GetTerraformSchemaVersion() int {
	return 0
}

// GetTerraformResourceType returns Terraform resource type for this HardcodedRoleMapper
func (mg *HardcodedRoleMapper) GetTerraformResourceType() string {
	return "keycloak_ldap_hardcoded_role_mapper"
}

// GetConnectionDetailsMapping for this HardcodedRoleMapper
func (tr *HardcodedRoleMapper) GetConnectionDetailsMapping() map[string]string {
	return nil
}

// GetObservation of this HardcodedRoleMapper
func (tr *HardcodedRoleMapper) GetObservation() (map[string]interface{}, error) {
	o, err := json.TFParser.Marshal(tr.Status.AtProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(o, &base)
}

// SetObservation for this HardcodedRoleMapper
func (tr *HardcodedRoleMapper) SetObservation(obs map[string]interface{}) error {
	p, err := json.TFParser.Marshal(obs)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Status.AtProvider)
}

// GetID returns ID of underlying Terraform resource of this HardcodedRoleMapper
func (tr *HardcodedRoleMapper) GetID() string {
	if tr.Status.AtProvider.ID == nil {
		return ""
	}
	return *tr.Status.AtProvider.ID
}

// GetParameters of this HardcodedRoleMapper
func (tr *HardcodedRoleMapper) GetParameters() (map[string]interface{}, error) {
	p, err := json.TFParser.Marshal(tr.Spec.ForProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(p, &base)
}

// SetParameters for this HardcodedRoleMapper
func (tr *HardcodedRoleMapper) SetParameters(params map[string]interface{}) error {
	p, err := json.TFParser.Marshal(params)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Spec.ForProvider)
}

// LateInitialize this HardcodedRoleMapper using its observed tfState.
// returns True if there are any spec changes for the resource.
func (tr *HardcodedRoleMapper) LateInitialize(attrs []byte) (bool, error) {
	params := &HardcodedRoleMapperParameters{}
	if err := json.TFParser.Unmarshal(attrs, params); err != nil {
		return false, errors.Wrap(err, "failed to unmarshal Terraform state parameters for late-initialization")
	}
	opts := []resource.GenericLateInitializerOption{resource.WithZeroValueJSONOmitEmptyFilter(resource.CNameWildcard)}

	li := resource.NewGenericLateInitializer(opts...)
	return li.LateInitialize(&tr.Spec.ForProvider, params)
}

// GetTerraformSchemaVersion returns the associated Terraform schema version
func (tr *HardcodedRoleMapper) GetTerraformSchemaVersion() int {
	return 0
}

// GetTerraformResourceType returns Terraform resource type for this MsadLdsUserAccountControlMapper
func (mg *MsadLdsUserAccountControlMapper) GetTerraformResourceType() string {
	return "keycloak_ldap_msad_lds_user_account_control_mapper"
}

// GetConnectionDetailsMapping for this MsadLdsUserAccountControlMapper
func (tr *MsadLdsUserAccountControlMapper) GetConnectionDetailsMapping() map[string]string {
	return nil
}

// GetObservation of this MsadLdsUserAccountControlMapper
func (tr *MsadLdsUserAccountControlMapper) GetObservation() (map[string]interface{}, error) {
	o, err := json.TFParser.Marshal(tr.Status.AtProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(o, &base)
}

// SetObservation for this MsadLdsUserAccountControlMapper
func (tr *MsadLdsUserAccountControlMapper) SetObservation(obs map[string]interface{}) error {
	p, err := json.TFParser.Marshal(obs)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Status.AtProvider)
}

// GetID returns ID of underlying Terraform resource of this MsadLdsUserAccountControlMapper
func (tr *MsadLdsUserAccountControlMapper) GetID() string {
	if tr.Status.AtProvider.ID == nil {
		return ""
	}
	return *tr.Status.AtProvider.ID
}

// GetParameters of this MsadLdsUserAccountControlMapper
func (tr *MsadLdsUserAccountControlMapper) GetParameters() (map[string]interface{}, error) {
	p, err := json.TFParser.Marshal(tr.Spec.ForProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(p, &base)
}

// SetParameters for this MsadLdsUserAccountControlMapper
func (tr *MsadLdsUserAccountControlMapper) SetParameters(params map[string]interface{}) error {
	p, err := json.TFParser.Marshal(params)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Spec.ForProvider)
}

// LateInitialize this MsadLdsUserAccountControlMapper using its observed tfState.
// returns True if there are any spec changes for the resource.
func (tr *MsadLdsUserAccountControlMapper) LateInitialize(attrs []byte) (bool, error) {
	params := &MsadLdsUserAccountControlMapperParameters{}
	if err := json.TFParser.Unmarshal(attrs, params); err != nil {
		return false, errors.Wrap(err, "failed to unmarshal Terraform state parameters for late-initialization")
	}
	opts := []resource.GenericLateInitializerOption{resource.WithZeroValueJSONOmitEmptyFilter(resource.CNameWildcard)}

	li := resource.NewGenericLateInitializer(opts...)
	return li.LateInitialize(&tr.Spec.ForProvider, params)
}

// GetTerraformSchemaVersion returns the associated Terraform schema version
func (tr *MsadLdsUserAccountControlMapper) GetTerraformSchemaVersion() int {
	return 0
}

// GetTerraformResourceType returns Terraform resource type for this MsadUserAccountControlMapper
func (mg *MsadUserAccountControlMapper) GetTerraformResourceType() string {
	return "keycloak_ldap_msad_user_account_control_mapper"
}

// GetConnectionDetailsMapping for this MsadUserAccountControlMapper
func (tr *MsadUserAccountControlMapper) GetConnectionDetailsMapping() map[string]string {
	return nil
}

// GetObservation of this MsadUserAccountControlMapper
func (tr *MsadUserAccountControlMapper) GetObservation() (map[string]interface{}, error) {
	o, err := json.TFParser.Marshal(tr.Status.AtProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(o, &base)
}

// SetObservation for this MsadUserAccountControlMapper
func (tr *MsadUserAccountControlMapper) SetObservation(obs map[string]interface{}) error {
	p, err := json.TFParser.Marshal(obs)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Status.AtProvider)
}

// GetID returns ID of underlying Terraform resource of this MsadUserAccountControlMapper
func (tr *MsadUserAccountControlMapper) GetID() string {
	if tr.Status.AtProvider.ID == nil {
		return ""
	}
	return *tr.Status.AtProvider.ID
}

// GetParameters of this MsadUserAccountControlMapper
func (tr *MsadUserAccountControlMapper) GetParameters() (map[string]interface{}, error) {
	p, err := json.TFParser.Marshal(tr.Spec.ForProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(p, &base)
}

// SetParameters for this MsadUserAccountControlMapper
func (tr *MsadUserAccountControlMapper) SetParameters(params map[string]interface{}) error {
	p, err := json.TFParser.Marshal(params)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Spec.ForProvider)
}

// LateInitialize this MsadUserAccountControlMapper using its observed tfState.
// returns True if there are any spec changes for the resource.
func (tr *MsadUserAccountControlMapper) LateInitialize(attrs []byte) (bool, error) {
	params := &MsadUserAccountControlMapperParameters{}
	if err := json.TFParser.Unmarshal(attrs, params); err != nil {
		return false, errors.Wrap(err, "failed to unmarshal Terraform state parameters for late-initialization")
	}
	opts := []resource.GenericLateInitializerOption{resource.WithZeroValueJSONOmitEmptyFilter(resource.CNameWildcard)}

	li := resource.NewGenericLateInitializer(opts...)
	return li.LateInitialize(&tr.Spec.ForProvider, params)
}

// GetTerraformSchemaVersion returns the associated Terraform schema version
func (tr *MsadUserAccountControlMapper) GetTerraformSchemaVersion() int {
	return 0
}

// GetTerraformResourceType returns Terraform resource type for this RoleMapper
func (mg *RoleMapper) GetTerraformResourceType() string {
	return "keycloak_ldap_role_mapper"
}

// GetConnectionDetailsMapping for this RoleMapper
func (tr *RoleMapper) GetConnectionDetailsMapping() map[string]string {
	return nil
}

// GetObservation of this RoleMapper
func (tr *RoleMapper) GetObservation() (map[string]interface{}, error) {
	o, err := json.TFParser.Marshal(tr.Status.AtProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(o, &base)
}

// SetObservation for this RoleMapper
func (tr *RoleMapper) SetObservation(obs map[string]interface{}) error {
	p, err := json.TFParser.Marshal(obs)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Status.AtProvider)
}

// GetID returns ID of underlying Terraform resource of this RoleMapper
func (tr *RoleMapper) GetID() string {
	if tr.Status.AtProvider.ID == nil {
		return ""
	}
	return *tr.Status.AtProvider.ID
}

// GetParameters of this RoleMapper
func (tr *RoleMapper) GetParameters() (map[string]interface{}, error) {
	p, err := json.TFParser.Marshal(tr.Spec.ForProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(p, &base)
}

// SetParameters for this RoleMapper
func (tr *RoleMapper) SetParameters(params map[string]interface{}) error {
	p, err := json.TFParser.Marshal(params)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Spec.ForProvider)
}

// LateInitialize this RoleMapper using its observed tfState.
// returns True if there are any spec changes for the resource.
func (tr *RoleMapper) LateInitialize(attrs []byte) (bool, error) {
	params := &RoleMapperParameters{}
	if err := json.TFParser.Unmarshal(attrs, params); err != nil {
		return false, errors.Wrap(err, "failed to unmarshal Terraform state parameters for late-initialization")
	}
	opts := []resource.GenericLateInitializerOption{resource.WithZeroValueJSONOmitEmptyFilter(resource.CNameWildcard)}

	li := resource.NewGenericLateInitializer(opts...)
	return li.LateInitialize(&tr.Spec.ForProvider, params)
}

// GetTerraformSchemaVersion returns the associated Terraform schema version
func (tr *RoleMapper) GetTerraformSchemaVersion() int {
	return 0
}

// GetTerraformResourceType returns Terraform resource type for this UserAttributeMapper
func (mg *UserAttributeMapper) GetTerraformResourceType() string {
	return "keycloak_ldap_user_attribute_mapper"
}

// GetConnectionDetailsMapping for this UserAttributeMapper
func (tr *UserAttributeMapper) GetConnectionDetailsMapping() map[string]string {
	return nil
}

// GetObservation of this UserAttributeMapper
func (tr *UserAttributeMapper) GetObservation() (map[string]interface{}, error) {
	o, err := json.TFParser.Marshal(tr.Status.AtProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(o, &base)
}

// SetObservation for this UserAttributeMapper
func (tr *UserAttributeMapper) SetObservation(obs map[string]interface{}) error {
	p, err := json.TFParser.Marshal(obs)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Status.AtProvider)
}

// GetID returns ID of underlying Terraform resource of this UserAttributeMapper
func (tr *UserAttributeMapper) GetID() string {
	if tr.Status.AtProvider.ID == nil {
		return ""
	}
	return *tr.Status.AtProvider.ID
}

// GetParameters of this UserAttributeMapper
func (tr *UserAttributeMapper) GetParameters() (map[string]interface{}, error) {
	p, err := json.TFParser.Marshal(tr.Spec.ForProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(p, &base)
}

// SetParameters for this UserAttributeMapper
func (tr *UserAttributeMapper) SetParameters(params map[string]interface{}) error {
	p, err := json.TFParser.Marshal(params)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Spec.ForProvider)
}

// LateInitialize this UserAttributeMapper using its observed tfState.
// returns True if there are any spec changes for the resource.
func (tr *UserAttributeMapper) LateInitialize(attrs []byte) (bool, error) {
	params := &UserAttributeMapperParameters{}
	if err := json.TFParser.Unmarshal(attrs, params); err != nil {
		return false, errors.Wrap(err, "failed to unmarshal Terraform state parameters for late-initialization")
	}
	opts := []resource.GenericLateInitializerOption{resource.WithZeroValueJSONOmitEmptyFilter(resource.CNameWildcard)}

	li := resource.NewGenericLateInitializer(opts...)
	return li.LateInitialize(&tr.Spec.ForProvider, params)
}

// GetTerraformSchemaVersion returns the associated Terraform schema version
func (tr *UserAttributeMapper) GetTerraformSchemaVersion() int {
	return 0
}

// GetTerraformResourceType returns Terraform resource type for this UserFederation
func (mg *UserFederation) GetTerraformResourceType() string {
	return "keycloak_ldap_user_federation"
}

// GetConnectionDetailsMapping for this UserFederation
func (tr *UserFederation) GetConnectionDetailsMapping() map[string]string {
	return map[string]string{"bind_credential": "spec.forProvider.bindCredentialSecretRef"}
}

// GetObservation of this UserFederation
func (tr *UserFederation) GetObservation() (map[string]interface{}, error) {
	o, err := json.TFParser.Marshal(tr.Status.AtProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(o, &base)
}

// SetObservation for this UserFederation
func (tr *UserFederation) SetObservation(obs map[string]interface{}) error {
	p, err := json.TFParser.Marshal(obs)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Status.AtProvider)
}

// GetID returns ID of underlying Terraform resource of this UserFederation
func (tr *UserFederation) GetID() string {
	if tr.Status.AtProvider.ID == nil {
		return ""
	}
	return *tr.Status.AtProvider.ID
}

// GetParameters of this UserFederation
func (tr *UserFederation) GetParameters() (map[string]interface{}, error) {
	p, err := json.TFParser.Marshal(tr.Spec.ForProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(p, &base)
}

// SetParameters for this UserFederation
func (tr *UserFederation) SetParameters(params map[string]interface{}) error {
	p, err := json.TFParser.Marshal(params)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Spec.ForProvider)
}

// LateInitialize this UserFederation using its observed tfState.
// returns True if there are any spec changes for the resource.
func (tr *UserFederation) LateInitialize(attrs []byte) (bool, error) {
	params := &UserFederationParameters{}
	if err := json.TFParser.Unmarshal(attrs, params); err != nil {
		return false, errors.Wrap(err, "failed to unmarshal Terraform state parameters for late-initialization")
	}
	opts := []resource.GenericLateInitializerOption{resource.WithZeroValueJSONOmitEmptyFilter(resource.CNameWildcard)}

	li := resource.NewGenericLateInitializer(opts...)
	return li.LateInitialize(&tr.Spec.ForProvider, params)
}

// GetTerraformSchemaVersion returns the associated Terraform schema version
func (tr *UserFederation) GetTerraformSchemaVersion() int {
	return 0
}
