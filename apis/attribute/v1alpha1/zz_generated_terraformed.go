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

// GetTerraformResourceType returns Terraform resource type for this ImporterIdentityProviderMapper
func (mg *ImporterIdentityProviderMapper) GetTerraformResourceType() string {
	return "keycloak_attribute_importer_identity_provider_mapper"
}

// GetConnectionDetailsMapping for this ImporterIdentityProviderMapper
func (tr *ImporterIdentityProviderMapper) GetConnectionDetailsMapping() map[string]string {
	return nil
}

// GetObservation of this ImporterIdentityProviderMapper
func (tr *ImporterIdentityProviderMapper) GetObservation() (map[string]interface{}, error) {
	o, err := json.TFParser.Marshal(tr.Status.AtProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(o, &base)
}

// SetObservation for this ImporterIdentityProviderMapper
func (tr *ImporterIdentityProviderMapper) SetObservation(obs map[string]interface{}) error {
	p, err := json.TFParser.Marshal(obs)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Status.AtProvider)
}

// GetID returns ID of underlying Terraform resource of this ImporterIdentityProviderMapper
func (tr *ImporterIdentityProviderMapper) GetID() string {
	if tr.Status.AtProvider.ID == nil {
		return ""
	}
	return *tr.Status.AtProvider.ID
}

// GetParameters of this ImporterIdentityProviderMapper
func (tr *ImporterIdentityProviderMapper) GetParameters() (map[string]interface{}, error) {
	p, err := json.TFParser.Marshal(tr.Spec.ForProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(p, &base)
}

// SetParameters for this ImporterIdentityProviderMapper
func (tr *ImporterIdentityProviderMapper) SetParameters(params map[string]interface{}) error {
	p, err := json.TFParser.Marshal(params)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Spec.ForProvider)
}

// LateInitialize this ImporterIdentityProviderMapper using its observed tfState.
// returns True if there are any spec changes for the resource.
func (tr *ImporterIdentityProviderMapper) LateInitialize(attrs []byte) (bool, error) {
	params := &ImporterIdentityProviderMapperParameters{}
	if err := json.TFParser.Unmarshal(attrs, params); err != nil {
		return false, errors.Wrap(err, "failed to unmarshal Terraform state parameters for late-initialization")
	}
	opts := []resource.GenericLateInitializerOption{resource.WithZeroValueJSONOmitEmptyFilter(resource.CNameWildcard)}

	li := resource.NewGenericLateInitializer(opts...)
	return li.LateInitialize(&tr.Spec.ForProvider, params)
}

// GetTerraformSchemaVersion returns the associated Terraform schema version
func (tr *ImporterIdentityProviderMapper) GetTerraformSchemaVersion() int {
	return 0
}

// GetTerraformResourceType returns Terraform resource type for this ToRoleIdentityProviderMapper
func (mg *ToRoleIdentityProviderMapper) GetTerraformResourceType() string {
	return "keycloak_attribute_to_role_identity_provider_mapper"
}

// GetConnectionDetailsMapping for this ToRoleIdentityProviderMapper
func (tr *ToRoleIdentityProviderMapper) GetConnectionDetailsMapping() map[string]string {
	return nil
}

// GetObservation of this ToRoleIdentityProviderMapper
func (tr *ToRoleIdentityProviderMapper) GetObservation() (map[string]interface{}, error) {
	o, err := json.TFParser.Marshal(tr.Status.AtProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(o, &base)
}

// SetObservation for this ToRoleIdentityProviderMapper
func (tr *ToRoleIdentityProviderMapper) SetObservation(obs map[string]interface{}) error {
	p, err := json.TFParser.Marshal(obs)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Status.AtProvider)
}

// GetID returns ID of underlying Terraform resource of this ToRoleIdentityProviderMapper
func (tr *ToRoleIdentityProviderMapper) GetID() string {
	if tr.Status.AtProvider.ID == nil {
		return ""
	}
	return *tr.Status.AtProvider.ID
}

// GetParameters of this ToRoleIdentityProviderMapper
func (tr *ToRoleIdentityProviderMapper) GetParameters() (map[string]interface{}, error) {
	p, err := json.TFParser.Marshal(tr.Spec.ForProvider)
	if err != nil {
		return nil, err
	}
	base := map[string]interface{}{}
	return base, json.TFParser.Unmarshal(p, &base)
}

// SetParameters for this ToRoleIdentityProviderMapper
func (tr *ToRoleIdentityProviderMapper) SetParameters(params map[string]interface{}) error {
	p, err := json.TFParser.Marshal(params)
	if err != nil {
		return err
	}
	return json.TFParser.Unmarshal(p, &tr.Spec.ForProvider)
}

// LateInitialize this ToRoleIdentityProviderMapper using its observed tfState.
// returns True if there are any spec changes for the resource.
func (tr *ToRoleIdentityProviderMapper) LateInitialize(attrs []byte) (bool, error) {
	params := &ToRoleIdentityProviderMapperParameters{}
	if err := json.TFParser.Unmarshal(attrs, params); err != nil {
		return false, errors.Wrap(err, "failed to unmarshal Terraform state parameters for late-initialization")
	}
	opts := []resource.GenericLateInitializerOption{resource.WithZeroValueJSONOmitEmptyFilter(resource.CNameWildcard)}

	li := resource.NewGenericLateInitializer(opts...)
	return li.LateInitialize(&tr.Spec.ForProvider, params)
}

// GetTerraformSchemaVersion returns the associated Terraform schema version
func (tr *ToRoleIdentityProviderMapper) GetTerraformSchemaVersion() int {
	return 0
}
