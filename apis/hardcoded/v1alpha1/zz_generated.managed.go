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
// Code generated by angryjet. DO NOT EDIT.

package v1alpha1

import xpv1 "github.com/crossplane/crossplane-runtime/apis/common/v1"

// GetCondition of this AttributeIdentityProviderMapper.
func (mg *AttributeIdentityProviderMapper) GetCondition(ct xpv1.ConditionType) xpv1.Condition {
	return mg.Status.GetCondition(ct)
}

// GetDeletionPolicy of this AttributeIdentityProviderMapper.
func (mg *AttributeIdentityProviderMapper) GetDeletionPolicy() xpv1.DeletionPolicy {
	return mg.Spec.DeletionPolicy
}

// GetProviderConfigReference of this AttributeIdentityProviderMapper.
func (mg *AttributeIdentityProviderMapper) GetProviderConfigReference() *xpv1.Reference {
	return mg.Spec.ProviderConfigReference
}

/*
GetProviderReference of this AttributeIdentityProviderMapper.
Deprecated: Use GetProviderConfigReference.
*/
func (mg *AttributeIdentityProviderMapper) GetProviderReference() *xpv1.Reference {
	return mg.Spec.ProviderReference
}

// GetPublishConnectionDetailsTo of this AttributeIdentityProviderMapper.
func (mg *AttributeIdentityProviderMapper) GetPublishConnectionDetailsTo() *xpv1.PublishConnectionDetailsTo {
	return mg.Spec.PublishConnectionDetailsTo
}

// GetWriteConnectionSecretToReference of this AttributeIdentityProviderMapper.
func (mg *AttributeIdentityProviderMapper) GetWriteConnectionSecretToReference() *xpv1.SecretReference {
	return mg.Spec.WriteConnectionSecretToReference
}

// SetConditions of this AttributeIdentityProviderMapper.
func (mg *AttributeIdentityProviderMapper) SetConditions(c ...xpv1.Condition) {
	mg.Status.SetConditions(c...)
}

// SetDeletionPolicy of this AttributeIdentityProviderMapper.
func (mg *AttributeIdentityProviderMapper) SetDeletionPolicy(r xpv1.DeletionPolicy) {
	mg.Spec.DeletionPolicy = r
}

// SetProviderConfigReference of this AttributeIdentityProviderMapper.
func (mg *AttributeIdentityProviderMapper) SetProviderConfigReference(r *xpv1.Reference) {
	mg.Spec.ProviderConfigReference = r
}

/*
SetProviderReference of this AttributeIdentityProviderMapper.
Deprecated: Use SetProviderConfigReference.
*/
func (mg *AttributeIdentityProviderMapper) SetProviderReference(r *xpv1.Reference) {
	mg.Spec.ProviderReference = r
}

// SetPublishConnectionDetailsTo of this AttributeIdentityProviderMapper.
func (mg *AttributeIdentityProviderMapper) SetPublishConnectionDetailsTo(r *xpv1.PublishConnectionDetailsTo) {
	mg.Spec.PublishConnectionDetailsTo = r
}

// SetWriteConnectionSecretToReference of this AttributeIdentityProviderMapper.
func (mg *AttributeIdentityProviderMapper) SetWriteConnectionSecretToReference(r *xpv1.SecretReference) {
	mg.Spec.WriteConnectionSecretToReference = r
}

// GetCondition of this RoleIdentityProviderMapper.
func (mg *RoleIdentityProviderMapper) GetCondition(ct xpv1.ConditionType) xpv1.Condition {
	return mg.Status.GetCondition(ct)
}

// GetDeletionPolicy of this RoleIdentityProviderMapper.
func (mg *RoleIdentityProviderMapper) GetDeletionPolicy() xpv1.DeletionPolicy {
	return mg.Spec.DeletionPolicy
}

// GetProviderConfigReference of this RoleIdentityProviderMapper.
func (mg *RoleIdentityProviderMapper) GetProviderConfigReference() *xpv1.Reference {
	return mg.Spec.ProviderConfigReference
}

/*
GetProviderReference of this RoleIdentityProviderMapper.
Deprecated: Use GetProviderConfigReference.
*/
func (mg *RoleIdentityProviderMapper) GetProviderReference() *xpv1.Reference {
	return mg.Spec.ProviderReference
}

// GetPublishConnectionDetailsTo of this RoleIdentityProviderMapper.
func (mg *RoleIdentityProviderMapper) GetPublishConnectionDetailsTo() *xpv1.PublishConnectionDetailsTo {
	return mg.Spec.PublishConnectionDetailsTo
}

// GetWriteConnectionSecretToReference of this RoleIdentityProviderMapper.
func (mg *RoleIdentityProviderMapper) GetWriteConnectionSecretToReference() *xpv1.SecretReference {
	return mg.Spec.WriteConnectionSecretToReference
}

// SetConditions of this RoleIdentityProviderMapper.
func (mg *RoleIdentityProviderMapper) SetConditions(c ...xpv1.Condition) {
	mg.Status.SetConditions(c...)
}

// SetDeletionPolicy of this RoleIdentityProviderMapper.
func (mg *RoleIdentityProviderMapper) SetDeletionPolicy(r xpv1.DeletionPolicy) {
	mg.Spec.DeletionPolicy = r
}

// SetProviderConfigReference of this RoleIdentityProviderMapper.
func (mg *RoleIdentityProviderMapper) SetProviderConfigReference(r *xpv1.Reference) {
	mg.Spec.ProviderConfigReference = r
}

/*
SetProviderReference of this RoleIdentityProviderMapper.
Deprecated: Use SetProviderConfigReference.
*/
func (mg *RoleIdentityProviderMapper) SetProviderReference(r *xpv1.Reference) {
	mg.Spec.ProviderReference = r
}

// SetPublishConnectionDetailsTo of this RoleIdentityProviderMapper.
func (mg *RoleIdentityProviderMapper) SetPublishConnectionDetailsTo(r *xpv1.PublishConnectionDetailsTo) {
	mg.Spec.PublishConnectionDetailsTo = r
}

// SetWriteConnectionSecretToReference of this RoleIdentityProviderMapper.
func (mg *RoleIdentityProviderMapper) SetWriteConnectionSecretToReference(r *xpv1.SecretReference) {
	mg.Spec.WriteConnectionSecretToReference = r
}