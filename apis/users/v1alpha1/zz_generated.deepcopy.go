//go:build !ignore_autogenerated
// +build !ignore_autogenerated

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

// Code generated by controller-gen. DO NOT EDIT.

package v1alpha1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImpersonateScopeObservation) DeepCopyInto(out *ImpersonateScopeObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImpersonateScopeObservation.
func (in *ImpersonateScopeObservation) DeepCopy() *ImpersonateScopeObservation {
	if in == nil {
		return nil
	}
	out := new(ImpersonateScopeObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ImpersonateScopeParameters) DeepCopyInto(out *ImpersonateScopeParameters) {
	*out = *in
	if in.DecisionStrategy != nil {
		in, out := &in.DecisionStrategy, &out.DecisionStrategy
		*out = new(string)
		**out = **in
	}
	if in.Description != nil {
		in, out := &in.Description, &out.Description
		*out = new(string)
		**out = **in
	}
	if in.Policies != nil {
		in, out := &in.Policies, &out.Policies
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ImpersonateScopeParameters.
func (in *ImpersonateScopeParameters) DeepCopy() *ImpersonateScopeParameters {
	if in == nil {
		return nil
	}
	out := new(ImpersonateScopeParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ManageGroupMembershipScopeObservation) DeepCopyInto(out *ManageGroupMembershipScopeObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ManageGroupMembershipScopeObservation.
func (in *ManageGroupMembershipScopeObservation) DeepCopy() *ManageGroupMembershipScopeObservation {
	if in == nil {
		return nil
	}
	out := new(ManageGroupMembershipScopeObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ManageGroupMembershipScopeParameters) DeepCopyInto(out *ManageGroupMembershipScopeParameters) {
	*out = *in
	if in.DecisionStrategy != nil {
		in, out := &in.DecisionStrategy, &out.DecisionStrategy
		*out = new(string)
		**out = **in
	}
	if in.Description != nil {
		in, out := &in.Description, &out.Description
		*out = new(string)
		**out = **in
	}
	if in.Policies != nil {
		in, out := &in.Policies, &out.Policies
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ManageGroupMembershipScopeParameters.
func (in *ManageGroupMembershipScopeParameters) DeepCopy() *ManageGroupMembershipScopeParameters {
	if in == nil {
		return nil
	}
	out := new(ManageGroupMembershipScopeParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ManageScopeObservation) DeepCopyInto(out *ManageScopeObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ManageScopeObservation.
func (in *ManageScopeObservation) DeepCopy() *ManageScopeObservation {
	if in == nil {
		return nil
	}
	out := new(ManageScopeObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ManageScopeParameters) DeepCopyInto(out *ManageScopeParameters) {
	*out = *in
	if in.DecisionStrategy != nil {
		in, out := &in.DecisionStrategy, &out.DecisionStrategy
		*out = new(string)
		**out = **in
	}
	if in.Description != nil {
		in, out := &in.Description, &out.Description
		*out = new(string)
		**out = **in
	}
	if in.Policies != nil {
		in, out := &in.Policies, &out.Policies
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ManageScopeParameters.
func (in *ManageScopeParameters) DeepCopy() *ManageScopeParameters {
	if in == nil {
		return nil
	}
	out := new(ManageScopeParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MapRolesScopeObservation) DeepCopyInto(out *MapRolesScopeObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MapRolesScopeObservation.
func (in *MapRolesScopeObservation) DeepCopy() *MapRolesScopeObservation {
	if in == nil {
		return nil
	}
	out := new(MapRolesScopeObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *MapRolesScopeParameters) DeepCopyInto(out *MapRolesScopeParameters) {
	*out = *in
	if in.DecisionStrategy != nil {
		in, out := &in.DecisionStrategy, &out.DecisionStrategy
		*out = new(string)
		**out = **in
	}
	if in.Description != nil {
		in, out := &in.Description, &out.Description
		*out = new(string)
		**out = **in
	}
	if in.Policies != nil {
		in, out := &in.Policies, &out.Policies
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new MapRolesScopeParameters.
func (in *MapRolesScopeParameters) DeepCopy() *MapRolesScopeParameters {
	if in == nil {
		return nil
	}
	out := new(MapRolesScopeParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *Permissions) DeepCopyInto(out *Permissions) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new Permissions.
func (in *Permissions) DeepCopy() *Permissions {
	if in == nil {
		return nil
	}
	out := new(Permissions)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *Permissions) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PermissionsList) DeepCopyInto(out *PermissionsList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]Permissions, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PermissionsList.
func (in *PermissionsList) DeepCopy() *PermissionsList {
	if in == nil {
		return nil
	}
	out := new(PermissionsList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *PermissionsList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PermissionsObservation) DeepCopyInto(out *PermissionsObservation) {
	*out = *in
	if in.AuthorizationResourceServerID != nil {
		in, out := &in.AuthorizationResourceServerID, &out.AuthorizationResourceServerID
		*out = new(string)
		**out = **in
	}
	if in.Enabled != nil {
		in, out := &in.Enabled, &out.Enabled
		*out = new(bool)
		**out = **in
	}
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PermissionsObservation.
func (in *PermissionsObservation) DeepCopy() *PermissionsObservation {
	if in == nil {
		return nil
	}
	out := new(PermissionsObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PermissionsParameters) DeepCopyInto(out *PermissionsParameters) {
	*out = *in
	if in.ImpersonateScope != nil {
		in, out := &in.ImpersonateScope, &out.ImpersonateScope
		*out = make([]ImpersonateScopeParameters, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.ManageGroupMembershipScope != nil {
		in, out := &in.ManageGroupMembershipScope, &out.ManageGroupMembershipScope
		*out = make([]ManageGroupMembershipScopeParameters, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.ManageScope != nil {
		in, out := &in.ManageScope, &out.ManageScope
		*out = make([]ManageScopeParameters, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.MapRolesScope != nil {
		in, out := &in.MapRolesScope, &out.MapRolesScope
		*out = make([]MapRolesScopeParameters, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.RealmID != nil {
		in, out := &in.RealmID, &out.RealmID
		*out = new(string)
		**out = **in
	}
	if in.UserImpersonatedScope != nil {
		in, out := &in.UserImpersonatedScope, &out.UserImpersonatedScope
		*out = make([]UserImpersonatedScopeParameters, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
	if in.ViewScope != nil {
		in, out := &in.ViewScope, &out.ViewScope
		*out = make([]ViewScopeParameters, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PermissionsParameters.
func (in *PermissionsParameters) DeepCopy() *PermissionsParameters {
	if in == nil {
		return nil
	}
	out := new(PermissionsParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PermissionsSpec) DeepCopyInto(out *PermissionsSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PermissionsSpec.
func (in *PermissionsSpec) DeepCopy() *PermissionsSpec {
	if in == nil {
		return nil
	}
	out := new(PermissionsSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PermissionsStatus) DeepCopyInto(out *PermissionsStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PermissionsStatus.
func (in *PermissionsStatus) DeepCopy() *PermissionsStatus {
	if in == nil {
		return nil
	}
	out := new(PermissionsStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UserImpersonatedScopeObservation) DeepCopyInto(out *UserImpersonatedScopeObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UserImpersonatedScopeObservation.
func (in *UserImpersonatedScopeObservation) DeepCopy() *UserImpersonatedScopeObservation {
	if in == nil {
		return nil
	}
	out := new(UserImpersonatedScopeObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UserImpersonatedScopeParameters) DeepCopyInto(out *UserImpersonatedScopeParameters) {
	*out = *in
	if in.DecisionStrategy != nil {
		in, out := &in.DecisionStrategy, &out.DecisionStrategy
		*out = new(string)
		**out = **in
	}
	if in.Description != nil {
		in, out := &in.Description, &out.Description
		*out = new(string)
		**out = **in
	}
	if in.Policies != nil {
		in, out := &in.Policies, &out.Policies
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UserImpersonatedScopeParameters.
func (in *UserImpersonatedScopeParameters) DeepCopy() *UserImpersonatedScopeParameters {
	if in == nil {
		return nil
	}
	out := new(UserImpersonatedScopeParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ViewScopeObservation) DeepCopyInto(out *ViewScopeObservation) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ViewScopeObservation.
func (in *ViewScopeObservation) DeepCopy() *ViewScopeObservation {
	if in == nil {
		return nil
	}
	out := new(ViewScopeObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *ViewScopeParameters) DeepCopyInto(out *ViewScopeParameters) {
	*out = *in
	if in.DecisionStrategy != nil {
		in, out := &in.DecisionStrategy, &out.DecisionStrategy
		*out = new(string)
		**out = **in
	}
	if in.Description != nil {
		in, out := &in.Description, &out.Description
		*out = new(string)
		**out = **in
	}
	if in.Policies != nil {
		in, out := &in.Policies, &out.Policies
		*out = make([]*string, len(*in))
		for i := range *in {
			if (*in)[i] != nil {
				in, out := &(*in)[i], &(*out)[i]
				*out = new(string)
				**out = **in
			}
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new ViewScopeParameters.
func (in *ViewScopeParameters) DeepCopy() *ViewScopeParameters {
	if in == nil {
		return nil
	}
	out := new(ViewScopeParameters)
	in.DeepCopyInto(out)
	return out
}