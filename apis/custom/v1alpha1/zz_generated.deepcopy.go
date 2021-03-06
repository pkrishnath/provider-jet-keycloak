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
func (in *IdentityProviderMapper) DeepCopyInto(out *IdentityProviderMapper) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IdentityProviderMapper.
func (in *IdentityProviderMapper) DeepCopy() *IdentityProviderMapper {
	if in == nil {
		return nil
	}
	out := new(IdentityProviderMapper)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IdentityProviderMapper) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IdentityProviderMapperList) DeepCopyInto(out *IdentityProviderMapperList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]IdentityProviderMapper, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IdentityProviderMapperList.
func (in *IdentityProviderMapperList) DeepCopy() *IdentityProviderMapperList {
	if in == nil {
		return nil
	}
	out := new(IdentityProviderMapperList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *IdentityProviderMapperList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IdentityProviderMapperObservation) DeepCopyInto(out *IdentityProviderMapperObservation) {
	*out = *in
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IdentityProviderMapperObservation.
func (in *IdentityProviderMapperObservation) DeepCopy() *IdentityProviderMapperObservation {
	if in == nil {
		return nil
	}
	out := new(IdentityProviderMapperObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IdentityProviderMapperParameters) DeepCopyInto(out *IdentityProviderMapperParameters) {
	*out = *in
	if in.ExtraConfig != nil {
		in, out := &in.ExtraConfig, &out.ExtraConfig
		*out = make(map[string]*string, len(*in))
		for key, val := range *in {
			var outVal *string
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
	if in.IdentityProviderAlias != nil {
		in, out := &in.IdentityProviderAlias, &out.IdentityProviderAlias
		*out = new(string)
		**out = **in
	}
	if in.IdentityProviderMapper != nil {
		in, out := &in.IdentityProviderMapper, &out.IdentityProviderMapper
		*out = new(string)
		**out = **in
	}
	if in.Realm != nil {
		in, out := &in.Realm, &out.Realm
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IdentityProviderMapperParameters.
func (in *IdentityProviderMapperParameters) DeepCopy() *IdentityProviderMapperParameters {
	if in == nil {
		return nil
	}
	out := new(IdentityProviderMapperParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IdentityProviderMapperSpec) DeepCopyInto(out *IdentityProviderMapperSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IdentityProviderMapperSpec.
func (in *IdentityProviderMapperSpec) DeepCopy() *IdentityProviderMapperSpec {
	if in == nil {
		return nil
	}
	out := new(IdentityProviderMapperSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *IdentityProviderMapperStatus) DeepCopyInto(out *IdentityProviderMapperStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new IdentityProviderMapperStatus.
func (in *IdentityProviderMapperStatus) DeepCopy() *IdentityProviderMapperStatus {
	if in == nil {
		return nil
	}
	out := new(IdentityProviderMapperStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UserFederation) DeepCopyInto(out *UserFederation) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UserFederation.
func (in *UserFederation) DeepCopy() *UserFederation {
	if in == nil {
		return nil
	}
	out := new(UserFederation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *UserFederation) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UserFederationList) DeepCopyInto(out *UserFederationList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]UserFederation, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UserFederationList.
func (in *UserFederationList) DeepCopy() *UserFederationList {
	if in == nil {
		return nil
	}
	out := new(UserFederationList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *UserFederationList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UserFederationObservation) DeepCopyInto(out *UserFederationObservation) {
	*out = *in
	if in.ID != nil {
		in, out := &in.ID, &out.ID
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UserFederationObservation.
func (in *UserFederationObservation) DeepCopy() *UserFederationObservation {
	if in == nil {
		return nil
	}
	out := new(UserFederationObservation)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UserFederationParameters) DeepCopyInto(out *UserFederationParameters) {
	*out = *in
	if in.CachePolicy != nil {
		in, out := &in.CachePolicy, &out.CachePolicy
		*out = new(string)
		**out = **in
	}
	if in.ChangedSyncPeriod != nil {
		in, out := &in.ChangedSyncPeriod, &out.ChangedSyncPeriod
		*out = new(float64)
		**out = **in
	}
	if in.Config != nil {
		in, out := &in.Config, &out.Config
		*out = make(map[string]*string, len(*in))
		for key, val := range *in {
			var outVal *string
			if val == nil {
				(*out)[key] = nil
			} else {
				in, out := &val, &outVal
				*out = new(string)
				**out = **in
			}
			(*out)[key] = outVal
		}
	}
	if in.Enabled != nil {
		in, out := &in.Enabled, &out.Enabled
		*out = new(bool)
		**out = **in
	}
	if in.FullSyncPeriod != nil {
		in, out := &in.FullSyncPeriod, &out.FullSyncPeriod
		*out = new(float64)
		**out = **in
	}
	if in.ParentID != nil {
		in, out := &in.ParentID, &out.ParentID
		*out = new(string)
		**out = **in
	}
	if in.Priority != nil {
		in, out := &in.Priority, &out.Priority
		*out = new(float64)
		**out = **in
	}
	if in.ProviderID != nil {
		in, out := &in.ProviderID, &out.ProviderID
		*out = new(string)
		**out = **in
	}
	if in.RealmID != nil {
		in, out := &in.RealmID, &out.RealmID
		*out = new(string)
		**out = **in
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UserFederationParameters.
func (in *UserFederationParameters) DeepCopy() *UserFederationParameters {
	if in == nil {
		return nil
	}
	out := new(UserFederationParameters)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UserFederationSpec) DeepCopyInto(out *UserFederationSpec) {
	*out = *in
	in.ResourceSpec.DeepCopyInto(&out.ResourceSpec)
	in.ForProvider.DeepCopyInto(&out.ForProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UserFederationSpec.
func (in *UserFederationSpec) DeepCopy() *UserFederationSpec {
	if in == nil {
		return nil
	}
	out := new(UserFederationSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *UserFederationStatus) DeepCopyInto(out *UserFederationStatus) {
	*out = *in
	in.ResourceStatus.DeepCopyInto(&out.ResourceStatus)
	in.AtProvider.DeepCopyInto(&out.AtProvider)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new UserFederationStatus.
func (in *UserFederationStatus) DeepCopy() *UserFederationStatus {
	if in == nil {
		return nil
	}
	out := new(UserFederationStatus)
	in.DeepCopyInto(out)
	return out
}
