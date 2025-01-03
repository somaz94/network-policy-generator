//go:build !ignore_autogenerated

/*
Copyright 2024.

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

package v1

import (
	runtime "k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *GlobalRule) DeepCopyInto(out *GlobalRule) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new GlobalRule.
func (in *GlobalRule) DeepCopy() *GlobalRule {
	if in == nil {
		return nil
	}
	out := new(GlobalRule)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NetworkPolicyGenerator) DeepCopyInto(out *NetworkPolicyGenerator) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NetworkPolicyGenerator.
func (in *NetworkPolicyGenerator) DeepCopy() *NetworkPolicyGenerator {
	if in == nil {
		return nil
	}
	out := new(NetworkPolicyGenerator)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NetworkPolicyGenerator) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NetworkPolicyGeneratorList) DeepCopyInto(out *NetworkPolicyGeneratorList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		in, out := &in.Items, &out.Items
		*out = make([]NetworkPolicyGenerator, len(*in))
		for i := range *in {
			(*in)[i].DeepCopyInto(&(*out)[i])
		}
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NetworkPolicyGeneratorList.
func (in *NetworkPolicyGeneratorList) DeepCopy() *NetworkPolicyGeneratorList {
	if in == nil {
		return nil
	}
	out := new(NetworkPolicyGeneratorList)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *NetworkPolicyGeneratorList) DeepCopyObject() runtime.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NetworkPolicyGeneratorSpec) DeepCopyInto(out *NetworkPolicyGeneratorSpec) {
	*out = *in
	out.Duration = in.Duration
	in.Policy.DeepCopyInto(&out.Policy)
	if in.GlobalRules != nil {
		in, out := &in.GlobalRules, &out.GlobalRules
		*out = make([]GlobalRule, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NetworkPolicyGeneratorSpec.
func (in *NetworkPolicyGeneratorSpec) DeepCopy() *NetworkPolicyGeneratorSpec {
	if in == nil {
		return nil
	}
	out := new(NetworkPolicyGeneratorSpec)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *NetworkPolicyGeneratorStatus) DeepCopyInto(out *NetworkPolicyGeneratorStatus) {
	*out = *in
	in.LastAnalyzed.DeepCopyInto(&out.LastAnalyzed)
	if in.ObservedTraffic != nil {
		in, out := &in.ObservedTraffic, &out.ObservedTraffic
		*out = make([]TrafficFlow, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new NetworkPolicyGeneratorStatus.
func (in *NetworkPolicyGeneratorStatus) DeepCopy() *NetworkPolicyGeneratorStatus {
	if in == nil {
		return nil
	}
	out := new(NetworkPolicyGeneratorStatus)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *PolicyConfig) DeepCopyInto(out *PolicyConfig) {
	*out = *in
	if in.AllowedNamespaces != nil {
		in, out := &in.AllowedNamespaces, &out.AllowedNamespaces
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
	if in.DeniedNamespaces != nil {
		in, out := &in.DeniedNamespaces, &out.DeniedNamespaces
		*out = make([]string, len(*in))
		copy(*out, *in)
	}
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new PolicyConfig.
func (in *PolicyConfig) DeepCopy() *PolicyConfig {
	if in == nil {
		return nil
	}
	out := new(PolicyConfig)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *TrafficFlow) DeepCopyInto(out *TrafficFlow) {
	*out = *in
}

// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new TrafficFlow.
func (in *TrafficFlow) DeepCopy() *TrafficFlow {
	if in == nil {
		return nil
	}
	out := new(TrafficFlow)
	in.DeepCopyInto(out)
	return out
}
