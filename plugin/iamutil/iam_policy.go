// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package iamutil

import (
	"fmt"

	"github.com/hashicorp/vault-plugin-secrets-gcp/plugin/util"
)

const (
	ServiceAccountMemberTmpl = "serviceAccount:%s"
)

type Policy struct {
	Bindings []*Binding `json:"bindings,omitempty"`
	Etag     string     `json:"etag,omitempty"`
	Version  int        `json:"version,omitempty"`
}

type Binding struct {
	Members   []string   `json:"members,omitempty"`
	Role      string     `json:"role,omitempty"`
	Condition *Condition `json:"condition,omitempty"`
}

type Condition struct {
	Title       string `json:"title,omitempty"`
	Description string `json:"description,omitempty"`
	Expression  string `json:"expression,omitempty"`
}

type PolicyDelta struct {
	Roles     util.StringSet
	Email     string
	Condition *Condition
}

func (p *Policy) AddBindings(toAdd *PolicyDelta) (changed bool, updated *Policy) {
	return p.ChangeBindings(toAdd, nil)
}

func (p *Policy) RemoveBindings(toRemove *PolicyDelta) (changed bool, updated *Policy) {
	return p.ChangeBindings(nil, toRemove)
}

func (p *Policy) ChangeBindings(toAdd *PolicyDelta, toRemove *PolicyDelta) (changed bool, updated *Policy) {
	//If No toAdd and no toRemove, return False
	if toAdd == nil && toRemove == nil {
		return false, p
	}
	//Convert email into serviceAccountEmail
	var toAddMem, toRemoveMem string
	if toAdd != nil {
		toAddMem = fmt.Sprintf(ServiceAccountMemberTmpl, toAdd.Email)
	}
	if toRemove != nil {
		toRemoveMem = fmt.Sprintf(ServiceAccountMemberTmpl, toRemove.Email)
	}

	changed = false

	newBindings := make([]*Binding, 0, len(p.Bindings))
	alreadyAdded := make([]*Binding, 0)
	//Loop through the existing policyBindings
	for _, bind := range p.Bindings {
		//for each binding, set of existing members
		memberSet := util.ToSet(bind.Members)
		//If adding
		if toAdd != nil {
			//If the binding role is in the list of roles and they have the same condition.
			if toAdd.Roles.Includes(bind.Role) && toAdd.Condition == bind.Condition {
				changed = true
				// Add the binding to the set of alreadyAdded bindings
				alreadyAdded = append(alreadyAdded, bind)
				// Add the member to the memberSet
				memberSet.Add(toAddMem)
			}
		}

		if toRemove != nil {
			// If the list of roles includes one of the roles to remove, and they have the same condition
			// TODO:: Do we want to remove users regardless of the condition?
			if toRemove.Roles.Includes(bind.Role) && toAdd.Condition == bind.Condition {
				if memberSet.Includes(toRemoveMem) {
					changed = true
					//remove the member form the memberSet
					delete(memberSet, toRemoveMem)
				}
			}
		}

		//If there is more than one member in the memberSet, add the binding to the memberSet using the existing
		//binding Condition
		if len(memberSet) > 0 {
			newBindings = append(newBindings, &Binding{
				Role:      bind.Role,
				Members:   memberSet.ToSlice(),
				Condition: bind.Condition,
			})
		}
	}
	// End loop through existing bindings

	if toAdd != nil {
		//For each role being added
		for r := range toAdd.Roles {
			binding := &Binding{
				Role:      r,
				Members:   []string{toAddMem},
				Condition: toAdd.Condition,
			}
			// If the binding (role and condition) didn't already exist, add it
			if !BindingExists(alreadyAdded, binding) {
				changed = true
				newBindings = append(newBindings, binding)
			}
		}
	}

	if changed {
		return true, &Policy{
			Bindings: newBindings,
			Etag:     p.Etag,
			Version:  p.Version,
		}
	}
	return false, p
}

func BindingExists(existingBindings []*Binding, binding *Binding) (exists bool) {
	// For each binding that already existed, loop through and see if the same role and condition
	// already existed. If it does, return true, else return false
	for _, bind := range existingBindings {
		if bind.Role == binding.Role && bind.Condition == binding.Condition {
			return true
		}
	}
	return false
}
