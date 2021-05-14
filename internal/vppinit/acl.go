// Copyright (c) 2020 Cisco and/or its affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vppinit

import (
	"context"
	"net"
	"time"

	"git.fd.io/govpp.git/api"
	"github.com/edwarnicke/govpp/binapi/acl"
	"github.com/edwarnicke/govpp/binapi/acl_types"
	"github.com/edwarnicke/govpp/binapi/interface_types"
	"github.com/pkg/errors"

	"github.com/networkservicemesh/sdk-vpp/pkg/tools/types"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
)

func denyAllACLToInterface(ctx context.Context, vppConn api.Connection, swIfIndex interface_types.InterfaceIndex) error {
	denyAll := &acl.ACLAddReplace{
		ACLIndex: ^uint32(0),
		Tag:      "nsm-vppinit-denyall",
		R: []acl_types.ACLRule{
			{
				IsPermit: acl_types.ACL_ACTION_API_DENY,
				SrcPrefix: types.ToVppPrefix(&net.IPNet{
					IP:   net.IPv4zero,
					Mask: net.CIDRMask(0, 32),
				}),
			},
			{
				IsPermit: acl_types.ACL_ACTION_API_DENY,
				SrcPrefix: types.ToVppPrefix(&net.IPNet{
					IP:   net.IPv6zero,
					Mask: net.CIDRMask(0, 128),
				}),
			},
		},
	}

	now := time.Now()
	denyAllRsp, err := acl.NewServiceClient(vppConn).ACLAddReplace(ctx, denyAll)
	if err != nil {
		return errors.Wrapf(err, "unable to add denyall ACL")
	}

	log.FromContext(ctx).
		WithField("aclIndex", denyAllRsp.ACLIndex).
		WithField("duration", time.Since(now)).
		WithField("vppapi", "ACLAddReplace").Debug("completed")

	now = time.Now()
	interfaceACLList := &acl.ACLInterfaceSetACLList{
		SwIfIndex: swIfIndex,
		Count:     2,
		NInput:    1,
		Acls: []uint32{
			denyAllRsp.ACLIndex,
			denyAllRsp.ACLIndex,
		},
	}
	_, err = acl.NewServiceClient(vppConn).ACLInterfaceSetACLList(ctx, interfaceACLList)
	if err != nil {
		return errors.Wrapf(err, "unable to add aclList ACL")
	}
	log.FromContext(ctx).
		WithField("swIfIndex", interfaceACLList.SwIfIndex).
		WithField("acls", interfaceACLList.Acls).
		WithField("NInput", interfaceACLList.NInput).
		WithField("duration", time.Since(now)).
		WithField("vppapi", "ACLInterfaceSetACLList").Debug("completed")
	return nil
}
