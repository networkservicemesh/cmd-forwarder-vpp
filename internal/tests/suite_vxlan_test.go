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

package tests

import (
	"context"
	"net"

	"git.fd.io/govpp.git/api"
	"google.golang.org/grpc"

	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	"github.com/networkservicemesh/sdk/pkg/networkservice/ipam/point2pointipam"
	"github.com/networkservicemesh/sdk/pkg/networkservice/utils/metadata"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/client"

	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/tools/token"

	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/connectioncontext"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/mechanisms/vxlan"
)

type vxlanVerifiableEndpoint struct {
	ctx     context.Context
	vppConn api.Connection
	endpoint.Endpoint
}

func newVxlanVerifiableEndpoint(ctx context.Context,
	prefix1, prefix2 *net.IPNet,
	tokenGenerator token.GeneratorFunc,
	vppConn api.Connection) verifiableEndpoint {
	rv := &vxlanVerifiableEndpoint{
		ctx:     ctx,
		vppConn: vppConn,
	}
	name := "vxlanVerifiableEndpoint"
	rv.Endpoint = endpoint.NewServer(ctx,
		tokenGenerator,
		endpoint.WithName(name),
		endpoint.WithAuthorizeServer(authorize.NewServer()),
		endpoint.WithAdditionalFunctionality(
			metadata.NewServer(),
			point2pointipam.NewServer(prefix1),
			point2pointipam.NewServer(prefix2),
			connectioncontext.NewServer(vppConn),
			mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
				vxlan.MECHANISM: vxlan.NewServer(vppConn, net.ParseIP(serverIP)),
			}),
		),
	)
	return rv
}

func (v *vxlanVerifiableEndpoint) VerifyConnection(conn *networkservice.Connection) error {
	for _, ip := range conn.GetContext().GetIpContext().GetSrcIpAddrs() {
		if err := pingVpp(v.ctx, v.vppConn, ip); err != nil {
			return err
		}
	}
	return nil
}

func (v *vxlanVerifiableEndpoint) VerifyClose(conn *networkservice.Connection) error {
	return nil
}

type vxlanVerifiableClient struct {
	ctx     context.Context
	vppConn api.Connection
	networkservice.NetworkServiceClient
}

func newVxlanVerifiableClient(
	ctx context.Context,
	sutCC grpc.ClientConnInterface,
	vppConn api.Connection,
) verifiableClient {
	return &vxlanVerifiableClient{
		ctx:     ctx,
		vppConn: vppConn,
		NetworkServiceClient: client.NewClient(ctx,
			sutCC,
			client.WithName("vxlanVerifiableClient"),
			client.WithAdditionalFunctionality(
				connectioncontext.NewClient(vppConn),
				vxlan.NewClient(vppConn, net.ParseIP(clientIP)),
			),
		),
	}
}

func (v *vxlanVerifiableClient) VerifyConnection(conn *networkservice.Connection) error {
	for _, ip := range conn.GetContext().GetIpContext().GetDstIpAddrs() {
		if err := pingVpp(v.ctx, v.vppConn, ip); err != nil {
			return err
		}
	}
	return nil
}

func (v *vxlanVerifiableClient) VerifyClose(conn *networkservice.Connection) error {
	return nil
}
