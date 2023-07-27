// Copyright (c) 2020-2023 Cisco and/or its affiliates.
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

// nolint:dupl
package tests

import (
	"context"
	"net"

	"google.golang.org/grpc"

	"github.com/networkservicemesh/vpphelper"

	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/client"

	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	"github.com/networkservicemesh/sdk/pkg/networkservice/ipam/point2pointipam"
	"github.com/networkservicemesh/sdk/pkg/networkservice/utils/metadata"

	"github.com/networkservicemesh/api/pkg/api/networkservice"

	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/tools/token"

	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/connectioncontext"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/mechanisms/wireguard"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/pinhole"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/up"
)

type wireguardVerifiableEndpoint struct {
	ctx     context.Context
	vppConn vpphelper.Connection
	endpoint.Endpoint
}

func newWireguardVerifiableEndpoint(ctx context.Context,
	prefix1, prefix2 *net.IPNet,
	tokenGenerator token.GeneratorFunc,
	vppConn vpphelper.Connection) verifiableEndpoint {
	rv := &wireguardVerifiableEndpoint{
		ctx:     ctx,
		vppConn: vppConn,
	}
	name := "wireguardVerifiableEndpoint"
	rv.Endpoint = endpoint.NewServer(ctx,
		tokenGenerator,
		endpoint.WithName(name),
		endpoint.WithAuthorizeServer(authorize.NewServer()),
		endpoint.WithAdditionalFunctionality(
			metadata.NewServer(),
			point2pointipam.NewServer(prefix1),
			point2pointipam.NewServer(prefix2),
			up.NewServer(ctx, vppConn),
			pinhole.NewServer(vppConn),
			connectioncontext.NewServer(vppConn),
			mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
				wireguard.MECHANISM: wireguard.NewServer(vppConn, net.ParseIP(serverIP)),
			}),
		),
	)
	return rv
}

func (v *wireguardVerifiableEndpoint) VerifyConnection(conn *networkservice.Connection) error {
	for _, ip := range conn.GetContext().GetIpContext().GetSrcIpAddrs() {
		if err := pingVpp(v.ctx, v.vppConn, ip); err != nil {
			return err
		}
	}
	return nil
}

func (v *wireguardVerifiableEndpoint) VerifyClose(_ *networkservice.Connection) error {
	return nil
}

type wireguardVerifiableClient struct {
	ctx     context.Context
	vppConn vpphelper.Connection
	networkservice.NetworkServiceClient
}

func newWireguardVerifiableClient(
	ctx context.Context,
	sutCC grpc.ClientConnInterface,
	vppConn vpphelper.Connection,
) verifiableClient {
	return &wireguardVerifiableClient{
		ctx:     ctx,
		vppConn: vppConn,
		NetworkServiceClient: client.NewClient(
			ctx,
			client.WithName("wireguardVerifiableClient"),
			client.WithClientConn(sutCC),
			client.WithAdditionalFunctionality(
				up.NewClient(ctx, vppConn),
				connectioncontext.NewClient(vppConn),
				wireguard.NewClient(vppConn, net.ParseIP(clientIP)),
				pinhole.NewClient(vppConn),
			),
		),
	}
}

func (v *wireguardVerifiableClient) VerifyConnection(conn *networkservice.Connection) error {
	for _, ip := range conn.GetContext().GetIpContext().GetDstIpAddrs() {
		if err := pingVpp(v.ctx, v.vppConn, ip); err != nil {
			return err
		}
	}
	return nil
}

func (v *wireguardVerifiableClient) VerifyClose(_ *networkservice.Connection) error {
	return nil
}
