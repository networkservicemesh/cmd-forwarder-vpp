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

	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/client"
	"github.com/networkservicemesh/sdk/pkg/networkservice/ipam/point2pointipam"

	"github.com/networkservicemesh/api/pkg/api/networkservice"

	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	"github.com/networkservicemesh/sdk/pkg/networkservice/utils/metadata"
	"github.com/networkservicemesh/sdk/pkg/tools/token"

	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/connectioncontext"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/mechanisms/vxlan"
)

type vxlanVerifiableEndpoint struct {
	ctx        context.Context
	vppRootDir string
	endpoint.Endpoint
}

func newVxlanVerifiableEndpoint(ctx context.Context,
	prefix *net.IPNet,
	tokenGenerator token.GeneratorFunc,
	vppConn api.Connection,
	vppRootDir string) verifiableEndpoint {
	rv := &vxlanVerifiableEndpoint{
		ctx:        ctx,
		vppRootDir: vppRootDir,
	}
	name := "vxlanVerifiableEndpoint"
	rv.Endpoint = endpoint.NewServer(ctx, name,
		authorize.NewServer(),
		tokenGenerator,
		metadata.NewServer(),
		point2pointipam.NewServer(prefix),
		mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
			vxlan.MECHANISM: vxlan.NewServer(vppConn, net.ParseIP(serverIP)),
		}),
		connectioncontext.NewServer(vppConn),
	)
	return rv
}

func (v *vxlanVerifiableEndpoint) VerifyConnection(conn *networkservice.Connection) error {
	return pingVpp(conn.GetContext().GetIpContext().GetSrcIpAddr(), v.vppRootDir)
}

func (v *vxlanVerifiableEndpoint) VerifyClose(conn *networkservice.Connection) error {
	return nil
}

type vxlanVerifiableClient struct {
	ctx        context.Context
	vppRootDir string
	networkservice.NetworkServiceClient
}

func newVxlanVerifiableClient(
	ctx context.Context,
	sutCC grpc.ClientConnInterface,
	vppConn api.Connection,
	vppRootDir string,
) verifiableClient {
	return &vxlanVerifiableClient{
		ctx:        ctx,
		vppRootDir: vppRootDir,
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
	return pingVpp(conn.GetContext().GetIpContext().GetDstIpAddr(), v.vppRootDir)
}

func (v *vxlanVerifiableClient) VerifyClose(conn *networkservice.Connection) error {
	return nil
}
