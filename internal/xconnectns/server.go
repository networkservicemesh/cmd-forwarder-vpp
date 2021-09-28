// Copyright (c) 2021 Doc.ai and/or its affiliates.
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

//+build linux

// Package xconnectns provides an endpoint implementing xconnectns
package xconnectns

import (
	"context"
	"net"
	"net/url"

	"google.golang.org/grpc"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/memif"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/noop"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/vfio"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/vxlan"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/wireguard"
	sriovxconnectns "github.com/networkservicemesh/sdk-sriov/pkg/networkservice/chains/xconnectns"
	"github.com/networkservicemesh/sdk-sriov/pkg/networkservice/common/resourcepool"
	sriovconfig "github.com/networkservicemesh/sdk-sriov/pkg/sriov/config"
	sriovtokens "github.com/networkservicemesh/sdk-sriov/pkg/tools/tokens"
	vppxconnectns "github.com/networkservicemesh/sdk-vpp/pkg/networkservice/chains/xconnectns"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/switchcase"
	"github.com/networkservicemesh/sdk/pkg/tools/token"
)

// NewServer - returns an implementation of the xconnectns network service
func NewServer(
	ctx context.Context,
	name string,
	authzServer networkservice.NetworkServiceServer,
	tokenGenerator token.GeneratorFunc,
	vppConn vppxconnectns.Connection,
	tunnelIP net.IP,
	tunnelPort uint16,
	pciPool resourcepool.PCIPool,
	resourcePool resourcepool.ResourcePool,
	sriovConfig *sriovconfig.Config,
	vfioDir, cgroupBaseDir string,
	clientURL *url.URL,
	clientDialOptions ...grpc.DialOption,
) endpoint.Endpoint {
	vppForwarder := vppxconnectns.NewServer(ctx, name, authzServer, tokenGenerator, clientURL, vppConn, tunnelIP, tunnelPort, clientDialOptions...)
	if sriovConfig == nil {
		return vppForwarder
	}

	return endpoint.Combine(func(servers []networkservice.NetworkServiceServer) networkservice.NetworkServiceServer {
		vppForwarder := servers[0]
		sriovForwarder := servers[1]
		return mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
			kernel.MECHANISM: switchcase.NewServer(
				&switchcase.ServerCase{
					Condition: func(_ context.Context, conn *networkservice.Connection) bool {
						return sriovtokens.IsTokenID(kernel.ToMechanism(conn.GetMechanism()).GetDeviceTokenID())
					},
					Server: sriovForwarder,
				},
				&switchcase.ServerCase{
					Condition: switchcase.Default,
					Server:    vppForwarder,
				},
			),
			vfio.MECHANISM:      sriovForwarder,
			memif.MECHANISM:     vppForwarder,
			vxlan.MECHANISM:     vppForwarder,
			wireguard.MECHANISM: vppForwarder,
			noop.MECHANISM:      sriovForwarder,
		})
	},
		vppForwarder,
		sriovxconnectns.NewServer(ctx, name, authzServer, tokenGenerator, pciPool, resourcePool, sriovConfig, vfioDir, cgroupBaseDir, clientURL, clientDialOptions...),
	)
}
