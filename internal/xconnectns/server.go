// Copyright (c) 2021-2022 Doc.ai and/or its affiliates.
//
// Copyright (c) 2022-2024 Cisco and/or its affiliates.
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

//go:build linux

// Package xconnectns provides an endpoint implementing xconnectns
package xconnectns

import (
	"context"
	"net"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/memif"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/noop"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/vfio"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/vxlan"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/wireguard"
	sriovforwarder "github.com/networkservicemesh/sdk-sriov/pkg/networkservice/chains/forwarder"
	"github.com/networkservicemesh/sdk-sriov/pkg/networkservice/common/resourcepool"
	sriovconfig "github.com/networkservicemesh/sdk-sriov/pkg/sriov/config"
	sriovtokens "github.com/networkservicemesh/sdk-sriov/pkg/tools/tokens"
	vppforwarder "github.com/networkservicemesh/sdk-vpp/pkg/networkservice/chains/forwarder"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/switchcase"
	authmonitor "github.com/networkservicemesh/sdk/pkg/tools/monitorconnection/authorize"
	"github.com/networkservicemesh/sdk/pkg/tools/token"
)

// NewServer - returns an implementation of the xconnectns network service
func NewServer(
	ctx context.Context,
	tokenGenerator token.GeneratorFunc,
	vppConn vppforwarder.Connection,
	tunnelIP net.IP,
	pciPool resourcepool.PCIPool,
	resourcePool resourcepool.ResourcePool,
	sriovConfig *sriovconfig.Config,
	vfioDir, cgroupBaseDir string,
	options ...Option,
) endpoint.Endpoint {
	xconnOpts := &xconnOptions{
		name:                             "forwarder-" + uuid.New().String(),
		authorizeServer:                  authorize.NewServer(authorize.Any()),
		authorizeMonitorConnectionServer: authmonitor.NewMonitorConnectionServer(authmonitor.Any()),
		clientURL:                        &url.URL{Scheme: "unix", Host: "connect.to.socket"},
		dialTimeout:                      time.Millisecond * 200,
		domain2Device:                    make(map[string]string),
	}
	for _, opt := range options {
		opt(xconnOpts)
	}

	vppForwarder := vppforwarder.NewServer(ctx, tokenGenerator, vppConn, tunnelIP,
		vppforwarder.WithName(xconnOpts.name),
		vppforwarder.WithAuthorizeServer(xconnOpts.authorizeServer),
		vppforwarder.WithAuthorizeMonitorConnectionServer(xconnOpts.authorizeMonitorConnectionServer),
		vppforwarder.WithClientURL(xconnOpts.clientURL),
		vppforwarder.WithDialTimeout(xconnOpts.dialTimeout),
		vppforwarder.WithVlanDomain2Device(xconnOpts.domain2Device),
		vppforwarder.WithMechanismPriority(xconnOpts.mechanismPrioriyList),
		vppforwarder.WithCleanupOptions(xconnOpts.cleanupOpts...),
		vppforwarder.WithStatsOptions(xconnOpts.metricsOpts...),
		vppforwarder.WithVxlanOptions(xconnOpts.vxlanOpts...),
		vppforwarder.WithDialOptions(xconnOpts.dialOpts...))
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
		sriovforwarder.NewServer(ctx,
			xconnOpts.name,
			xconnOpts.authorizeServer,
			xconnOpts.authorizeMonitorConnectionServer,
			tokenGenerator,
			pciPool,
			resourcePool,
			sriovConfig,
			vfioDir,
			cgroupBaseDir,
			xconnOpts.clientURL,
			xconnOpts.dialTimeout,
			xconnOpts.dialOpts...),
	)
}
