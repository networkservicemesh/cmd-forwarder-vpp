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

//go:build linux

package tests

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/binapi/vpe"
	"github.com/pkg/errors"

	"github.com/networkservicemesh/vpphelper"

	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/sendfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/chain"
	"github.com/networkservicemesh/sdk/pkg/networkservice/ipam/point2pointipam"

	"github.com/networkservicemesh/sdk/pkg/tools/log"

	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/client"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/recvfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/utils/metadata"
	"github.com/networkservicemesh/sdk/pkg/tools/token"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/connectioncontext"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/mechanisms/memif"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/tag"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/up"

	"google.golang.org/grpc"
)

type memifVerifiableEndpoint struct {
	ctx     context.Context
	vppConn api.Connection
	endpoint.Endpoint
}

func newMemifVerifiableEndpoint(ctx context.Context,
	prefix1, prefix2 *net.IPNet,
	tokenGenerator token.GeneratorFunc,
	vppConn vpphelper.Connection,
) verifiableEndpoint {
	return &memifVerifiableEndpoint{
		ctx:     ctx,
		vppConn: vppConn,
		Endpoint: endpoint.NewServer(
			ctx,
			tokenGenerator,
			endpoint.WithName("memifVerifiableEndpoint"),
			endpoint.WithAuthorizeServer(authorize.NewServer()),
			endpoint.WithAdditionalFunctionality(
				sendfd.NewServer(),
				point2pointipam.NewServer(prefix1),
				point2pointipam.NewServer(prefix2),
				mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
					memif.MECHANISM: chain.NewNetworkServiceServer(
						metadata.NewServer(),
						up.NewServer(ctx, vppConn),
						connectioncontext.NewServer(vppConn),
						tag.NewServer(ctx, vppConn),
						memif.NewServer(ctx, vppConn),
					),
				}),
			),
		),
	}
}

func (k *memifVerifiableEndpoint) VerifyConnection(conn *networkservice.Connection) error {
	for _, ip := range conn.GetContext().GetIpContext().GetSrcIpAddrs() {
		if err := pingVpp(k.ctx, k.vppConn, ip); err != nil {
			return err
		}
	}
	return nil
}

func (k *memifVerifiableEndpoint) VerifyClose(_ *networkservice.Connection) error {
	return nil
}

type memifVerifiableClient struct {
	ctx     context.Context
	vppConn api.Connection
	networkservice.NetworkServiceClient
}

func newMemifVerifiableClient(ctx context.Context, sutCC grpc.ClientConnInterface, vppConn vpphelper.Connection) verifiableClient {
	rv := &memifVerifiableClient{
		ctx:     ctx,
		vppConn: vppConn,
		NetworkServiceClient: client.NewClient(
			ctx,
			client.WithName("memifVerifiableClient"),
			client.WithClientConn(sutCC),
			client.WithAdditionalFunctionality(
				metadata.NewClient(),
				up.NewClient(ctx, vppConn),
				connectioncontext.NewClient(vppConn),
				memif.NewClient(ctx, vppConn),
				sendfd.NewClient(),
				recvfd.NewClient(),
			),
		),
	}
	return rv
}

func (m *memifVerifiableClient) VerifyConnection(conn *networkservice.Connection) error {
	for _, ip := range conn.GetContext().GetIpContext().GetDstIpAddrs() {
		if err := pingVpp(m.ctx, m.vppConn, ip); err != nil {
			return err
		}
	}
	return nil
}

func (m *memifVerifiableClient) VerifyClose(_ *networkservice.Connection) error {
	return nil
}

func pingVpp(ctx context.Context, vppConn api.Connection, ipaddress string) error {
	ip, _, err := net.ParseCIDR(ipaddress)
	if err != nil {
		return errors.WithStack(err)
	}
	pingCmd := &vpe.CliInband{
		Cmd: fmt.Sprintf("ping %s interval 0.1 repeat 1 verbose", ip.String()),
	}

	// Prime the pump, vpp doesn't arp until needed, and so the first ping will fail
	now := time.Now()
	pingRsp, err := vpe.NewServiceClient(vppConn).CliInband(ctx, pingCmd)
	if err != nil {
		return errors.WithStack(err)
	}
	log.FromContext(ctx).
		WithField("vppapi", "CliInband").
		WithField("Cmd", pingCmd).
		WithField("Reply", pingRsp.Reply).
		WithField("duration", time.Since(now)).Debug("completed")

	now = time.Now()
	if pingRsp, err = vpe.NewServiceClient(vppConn).CliInband(ctx, pingCmd); err != nil {
		return errors.WithStack(err)
	}
	log.FromContext(ctx).
		WithField("vppapi", "CliInband").
		WithField("Cmd", pingCmd).
		WithField("Reply", pingRsp.Reply).
		WithField("duration", time.Since(now)).Debug("completed")

	if strings.Contains(pingRsp.Reply, " 0% packet loss") &&
		!strings.Contains(pingRsp.Reply, " 0 sent, 0 received") {
		return nil
	}
	return errors.New("Ping failed")
}
