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

// +build linux

package tests

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"time"

	"git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/binapi/vpe"
	"github.com/edwarnicke/vpphelper"
	"github.com/pkg/errors"

	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/tag"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/sendfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/chain"
	"github.com/networkservicemesh/sdk/pkg/networkservice/ipam/point2pointipam"

	"github.com/networkservicemesh/sdk/pkg/tools/log"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/connectioncontext"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/mechanisms/memif"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/up"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/client"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/recvfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/utils/metadata"
	"github.com/networkservicemesh/sdk/pkg/tools/token"

	"google.golang.org/grpc"
)

type memifVerifiableEndpoint struct {
	ctx     context.Context
	vppConn api.Connection
	endpoint.Endpoint
}

func newMemifVerifiableEndpoint(ctx context.Context,
	prefix *net.IPNet,
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
				point2pointipam.NewServer(prefix),
				mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
					memif.MECHANISM: chain.NewNetworkServiceServer(
						metadata.NewServer(),
						memif.NewServer(vppConn),
						tag.NewServer(ctx, vppConn),
						connectioncontext.NewServer(vppConn),
						up.NewServer(ctx, vppConn),
						sendfd.NewServer(),
					),
				}),
				sendfd.NewServer(),
			),
		),
	}
}

func (k *memifVerifiableEndpoint) VerifyConnection(conn *networkservice.Connection) error {
	return pingVpp(k.ctx, k.vppConn, conn.GetContext().GetIpContext().GetSrcIpAddr())
}

func (k *memifVerifiableEndpoint) VerifyClose(conn *networkservice.Connection) error {
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
			sutCC,
			client.WithName("memifVerifiableClient"),
			client.WithAdditionalFunctionality(
				metadata.NewClient(),
				up.NewClient(ctx, vppConn),
				connectioncontext.NewClient(vppConn),
				memif.NewClient(vppConn),
				recvfd.NewClient(),
			),
		),
	}
	return rv
}

func (m *memifVerifiableClient) VerifyConnection(conn *networkservice.Connection) error {
	return pingVpp(m.ctx, m.vppConn, conn.GetContext().GetIpContext().GetDstIpAddr())
}

func (m *memifVerifiableClient) VerifyClose(conn *networkservice.Connection) error {
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

	if regexp.MustCompile(" 0% packet loss").MatchString(pingRsp.Reply) {
		return nil
	}
	return errors.New("Ping failed")
}
