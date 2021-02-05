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
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"

	"github.com/edwarnicke/exechelper"
	"github.com/edwarnicke/vpphelper"
	"github.com/pkg/errors"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/connectioncontext"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/mechanisms/memif"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/tag"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/up"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/client"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/recvfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/ipam/point2pointipam"
	"github.com/networkservicemesh/sdk/pkg/networkservice/utils/metadata"
	"github.com/networkservicemesh/sdk/pkg/tools/token"

	"google.golang.org/grpc"

	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/sendfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/chain"
)

type memifVerifiableEndpoint struct {
	ctx        context.Context
	vppRootDir string
	endpoint.Endpoint
}

func newMemifVerifiableEndpoint(ctx context.Context,
	prefix *net.IPNet,
	tokenGenerator token.GeneratorFunc,
	vppConn vpphelper.Connection,
	vppRootDir string,
	lastSocketID *uint32,
) verifiableEndpoint {
	baseDir, err := ioutil.TempDir("", "forwarder.test-")
	if err != nil {
		panic(fmt.Sprintf("unable create TmpDir: %+v", err))
	}
	return &memifVerifiableEndpoint{
		ctx:        ctx,
		vppRootDir: vppRootDir,
		Endpoint: endpoint.NewServer(
			ctx,
			"memifVerifiableEndpoint",
			authorize.NewServer(),
			tokenGenerator,
			point2pointipam.NewServer(prefix),
			mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
				memif.MECHANISM: chain.NewNetworkServiceServer(
					metadata.NewServer(),
					memif.NewServer(vppConn, baseDir, lastSocketID),
					tag.NewServer(ctx, vppConn),
					connectioncontext.NewServer(vppConn),
					up.NewServer(ctx, vppConn),
					sendfd.NewServer(),
				),
			}),
			sendfd.NewServer(),
		),
	}
}

func (k *memifVerifiableEndpoint) VerifyConnection(conn *networkservice.Connection) error {
	return pingVpp(conn.GetContext().GetIpContext().GetSrcIpAddr(), k.vppRootDir)
}

func (k *memifVerifiableEndpoint) VerifyClose(conn *networkservice.Connection) error {
	return nil
}

type memifVerifiableClient struct {
	ctx        context.Context
	vppRootDir string
	networkservice.NetworkServiceClient
}

func newMemifVerifiableClient(ctx context.Context,
	tokenGenerator token.GeneratorFunc,
	sutCC grpc.ClientConnInterface,
	vppConn vpphelper.Connection,
	lastSocketID *uint32,
	vppRootDir string,
) verifiableClient {
	rv := &memifVerifiableClient{
		ctx:        ctx,
		vppRootDir: vppRootDir,
		NetworkServiceClient: client.NewClient(
			ctx,
			"memifVerifiableClient",
			nil,
			tokenGenerator,
			sutCC,
			metadata.NewClient(),
			up.NewClient(ctx, vppConn),
			connectioncontext.NewClient(vppConn),
			memif.NewClient(vppConn, lastSocketID),
			recvfd.NewClient(),
		),
	}
	return rv
}

func (m *memifVerifiableClient) VerifyConnection(conn *networkservice.Connection) error {
	return pingVpp(conn.GetContext().GetIpContext().GetDstIpAddr(), m.vppRootDir)
}

func (m *memifVerifiableClient) VerifyClose(conn *networkservice.Connection) error {
	return nil
}

func pingVpp(ipaddress, rootDir string) error {
	ip, _, err := net.ParseCIDR(ipaddress)
	if err != nil {
		return errors.WithStack(err)
	}
	pingStr := fmt.Sprintf("vppctl -s %s/var/run/vpp/cli.sock ping %s interval 0.1 repeat 1 verbose", rootDir, ip.String())

	// Prime the pump, vpp doesn't arp until needed, and so the first ping will fail
	_ = exechelper.Run(pingStr,
		exechelper.WithEnvirons(os.Environ()...),
		exechelper.WithStdout(os.Stdout),
		exechelper.WithStderr(os.Stderr),
	)

	buf := bytes.NewBuffer([]byte{})
	if err := exechelper.Run(pingStr,
		exechelper.WithEnvirons(os.Environ()...),
		exechelper.WithStdout(os.Stdout),
		exechelper.WithStderr(os.Stderr),
		exechelper.WithStdout(buf),
		exechelper.WithStderr(buf),
	); err != nil {
		return errors.WithStack(err)
	}
	if regexp.MustCompile(" 0% packet loss").Match(buf.Bytes()) {
		return nil
	}
	return errors.New("Ping failed")
}
