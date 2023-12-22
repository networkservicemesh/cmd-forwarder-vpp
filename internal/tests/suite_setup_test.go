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
	"os"
	"path/filepath"
	"time"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/edwarnicke/exechelper"
	"github.com/edwarnicke/grpcfd"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"go.fd.io/govpp/binapi/vpe"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/networkservicemesh/vpphelper"

	"github.com/networkservicemesh/api/pkg/api/registry"
	"github.com/networkservicemesh/sdk/pkg/registry/common/begin"
	"github.com/networkservicemesh/sdk/pkg/registry/common/expire"
	"github.com/networkservicemesh/sdk/pkg/registry/common/memory"
	registryrecvfd "github.com/networkservicemesh/sdk/pkg/registry/common/recvfd"
	"github.com/networkservicemesh/sdk/pkg/registry/core/adapters"
	registrychain "github.com/networkservicemesh/sdk/pkg/registry/core/chain"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"github.com/networkservicemesh/sdk/pkg/tools/log/logruslogger"
	"github.com/networkservicemesh/sdk/pkg/tools/spiffejwt"
	"github.com/networkservicemesh/sdk/pkg/tools/spire"
	"github.com/networkservicemesh/sdk/pkg/tools/token"

	"github.com/networkservicemesh/cmd-forwarder-vpp/internal/vppinit"
)

func (f *ForwarderTestSuite) SetupSuite() {
	logrus.SetFormatter(&nested.Formatter{})
	logrus.SetLevel(logrus.DebugLevel)
	log.EnableTracing(true)
	f.ctx, f.cancel = context.WithCancel(context.Background())
	f.ctx = log.WithLog(f.ctx, logruslogger.New(f.ctx))

	starttime := time.Now()

	// ********************************************************************************
	log.FromContext(f.ctx).Infof("Getting Config from Env (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	_ = os.Setenv("NSM_TUNNEL_IP", forwarderIP)
	_ = os.Setenv("NSM_VPP_INIT", "AF_XDP")
	f.Require().NoError(f.config.Process())

	// ********************************************************************************
	log.FromContext(f.ctx).Infof("Creating test bridge (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	bridgeCancel, err := SetupBridge()
	f.Require().NoError(err)
	f.bridgeCancel = bridgeCancel

	// ********************************************************************************
	log.FromContext(f.ctx).Infof("Creating test vpp Server (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	f.vppServerConn, f.vppServerRoot, f.vppServerErrCh = f.createVpp(f.ctx, "vpp-server")
	_, err = vppinit.LinkToSocket(f.ctx, f.vppServerConn, net.ParseIP(serverIP), vppinit.AfPacket)
	f.Require().NoError(err)

	// ********************************************************************************
	log.FromContext(f.ctx).Infof("Creating test vpp Client (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	f.vppClientConn, f.vppClientRoot, f.vppClientErrCh = f.createVpp(f.ctx, "vpp-client")
	_, err = vppinit.LinkToSocket(f.ctx, f.vppClientConn, net.ParseIP(clientIP), vppinit.AfPacket)
	f.Require().NoError(err)

	// ********************************************************************************
	log.FromContext(f.ctx).Infof("Running Spire (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	executable, err := os.Executable()
	f.Require().NoError(err)
	f.spireErrCh = spire.Start(
		spire.WithContext(f.ctx),
		spire.WithEntry("spiffe://example.org/forwarder", "unix:path:/usr/bin/forwarder"),
		spire.WithEntry(fmt.Sprintf("spiffe://example.org/%s", filepath.Base(executable)),
			fmt.Sprintf("unix:path:%s", executable),
		),
	)
	f.Require().Len(f.spireErrCh, 0)

	// ********************************************************************************
	log.FromContext(f.ctx).Infof("Getting X509Source (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	source, err := workloadapi.NewX509Source(f.ctx)
	f.x509source = source
	f.x509bundle = source
	f.Require().NoError(err)
	svid, err := f.x509source.GetX509SVID()
	f.Require().NoError(err, "error getting x509 svid")
	log.FromContext(f.ctx).Infof("SVID: %q received (time since start: %s)", svid.ID, time.Since(starttime))

	// ********************************************************************************
	log.FromContext(f.ctx).Infof("Running system under test (SUT) (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	f.sutErrCh = exechelper.Start(forwarderName,
		exechelper.WithContext(f.ctx),
		exechelper.WithEnvirons(append(os.Environ(), "NSM_REGISTRY_CLIENT_POLICIES=\"\"")...),
		exechelper.WithStdout(os.Stdout),
		exechelper.WithStderr(os.Stderr),
		exechelper.WithGracePeriod(30*time.Second),
	)
	f.Require().Len(f.sutErrCh, 0)

	// ********************************************************************************
	log.FromContext(f.ctx).Infof("Creating registryServer and registryClient (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	memrg := memory.NewNetworkServiceEndpointRegistryServer()
	f.registryServer = registrychain.NewNetworkServiceEndpointRegistryServer(
		begin.NewNetworkServiceEndpointRegistryServer(),
		expire.NewNetworkServiceEndpointRegistryServer(f.ctx, expire.WithDefaultExpiration(time.Hour)),
		registryrecvfd.NewNetworkServiceEndpointRegistryServer(),
		memrg,
	)

	f.registryNSServer = memory.NewNetworkServiceRegistryServer()

	// ********************************************************************************
	log.FromContext(f.ctx).Infof("Get the regEndpoint from SUT (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	serverCreds := credentials.NewTLS(tlsconfig.MTLSServerConfig(f.x509source, f.x509bundle, tlsconfig.AuthorizeAny()))
	serverCreds = grpcfd.TransportCredentials(serverCreds)
	server := grpc.NewServer(grpc.Creds(serverCreds))

	registry.RegisterNetworkServiceEndpointRegistryServer(server, f.registryServer)
	registry.RegisterNetworkServiceRegistryServer(server, f.registryNSServer)

	f.Require().Len(f.ListenAndServe(f.ctx, &f.config.ConnectTo, server), 0)
	ctx := f.ctx

	recv, err := adapters.NetworkServiceEndpointServerToClient(memrg).Find(ctx, &registry.NetworkServiceEndpointQuery{
		NetworkServiceEndpoint: &registry.NetworkServiceEndpoint{
			NetworkServiceNames: []string{f.config.NSName},
		},
		Watch: true,
	})
	f.Require().NoError(err)

	regEndpoint, err := recv.Recv()
	f.Require().NoError(err)
	log.FromContext(ctx).Infof("Received regEndpoint: %+v (time since start: %s)", regEndpoint, time.Since(starttime))

	// ********************************************************************************
	log.FromContext(f.ctx).Infof("Creating grpc.ClientConn to SUT (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	clientCreds := credentials.NewTLS(tlsconfig.MTLSClientConfig(f.x509source, f.x509bundle, tlsconfig.AuthorizeAny()))
	clientCreds = grpcfd.TransportCredentials(clientCreds)
	f.sutCC, err = grpc.DialContext(f.ctx,
		regEndpoint.NetworkServiceEndpoint.GetUrl(),
		grpc.WithTransportCredentials(clientCreds),
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(
			grpc.PerRPCCredentials(token.NewPerRPCCredentials(spiffejwt.TokenGeneratorFunc(source, f.config.MaxTokenLifetime))),
		),
		grpcfd.WithChainUnaryInterceptor(),
		grpcfd.WithChainStreamInterceptor(),
	)
	f.Require().NoError(err)

	now := time.Now()
	version, err := vpe.NewServiceClient(f.vppClientConn).ShowVersion(ctx, &vpe.ShowVersion{})
	f.Require().NoError(err)
	log.FromContext(ctx).
		WithField("duration", time.Since(now)).
		WithField("vppName", "vpp-client").
		WithField("version", version.Version).Info("complete")

	now = time.Now()
	version, err = vpe.NewServiceClient(f.vppServerConn).ShowVersion(ctx, &vpe.ShowVersion{})
	f.Require().NoError(err)
	log.FromContext(ctx).
		WithField("duration", time.Since(now)).
		WithField("vppName", "vpp-server").
		WithField("version", version.Version).Info("complete")

	// ********************************************************************************
	log.FromContext(f.ctx).Infof("SetupSuite Complete (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
}

func (f *ForwarderTestSuite) createVpp(ctx context.Context, name string) (vppConn vpphelper.Connection, vppRoot string, errCh <-chan error) {
	now := time.Now()
	var err error
	vppRoot, err = os.MkdirTemp("", fmt.Sprintf("%s-", name))
	f.Require().NoError(err)

	f.Require().NoError(err)
	vppConn, errCh = vpphelper.StartAndDialContext(
		ctx,
		vpphelper.WithRootDir(vppRoot),
	)
	f.Require().Len(errCh, 0)
	log.FromContext(ctx).WithField("duration", time.Since(now)).Infof("Launched vpp %q. Access with vppctl -s /tmp/%s/var/run/vpp/cli.sock", vppRoot, vppRoot)
	return vppConn, vppRoot, errCh
}

func (f *ForwarderTestSuite) TearDownSuite() {
	f.cancel()
	f.bridgeCancel()
	for {
		_, ok := <-f.sutErrCh
		if !ok {
			break
		}
	}
	for {
		_, ok := <-f.spireErrCh
		if !ok {
			break
		}
	}
	for {
		_, ok := <-f.vppServerErrCh
		if !ok {
			break
		}
	}
	for {
		_, ok := <-f.vppClientErrCh
		if !ok {
			break
		}
	}
}
