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

package main

import (
	"context"
	"io/ioutil"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/edwarnicke/debug"
	"github.com/edwarnicke/grpcfd"
	"github.com/edwarnicke/log"
	"github.com/edwarnicke/signalctx"
	"github.com/edwarnicke/vpphelper"
	"github.com/golang/protobuf/ptypes"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	registryapi "github.com/networkservicemesh/api/pkg/api/registry"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/chains/xconnectns"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	registrysendfd "github.com/networkservicemesh/sdk/pkg/registry/common/sendfd"
	registrychain "github.com/networkservicemesh/sdk/pkg/registry/core/chain"
	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
	"github.com/networkservicemesh/sdk/pkg/tools/spiffejwt"

	"github.com/networkservicemesh/cmd-forwarder-vpp/internal/vppinit"
)

// Config - configuration for cmd-forwarder-vpp
type Config struct {
	Name             string        `default:"forwarder" desc:"Name of Endpoint"`
	NSName           string        `default:"xconnectns" desc:"Name of Network Service to Register with Registry"`
	TunnelIP         net.IP        `desc:"IP to use for tunnels" split_words:"true"`
	ConnectTo        url.URL       `default:"unix:///connect.to.socket" desc:"url to connect to" split_words:"true"`
	MaxTokenLifetime time.Duration `default:"24h" desc:"maximum lifetime of tokens" split_words:"true"`
}

func main() {
	// ********************************************************************************
	// setup context to catch signals
	// ********************************************************************************
	ctx := signalctx.WithSignals(context.Background())
	ctx, cancel := context.WithCancel(ctx)

	// ********************************************************************************
	// setup logging
	// ********************************************************************************
	logrus.SetFormatter(&nested.Formatter{})
	ctx = log.WithField(ctx, "cmd", os.Args[0])

	// ********************************************************************************
	// Debug self if necessary
	// ********************************************************************************
	if err := debug.Self(); err != nil {
		log.Entry(ctx).Infof("%s", err)
	}

	starttime := time.Now()

	// enumerating phases
	log.Entry(ctx).Infof("there are 6 phases which will be executed followed by a success message:")
	log.Entry(ctx).Infof("the phases include:")
	log.Entry(ctx).Infof("1: get config from environment")
	log.Entry(ctx).Infof("2: run vpp and get a connection to it")
	log.Entry(ctx).Infof("3: retrieve spiffe svid")
	log.Entry(ctx).Infof("4: create xconnect network service endpoint")
	log.Entry(ctx).Infof("5: create grpc server and register xconnect")
	log.Entry(ctx).Infof("6: register xconnectns with the registry")
	log.Entry(ctx).Infof("a final success message with start time duration")

	// ********************************************************************************
	log.Entry(ctx).Infof("executing phase 1: get config from environment (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	now := time.Now()
	config := &Config{}
	if err := envconfig.Usage("nsm", config); err != nil {
		logrus.Fatal(err)
	}
	if err := envconfig.Process("nsm", config); err != nil {
		logrus.Fatalf("error processing config from env: %+v", err)
	}

	log.Entry(ctx).Infof("Config: %#v", config)
	log.Entry(ctx).WithField("duration", time.Since(now)).Infof("completed phase 1: get config from environment")

	// ********************************************************************************
	log.Entry(ctx).Infof("executing phase 2: run vpp and get a connection to it (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	now = time.Now()
	vppCtx, vppCancel := context.WithTimeout(ctx, time.Second)
	defer vppCancel()
	vppConn, vppErrCh := vpphelper.StartAndDialContext(ctx, vpphelper.WithConnectContext(vppCtx))
	exitOnErrCh(ctx, cancel, vppErrCh)
	log.Entry(ctx).WithField("duration", time.Since(now)).Info("completed phase 2: run vpp and get a connection to it")

	// ********************************************************************************
	log.Entry(ctx).Infof("executing phase 3: retrieving svid, check spire agent logs if this is the last line you see (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	now = time.Now()
	source, err := workloadapi.NewX509Source(ctx)
	if err != nil {
		logrus.Fatalf("error getting x509 source: %+v", err)
	}
	svid, err := source.GetX509SVID()
	if err != nil {
		logrus.Fatalf("error getting x509 svid: %+v", err)
	}
	logrus.Infof("SVID: %q", svid.ID)
	log.Entry(ctx).WithField("duration", time.Since(now)).Info("completed phase 3: retrieving svid")

	// ********************************************************************************
	log.Entry(ctx).Infof("executing phase 4: create xconnect network service endpoint (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	now = time.Now()
	tmpDir, err := ioutil.TempDir("", "forwarder-")
	if err != nil {
		logrus.Fatalf("error creating tmpDir %+v", err)
	}
	defer func(tmpDir string) { _ = os.Remove(tmpDir) }(tmpDir)
	memifSocketDir := filepath.Join(tmpDir, "memif")
	err = os.Mkdir(memifSocketDir, 0700)
	if err != nil {
		logrus.Fatalf("error creating dir %s: %+v", memifSocketDir, err)
	}

	endpoint := xconnectns.NewServer(
		ctx,
		config.Name,
		authorize.NewServer(),
		spiffejwt.TokenGeneratorFunc(source, config.MaxTokenLifetime),
		&config.ConnectTo,
		vppConn,
		memifSocketDir,
		vppinit.Must(vppinit.LinkToAfPacket(ctx, vppConn, config.TunnelIP)),
		grpc.WithTransportCredentials(grpcfd.TransportCredentials(credentials.NewTLS(tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())))),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	)
	log.Entry(ctx).WithField("duration", time.Since(now)).Info("completed phase 4: create xconnect network service endpoint")

	// ********************************************************************************
	log.Entry(ctx).Infof("executing phase 5: create grpc server and register xconnect (time since start: %s)", time.Since(starttime))
	// TODO add serveroptions for tracing
	// ********************************************************************************
	now = time.Now()
	server := grpc.NewServer(grpc.Creds(grpcfd.TransportCredentials(credentials.NewTLS(tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny())))))
	endpoint.Register(server)
	listenOn := &(url.URL{Scheme: "unix", Path: filepath.Join(tmpDir, "listen.on")})
	srvErrCh := grpcutils.ListenAndServe(ctx, listenOn, server)
	exitOnErrCh(ctx, cancel, srvErrCh)
	log.Entry(ctx).WithField("duration", time.Since(now)).Info("completed phase 5: create grpc server and register xconnect")

	// ********************************************************************************
	log.Entry(ctx).Infof("executing phase 6: register %s with the registry (time since start: %s)", config.NSName, time.Since(starttime))
	// ********************************************************************************
	now = time.Now()
	registryCreds := credentials.NewTLS(tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny()))
	registryCreds = grpcfd.TransportCredentials(registryCreds)
	registryCC, err := grpc.DialContext(ctx,
		config.ConnectTo.String(),
		grpc.WithTransportCredentials(registryCreds),
		grpc.WithBlock(),
	)
	if err != nil {
		log.Entry(ctx).Fatalf("failed to connect to registry: %+v", err)
	}

	registryClient := registrychain.NewNetworkServiceEndpointRegistryClient(
		// TODO - add refresh
		registrysendfd.NewNetworkServiceEndpointRegistryClient(),
		registryapi.NewNetworkServiceEndpointRegistryClient(registryCC),
	)
	// TODO - something smarter for expireTime
	expireTime, err := ptypes.TimestampProto(time.Now().Add(config.MaxTokenLifetime))
	if err != nil {
		log.Entry(ctx).Fatalf("failed to connect to registry: %+v", err)
	}
	_, err = registryClient.Register(ctx, &registryapi.NetworkServiceEndpoint{
		Name:                config.Name,
		NetworkServiceNames: []string{config.NSName},
		Url:                 listenOn.String(),
		ExpirationTime:      expireTime,
	})
	if err != nil {
		log.Entry(ctx).Fatalf("failed to connect to registry: %+v", err)
	}
	log.Entry(ctx).WithField("duration", time.Since(now)).Infof("completed phase 6: register %s with the registry", config.NSName)

	log.Entry(ctx).Infof("Startup completed in %v", time.Since(starttime))

	// TODO - cleaner shutdown across these three channels
	<-ctx.Done()
	<-srvErrCh
	<-vppErrCh
}

func exitOnErrCh(ctx context.Context, cancel context.CancelFunc, errCh <-chan error) {
	// If we already have an error, log it and exit
	select {
	case err := <-errCh:
		log.Entry(ctx).Fatal(err)
	default:
	}
	// Otherwise wait for an error in the background to log and cancel
	go func(ctx context.Context, errCh <-chan error) {
		err := <-errCh
		log.Entry(ctx).Error(err)
		cancel()
	}(ctx, errCh)
}
