// Copyright (c) 2020-2022 Cisco and/or its affiliates.
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
// +build linux

package main

import (
	"context"
	"crypto/tls"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/edwarnicke/debug"
	"github.com/edwarnicke/grpcfd"
	"github.com/edwarnicke/vpphelper"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	registryapi "github.com/networkservicemesh/api/pkg/api/registry"
	"github.com/networkservicemesh/sdk-k8s/pkg/tools/deviceplugin"
	"github.com/networkservicemesh/sdk-k8s/pkg/tools/podresources"
	"github.com/networkservicemesh/sdk-sriov/pkg/networkservice/common/resourcepool"
	sriovconfig "github.com/networkservicemesh/sdk-sriov/pkg/sriov/config"
	"github.com/networkservicemesh/sdk-sriov/pkg/sriov/pci"
	"github.com/networkservicemesh/sdk-sriov/pkg/sriov/resource"
	sriovtoken "github.com/networkservicemesh/sdk-sriov/pkg/sriov/token"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/cleanup"
	registryclient "github.com/networkservicemesh/sdk/pkg/registry/chains/client"
	registryauthorize "github.com/networkservicemesh/sdk/pkg/registry/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/registry/common/sendfd"
	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"github.com/networkservicemesh/sdk/pkg/tools/log/logruslogger"
	authmonitor "github.com/networkservicemesh/sdk/pkg/tools/monitorconnection/authorize"
	"github.com/networkservicemesh/sdk/pkg/tools/opentelemetry"
	"github.com/networkservicemesh/sdk/pkg/tools/spiffejwt"
	"github.com/networkservicemesh/sdk/pkg/tools/spire"
	"github.com/networkservicemesh/sdk/pkg/tools/token"
	"github.com/networkservicemesh/sdk/pkg/tools/tracing"

	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/mechanisms/vxlan"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/stats"

	"github.com/networkservicemesh/cmd-forwarder-vpp/internal/config"
	"github.com/networkservicemesh/cmd-forwarder-vpp/internal/devicecfg"
	"github.com/networkservicemesh/cmd-forwarder-vpp/internal/vppinit"
	"github.com/networkservicemesh/cmd-forwarder-vpp/internal/xconnectns"
)

func main() {
	// ********************************************************************************
	// setup context to catch signals
	// ********************************************************************************
	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		// More Linux signals here
		syscall.SIGHUP,
		syscall.SIGTERM,
		syscall.SIGQUIT,
	)
	defer cancel()

	// ********************************************************************************
	// setup logging
	// ********************************************************************************
	logrus.SetFormatter(&nested.Formatter{})
	ctx = log.WithLog(ctx, logruslogger.New(ctx, map[string]interface{}{"cmd": os.Args[0]}))

	// ********************************************************************************
	// Debug self if necessary
	// ********************************************************************************
	if err := debug.Self(); err != nil {
		log.FromContext(ctx).Infof("%s", err)
	}

	starttime := time.Now()

	// enumerating phases
	log.FromContext(ctx).Infof("there are 9 phases which will be executed followed by a success message:")
	log.FromContext(ctx).Infof("the phases include:")
	log.FromContext(ctx).Infof("1: get config from environment")
	log.FromContext(ctx).Infof("2: run vpp and get a connection to it")
	log.FromContext(ctx).Infof("3: get SR-IOV config from file")
	log.FromContext(ctx).Infof("4: init pools")
	log.FromContext(ctx).Infof("5: start device plugin server")
	log.FromContext(ctx).Infof("6: retrieve spiffe svid")
	log.FromContext(ctx).Infof("7: create xconnect network service endpoint")
	log.FromContext(ctx).Infof("8: create grpc server and register xconnect")
	log.FromContext(ctx).Infof("9: register xconnectns with the registry")
	log.FromContext(ctx).Infof("a final success message with start time duration")

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 1: get config from environment (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	now := time.Now()

	cfg := new(config.Config)
	if err := cfg.Process(); err != nil {
		logrus.Fatal(err)
	}
	log.FromContext(ctx).Infof("Config: %#v", cfg)

	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logrus.Fatalf("invalid log level %s", cfg.LogLevel)
	}
	logrus.SetLevel(level)
	log.EnableTracing(level == logrus.TraceLevel)
	log.FromContext(ctx).WithField("duration", time.Since(now)).Infof("completed phase 1: get config from environment")

	// ********************************************************************************
	// Configure Open Telemetry
	// ********************************************************************************
	if opentelemetry.IsEnabled() {
		collectorAddress := cfg.OpenTelemetryEndpoint
		spanExporter := opentelemetry.InitSpanExporter(ctx, collectorAddress)
		metricExporter := opentelemetry.InitMetricExporter(ctx, collectorAddress)
		o := opentelemetry.Init(ctx, spanExporter, metricExporter, cfg.Name)
		defer func() {
			if err = o.Close(); err != nil {
				log.FromContext(ctx).Error(err.Error())
			}
		}()
	}

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 2: run vpp and get a connection to it (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	now = time.Now()

	var vppConn vpphelper.Connection
	var vppErrCh <-chan error
	var statsOpts []stats.Option
	cleanupDoneCh := make(chan struct{})
	cleanupOpts := []cleanup.Option{
		cleanup.WithoutGRPCCall(),
	}

	if fileExists(cfg.VppAPISocket) { // If we have an external VppAPISocket, use that
		vppConn = vpphelper.DialContext(ctx, cfg.VppAPISocket)
		errCh := make(chan error)
		close(errCh)
		vppErrCh = errCh
		dir, _ := path.Split(cfg.VppAPISocket)
		statsOpts = append(statsOpts, stats.WithSocket(path.Join(dir, "stats.sock")))
		cleanupOpts = append(cleanupOpts, cleanup.WithDoneChan(cleanupDoneCh))

		log.FromContext(ctx).Info("external vpp is being used")
	} else { // If we don't have a VPPAPISocket, start VPP and use that
		if err = cfg.VppInit.Decode("AF_PACKET"); err != nil {
			log.FromContext(ctx).Fatalf("VppInit.Decode error: %v", err)
		}
		vppConn, vppErrCh = vpphelper.StartAndDialContext(ctx)
		exitOnErrCh(ctx, cancel, vppErrCh)
		close(cleanupDoneCh)
		log.FromContext(ctx).Info("local vpp is being used")
	}

	log.FromContext(ctx).WithField("duration", time.Since(now)).Info("completed phase 2: run vpp and get a connection to it")

	// ********************************************************************************
	// executing phases 3-5
	// ********************************************************************************
	sriovConfig, pciPool, resourcePool := setupSRIOV(ctx, cfg, starttime)

	if sriovConfig == nil {
		log.FromContext(ctx).Warn("SR-IOV is not enabled")
	}

	deviceMap := setupDeviceMap(ctx, cfg)
	err = vppinit.InitLinks(ctx, vppConn, deviceMap, cfg.TunnelIP)
	if err != nil {
		log.FromContext(ctx).Warnf("Link init failed %+v", err)
	}

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 6: retrieving svid, check spire agent logs if this is the last line you see (time since start: %s)", time.Since(starttime))
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

	log.FromContext(ctx).WithField("duration", time.Since(now)).Info("completed phase 6: retrieving svid")

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 7: create xconnect network service endpoint (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	now = time.Now()

	tlsClientConfig := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeAny())
	tlsClientConfig.MinVersion = tls.VersionTLS12
	tlsServerConfig := tlsconfig.MTLSServerConfig(source, source, tlsconfig.AuthorizeAny())
	tlsServerConfig.MinVersion = tls.VersionTLS12

	dialOptions := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithTransportCredentials(
			grpcfd.TransportCredentials(credentials.NewTLS(tlsClientConfig))),
		grpc.WithDefaultCallOptions(
			grpc.PerRPCCredentials(token.NewPerRPCCredentials(spiffejwt.TokenGeneratorFunc(source, cfg.MaxTokenLifetime))),
		),
		grpcfd.WithChainStreamInterceptor(),
		grpcfd.WithChainUnaryInterceptor(),
	}
	spiffeIDConnMap := spire.SpiffeIDConnectionMap{}
	endpoint := xconnectns.NewServer(
		ctx,
		spiffejwt.TokenGeneratorFunc(source, cfg.MaxTokenLifetime),
		vppConn,
		vppinit.Must(cfg.VppInit.Execute(ctx, vppConn, cfg.TunnelIP)),
		pciPool,
		resourcePool,
		sriovConfig,
		cfg.VFIOPath, cfg.CgroupPath,
		xconnectns.WithName(cfg.Name),
		xconnectns.WithAuthorizeServer(authorize.NewServer(authorize.WithSpiffeIDConnectionMap(&spiffeIDConnMap))),
		xconnectns.WithAuthorizeMonitorConnectionsServer(authmonitor.NewMonitorConnectionServer(authmonitor.WithSpiffeIDConnectionMap(&spiffeIDConnMap))),
		xconnectns.WithVlanDomain2Device(deviceMap),
		xconnectns.WithMechanismPriority(cfg.MechanismPriority),
		xconnectns.WithClientURL(&cfg.ConnectTo),
		xconnectns.WithDialTimeout(cfg.DialTimeout),
		xconnectns.WithStatsOptions(statsOpts...),
		xconnectns.WithCleanupOptions(cleanupOpts...),
		xconnectns.WithVxlanOptions(vxlan.WithPort(cfg.VxlanPort)),
		xconnectns.WithDialOptions(dialOptions...),
	)

	log.FromContext(ctx).WithField("duration", time.Since(now)).Info("completed phase 7: create xconnect network service endpoint")

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 8: create grpc server and register xconnect (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	now = time.Now()

	server := grpc.NewServer(
		// TODO add serveroptions for tracing
		grpc.Creds(
			grpcfd.TransportCredentials(
				credentials.NewTLS(tlsServerConfig))),
	)
	endpoint.Register(server)

	srvErrCh := grpcutils.ListenAndServe(ctx, &cfg.ListenOn, server)
	exitOnErrCh(ctx, cancel, srvErrCh)

	log.FromContext(ctx).WithField("duration", time.Since(now)).Info("completed phase 8: create grpc server and register xconnect")

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 9: register %s with the registry (time since start: %s)", cfg.NSName, time.Since(starttime))
	// ********************************************************************************
	now = time.Now()

	clientOptions := append(
		tracing.WithTracingDial(),
		grpc.WithBlock(),
		grpc.WithDefaultCallOptions(
			grpc.WaitForReady(true),
			grpc.PerRPCCredentials(token.NewPerRPCCredentials(spiffejwt.TokenGeneratorFunc(source, cfg.MaxTokenLifetime)))),
		grpc.WithTransportCredentials(
			grpcfd.TransportCredentials(
				credentials.NewTLS(tlsClientConfig))),
		grpcfd.WithChainStreamInterceptor(),
		grpcfd.WithChainUnaryInterceptor(),
	)

	registryClient := registryclient.NewNetworkServiceEndpointRegistryClient(ctx,
		registryclient.WithClientURL(&cfg.ConnectTo),
		registryclient.WithDialOptions(clientOptions...),
		registryclient.WithNSEAdditionalFunctionality(
			sendfd.NewNetworkServiceEndpointRegistryClient(),
		),
		registryclient.WithAuthorizeNSERegistryClient(registryauthorize.NewNetworkServiceEndpointRegistryClient()),
	)
	_, err = registryClient.Register(ctx, &registryapi.NetworkServiceEndpoint{
		Name: cfg.Name,
		NetworkServiceLabels: map[string]*registryapi.NetworkServiceLabels{
			cfg.NSName: {
				Labels: cfg.Labels,
			},
		},
		NetworkServiceNames: []string{cfg.NSName},
		Url:                 cfg.ListenOn.String(),
	})
	if err != nil {
		log.FromContext(ctx).Fatalf("failed to connect to registry: %+v", err)
	}

	log.FromContext(ctx).WithField("duration", time.Since(now)).Infof("completed phase 9: register %s with the registry", cfg.NSName)

	log.FromContext(ctx).Infof("Startup completed in %v", time.Since(starttime))

	// TODO - cleaner shutdown across these channels
	<-ctx.Done()
	<-srvErrCh
	<-vppErrCh
	<-cleanupDoneCh
}

func setupDeviceMap(ctx context.Context, cfg *config.Config) map[string]string {
	if cfg.DeviceSelectorFile == "" {
		return nil
	}
	device2LabSel, err := devicecfg.ReadConfig(ctx, cfg.DeviceSelectorFile)
	if err != nil {
		log.FromContext(ctx).Fatalf("failed to get device selector configuration file: %+v", err)
	}
	if len(device2LabSel.Interfaces) == 0 {
		log.FromContext(ctx).Warn("skipping matching labels to device names: empty interface list")
		return nil
	}
	l2d := make(map[string]string)

	for _, device := range device2LabSel.Interfaces {
		for i := range device.Matches {
			for j := range device.Matches[i].LabelSelector {
				l2d[device.Matches[i].LabelSelector[j].Via] = device.Name
			}
		}
	}
	return l2d
}

func setupSRIOV(ctx context.Context, cfg *config.Config, starttime time.Time) (*sriovconfig.Config, resourcepool.PCIPool, resourcepool.ResourcePool) {
	if cfg.SRIOVConfigFile == "" {
		log.FromContext(ctx).Warn("skipping phases 3-5: no PCI resources config")
		return nil, nil, nil
	}

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 3: get SR-IOV config from file (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	now := time.Now()

	sriovConfig, err := sriovconfig.ReadConfig(ctx, cfg.SRIOVConfigFile)
	if err != nil {
		log.FromContext(ctx).Fatalf("failed to get PCI resources config: %+v", err)
	}

	if err = pci.UpdateConfig(cfg.PCIDevicesPath, cfg.PCIDriversPath, sriovConfig); err != nil {
		log.FromContext(ctx).Fatalf("failed to update PCI resources config with VFs: %+v", err)
	}

	log.FromContext(ctx).WithField("duration", time.Since(now)).Infof("completed phase 3: get SR-IOV config from file")

	if len(sriovConfig.PhysicalFunctions) == 0 {
		log.FromContext(ctx).Warn("skipping phases 4-5: empty PF list")
		return nil, nil, nil
	}

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 4: init pools (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	now = time.Now()

	tokenPool := sriovtoken.NewPool(sriovConfig)

	pciPool, err := pci.NewPool(cfg.PCIDevicesPath, cfg.PCIDriversPath, cfg.VFIOPath, sriovConfig)
	if err != nil {
		log.FromContext(ctx).Fatalf("failed to init PCI pool: %+v", err)
	}

	resourcePool := resource.NewPool(tokenPool, sriovConfig)

	log.FromContext(ctx).WithField("duration", time.Since(now)).Infof("completed phase 4: init pools")

	// ********************************************************************************
	log.FromContext(ctx).Infof("executing phase 5: start device plugin server (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	now = time.Now()

	if err = deviceplugin.StartServers(
		ctx,
		tokenPool,
		cfg.ResourcePollTimeout,
		deviceplugin.NewClient(cfg.DevicePluginPath),
		podresources.NewClient(cfg.PodResourcesPath),
	); err != nil {
		log.FromContext(ctx).Fatalf("failed to start a device plugin server: %+v", err)
	}

	log.FromContext(ctx).WithField("duration", time.Since(now)).Infof("completed phase 5: start device plugin server")

	return sriovConfig, pciPool, resourcePool
}

func exitOnErrCh(ctx context.Context, cancel context.CancelFunc, errCh <-chan error) {
	// If we already have an error, log it and exit
	select {
	case err := <-errCh:
		log.FromContext(ctx).Fatal(err)
	default:
	}
	// Otherwise wait for an error in the background to log and cancel
	go func(ctx context.Context, errCh <-chan error) {
		err := <-errCh
		log.FromContext(ctx).Error(err)
		cancel()
	}(ctx, errCh)
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
