// Copyright (c) 2023-2024 Cisco and/or its affiliates.
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

package tests

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/edwarnicke/exechelper"
	"github.com/edwarnicke/grpcfd"
	"github.com/pkg/errors"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"go.fd.io/govpp/adapter/statsclient"
	"go.fd.io/govpp/api"
	"go.fd.io/govpp/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/networkservicemesh/api/pkg/api/registry"
	"github.com/networkservicemesh/cmd-forwarder-vpp/internal/config"
	"github.com/networkservicemesh/sdk-kernel/pkg/kernel/tools/nshandle"
	"github.com/networkservicemesh/sdk/pkg/registry/common/memory"
	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"github.com/networkservicemesh/sdk/pkg/tools/log/logruslogger"
	"github.com/networkservicemesh/sdk/pkg/tools/spire"
)

// This test shows that the AF_PACKET forwarder interface is capable of receiving data after creation
func Test_VppInit_AfPacket(t *testing.T) {
	forwarderIntName := forwarderName
	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Second*20)
	ctx = log.WithLog(ctx, logruslogger.New(ctx))
	starttime := time.Now()

	// ********************************************************************************
	log.FromContext(ctx).Infof("Creating veth pair and put peer to a different netns (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	curNSHandle, err := nshandle.Current()
	require.NoError(t, err)

	peerNS, err := netns.New()
	require.NoError(t, err)
	defer func() { _ = peerNS.Close() }()

	err = netns.Set(curNSHandle)
	require.NoError(t, err)

	vethCancel, err := setupVeth(forwarderIntName, peerNS)
	require.NoError(t, err)
	defer vethCancel()

	// ********************************************************************************
	log.FromContext(ctx).Infof("Getting Config from Env (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	var cfg config.Config
	_ = os.Setenv("NSM_TUNNEL_IP", forwarderIP)
	_ = os.Setenv("NSM_VPP_INIT", "AF_PACKET")
	require.NoError(t, cfg.Process())

	// ********************************************************************************
	log.FromContext(ctx).Infof("Flooding the interface that will be used by forwarder (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	defer cancelCtx()
	_ = nshandle.RunIn(curNSHandle, peerNS, func() error {
		cmdStr := fmt.Sprintf("ping %s -f", forwarderIP)
		_ = exechelper.Start(cmdStr,
			exechelper.WithContext(ctx),
		)
		return nil
	})

	// ********************************************************************************
	log.FromContext(ctx).Infof("Running Spire (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	executable, err := os.Executable()
	require.NoError(t, err)
	spireErrCh := spire.Start(
		spire.WithContext(ctx),
		spire.WithEntry("spiffe://example.org/forwarder", "unix:path:/usr/bin/forwarder"),
		spire.WithEntry(fmt.Sprintf("spiffe://example.org/%s", filepath.Base(executable)),
			fmt.Sprintf("unix:path:%s", executable),
		),
	)
	require.Len(t, spireErrCh, 0)

	// ********************************************************************************
	log.FromContext(ctx).Infof("Running forwarder app (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	cmdStr := forwarderName
	sutErrCh := exechelper.Start(cmdStr,
		exechelper.WithContext(ctx),
		exechelper.WithEnvirons(append(os.Environ(), "NSM_REGISTRY_CLIENT_POLICIES=\"\"")...),
		exechelper.WithStdout(os.Stdout),
		exechelper.WithStderr(os.Stderr),
		exechelper.WithGracePeriod(30*time.Second),
	)
	require.Len(t, sutErrCh, 0)

	source, err := workloadapi.NewX509Source(ctx)
	x509source := source
	x509bundle := source
	require.NoError(t, err)
	svid, err := x509source.GetX509SVID()
	require.NoError(t, err, "error getting x509 svid")
	log.FromContext(ctx).Infof("SVID: %q received (time since start: %s)", svid.ID, time.Since(starttime))

	registryServer := memory.NewNetworkServiceEndpointRegistryServer()
	serverCreds := credentials.NewTLS(tlsconfig.MTLSServerConfig(x509source, x509bundle, tlsconfig.AuthorizeAny()))
	serverCreds = grpcfd.TransportCredentials(serverCreds)
	server := grpc.NewServer(grpc.Creds(serverCreds))
	registry.RegisterNetworkServiceEndpointRegistryServer(server, registryServer)

	errCh := grpcutils.ListenAndServe(ctx, &cfg.ConnectTo, server)
	select {
	case err = <-errCh:
		require.NoError(t, err)
	default:
	}

	// ********************************************************************************
	log.FromContext(ctx).Infof("Getting forwarder interface statistic (time since start: %s)", time.Since(starttime))
	// ********************************************************************************
	statsConn, err := core.ConnectStats(statsclient.NewStatsClient(""))
	require.NoError(t, err)
	defer statsConn.Disconnect()

	packetsReceived := false
	defer func() { require.True(t, packetsReceived) }()

	// Сheck until we receive packets or ctx.Done()
	for stats := new(api.InterfaceStats); len(stats.Interfaces) < 2 || !packetsReceived; time.Sleep(time.Millisecond * 100) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if e := statsConn.GetInterfaceStats(stats); e != nil {
			log.FromContext(ctx).Errorf("getting interface stats failed:", e)
			continue
		}

		for idx := range stats.Interfaces {
			iface := &stats.Interfaces[idx]
			if !strings.Contains(iface.InterfaceName, forwarderIntName) {
				continue
			}
			if iface.Rx.Packets > 0 {
				packetsReceived = true
				return
			}
			break
		}
	}
}

func setupVeth(forwarderIntName string, peerNS netns.NsHandle) (cancelVeth func(), err error) {
	fwdAddr := &net.IPNet{
		IP: net.ParseIP(forwarderIP), Mask: net.CIDRMask(24, 32),
	}
	peerAddr := &net.IPNet{
		IP: net.ParseIP(clientIP), Mask: net.CIDRMask(24, 32),
	}

	la := netlink.NewLinkAttrs()
	la.Name = forwarderIntName
	l := &netlink.Veth{
		LinkAttrs: la,
		PeerName:  la.Name + "-peer",
	}
	if err = netlink.LinkAdd(l); err != nil {
		return nil, errors.Wrapf(err, "unable to create link %s", l.PeerName)
	}

	if err = netlink.LinkSetUp(l); err != nil {
		return nil, errors.Wrapf(err, "unable to up link %s", l.Attrs().Name)
	}

	if err = netlink.AddrAdd(l, &netlink.Addr{IPNet: fwdAddr}); err != nil {
		return nil, errors.Wrapf(err, "unable to add address %s to link %s", fwdAddr, l.Attrs().Name)
	}

	peer, err := netlink.LinkByName(l.PeerName)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get link %s", l.PeerName)
	}

	if err = netlink.LinkSetNsFd(peer, int(peerNS)); err != nil {
		return nil, errors.Wrapf(err, "unable to set peer netns")
	}

	curNSHandle, err := nshandle.Current()
	if err != nil {
		return nil, err
	}
	defer func() { _ = curNSHandle.Close() }()

	peerNSHandle, err := netlink.NewHandleAtFrom(peerNS, curNSHandle)
	if err != nil {
		return nil, err
	}
	defer peerNSHandle.Close()

	peer, err = peerNSHandle.LinkByName(l.PeerName)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get peer %s", peer.Attrs().Name)
	}

	if err := peerNSHandle.AddrAdd(peer, &netlink.Addr{IPNet: peerAddr}); err != nil {
		return nil, errors.Wrapf(err, "unable to add address %s to peer %s", peerAddr, peer.Attrs().Name)
	}

	if err := peerNSHandle.LinkSetUp(peer); err != nil {
		return nil, errors.Wrapf(err, "unable to up link %s", peer.Attrs().Name)
	}

	return func() {
		_ = netlink.LinkDel(l)
	}, nil
}
