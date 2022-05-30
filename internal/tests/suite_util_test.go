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

package tests

import (
	"context"
	"net"
	"net/url"
	"time"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"

	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
)

const (
	contextTimeout = 100 * time.Second
	forwarderIP    = "10.0.2.1"
	clientIP       = "10.0.2.2"
	serverIP       = "10.0.2.3"
)

func (f *ForwarderTestSuite) ListenAndServe(ctx context.Context, listenOn *url.URL, server *grpc.Server) <-chan error {
	errCh := grpcutils.ListenAndServe(ctx, listenOn, server)
	select {
	case err, ok := <-errCh:
		f.Require().True(ok)
		f.Require().NoError(err)
	default:
	}
	returnErrCh := make(chan error, len(errCh)+1)
	go func(errCh <-chan error, returnErrCh chan<- error) {
		for err := range errCh {
			if err != nil {
				returnErrCh <- errors.Wrap(err, "ListenAndServe")
			}
		}
		close(returnErrCh)
	}(errCh, returnErrCh)
	return returnErrCh
}

func SetupBridge() error {
	la := netlink.NewLinkAttrs()
	la.Name = "bridge"
	bridge := &netlink.Bridge{LinkAttrs: la}
	err := netlink.LinkAdd(bridge)
	if err != nil {
		return errors.Wrapf(err, "could not add %s: %v", la.Name, err)
	}
	if err := netlink.LinkSetUp(bridge); err != nil {
		return errors.Wrapf(err, "failure creating bridge")
	}

	ifaceMap := map[string]*net.IPNet{
		"fowarder": {IP: net.ParseIP(forwarderIP), Mask: net.CIDRMask(24, 32)},
		"client":   {IP: net.ParseIP(clientIP), Mask: net.CIDRMask(24, 32)},
		"server":   {IP: net.ParseIP(serverIP), Mask: net.CIDRMask(24, 32)},
	}
	for ifaceName, netIP := range ifaceMap {
		la := netlink.NewLinkAttrs()
		la.Name = ifaceName
		l := &netlink.Veth{
			LinkAttrs: la,
			PeerName:  la.Name + "-veth",
		}
		if err := netlink.LinkAdd(l); err != nil {
			return errors.Wrapf(err, "unable to create link %s", l.PeerName)
		}
		peer, err := netlink.LinkByName(l.PeerName)
		if err != nil {
			return errors.Wrapf(err, "unable to get link %s", l.PeerName)
		}
		if err := netlink.LinkSetUp(l); err != nil {
			return errors.Wrapf(err, "unable to up link %s", l.Attrs().Name)
		}
		if err := netlink.LinkSetUp(peer); err != nil {
			return errors.Wrapf(err, "unable to up link %s", peer.Attrs().Name)
		}
		if err := netlink.AddrAdd(l, &netlink.Addr{IPNet: netIP}); err != nil {
			return errors.Wrapf(err, "unable to add address %s to link %s", netIP, l.Attrs().Name)
		}

		if err := netlink.LinkSetMaster(peer, bridge); err != nil {
			return errors.Wrapf(err, "unable to add link %s to bridge %s", peer.Attrs().Name, bridge.LinkAttrs.Name)
		}
	}
	return nil
}
