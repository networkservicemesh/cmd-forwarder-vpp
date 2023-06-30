// Copyright (c) 2021-2022 Nordix Foundation.
//
// Copyright (c) 2023 Cisco and/or its affiliates.
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

package vppinit

import (
	"context"
	"net"
	"time"

	"git.fd.io/govpp.git/api"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"

	interfaces "github.com/networkservicemesh/govpp/binapi/interface"
	"github.com/networkservicemesh/govpp/binapi/interface_types"

	"github.com/networkservicemesh/sdk/pkg/tools/log"
)

func initDevice(ctx context.Context, vppConn api.Connection, tunnelIP net.IP, device string, errChan chan error) {
	link, err := netlink.LinkByName(device)

	if err != nil {
		err = errors.Wrapf(err, "init for device %s failed", device)
	} else {
		if link == nil {
			err = setPromiscVpp(ctx, vppConn, device)
		} else {
			if !isTunnelLink(link, tunnelIP) {
				err = setupLinkVpp(ctx, vppConn, link)
			}
			if err != nil {
				err = errors.Wrapf(err, "error setting up device %s", device)
			} else {
				setPromiscHw(ctx, link)
			}
		}
	}
	errChan <- err
}

// InitLinks creates AF_PACKET interface if needed and put the given interfaces in promisc mode
func InitLinks(ctx context.Context, vppConn api.Connection, deviceNames map[string]string, tunnelIP net.IP) error {
	ch := make(chan error)
	defer func() {
		go func() {
		}()
	}()

	for _, device := range deviceNames {
		go initDevice(ctx, vppConn, tunnelIP, device, ch)
	}
	for i := 0; i < len(deviceNames); i++ {
		select {
		case <-ctx.Done():
			return errors.Wrapf(ctx.Err(), "timeout waiting for init links")
		case err := <-ch:
			if err != nil {
				log.FromContext(ctx).Warnf("Link init failed (%v)", err)
			}
		}
	}
	return nil
}

func isTunnelLink(link netlink.Link, tunnelIP net.IP) bool {
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		if addr.IPNet != nil && addr.IPNet.IP.Equal(tunnelIP) {
			return true
		}
	}
	return false
}

func setupLinkVpp(ctx context.Context, vppConn api.Connection, link netlink.Link) error {
	swIfIndex, err := createAfPacket(ctx, vppConn, link)
	if err != nil {
		return err
	}

	if mtuErr := setMtu(ctx, vppConn, link, swIfIndex); err != nil {
		return mtuErr
	}

	now := time.Now()
	_, err = interfaces.NewServiceClient(vppConn).SwInterfaceSetFlags(ctx, &interfaces.SwInterfaceSetFlags{
		SwIfIndex: swIfIndex,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	})
	if err != nil {
		return errors.Wrap(err, "unable to set interface admin UP")
	}
	log.FromContext(ctx).
		WithField("swIfIndex", swIfIndex).
		WithField("duration", time.Since(now)).
		WithField("vppapi", "SwInterfaceSetFlags").Debug("completed")
	return nil
}

func setPromiscHw(ctx context.Context, link netlink.Link) {
	now := time.Now()
	err := netlink.SetPromiscOn(link)

	if err != nil {
		log.FromContext(ctx).
			WithField("duration", time.Since(now)).
			WithField("HostInterfaceName", link.Attrs().Name).
			WithField("netlink", "SetPromiscOn").
			Warn("Promiscuous mode not set!")
	} else {
		log.FromContext(ctx).
			WithField("duration", time.Since(now)).
			WithField("HostInterfaceName", link.Attrs().Name).
			WithField("netlink", "SetPromiscOn").Debug("completed")
	}
}

func setPromiscVpp(ctx context.Context, vppConn api.Connection, hostIFName string) error {
	client, err := interfaces.NewServiceClient(vppConn).SwInterfaceDump(ctx, &interfaces.SwInterfaceDump{
		NameFilterValid: true,
		NameFilter:      hostIFName,
	})
	if err != nil {
		return err
	}
	var details *interfaces.SwInterfaceDetails
	details, err = client.Recv()
	if err == nil {
		now := time.Now()
		if _, err = interfaces.NewServiceClient(vppConn).SwInterfaceSetPromisc(ctx, &interfaces.SwInterfaceSetPromisc{
			SwIfIndex: details.SwIfIndex,
			PromiscOn: true,
		}); err == nil {
			log.FromContext(ctx).
				WithField("duration", time.Since(now)).
				WithField("HostInterfaceName", hostIFName).
				WithField("vppapi", "SwInterfaceSetPromisc").Debug("completed")
			return nil
		}
	}
	return err
}
