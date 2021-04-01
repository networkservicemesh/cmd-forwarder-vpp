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

// Package vppinit contains initialization code for vpp
package vppinit

import (
	"context"
	"fmt"
	"net"
	"time"

	"git.fd.io/govpp.git/api"
	"github.com/edwarnicke/govpp/binapi/af_packet"
	"github.com/edwarnicke/govpp/binapi/fib_types"
	interfaces "github.com/edwarnicke/govpp/binapi/interface"
	"github.com/edwarnicke/govpp/binapi/interface_types"
	"github.com/edwarnicke/govpp/binapi/ip"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"

	"github.com/networkservicemesh/sdk-vpp/pkg/tools/types"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
)

// Must - simple wrapper to panic in the event of an error
func Must(tunnelIP net.IP, err error) net.IP {
	if err != nil {
		panic(fmt.Sprintf("error: %+v", err))
	}
	return tunnelIP
}

// LinkToAfPacket - will link vpp via af_packet to the interface having the tunnelIP
// if tunnelIP is nil, it will find the interface for the default route and use that instead.
// It returns the resulting tunnelIP
func LinkToAfPacket(ctx context.Context, vppConn api.Connection, tunnelIP net.IP) (net.IP, error) {
	link, addrs, routes, err := linkAddrsRoutes(ctx, tunnelIP)
	if err != nil {
		return nil, err
	}
	if link == nil {
		return tunnelIP, nil
	}

	swIfIndex, err := createAfPacket(ctx, vppConn, link)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	_, err = interfaces.NewServiceClient(vppConn).SwInterfaceSetFlags(ctx, &interfaces.SwInterfaceSetFlags{
		SwIfIndex: swIfIndex,
		Flags:     interface_types.IF_STATUS_API_FLAG_ADMIN_UP,
	})
	if err != nil {
		return nil, err
	}
	log.FromContext(ctx).
		WithField("swIfIndex", swIfIndex).
		WithField("duration", time.Since(now)).
		WithField("vppapi", "SwInterfaceSetFlags").Debug("completed")

	for _, addr := range addrs {
		if addr.IPNet != nil && addr.IPNet.IP.IsGlobalUnicast() && tunnelIP == nil {
			tunnelIP = addr.IPNet.IP
		}
		if addr.IPNet != nil && addr.IPNet.IP.Equal(tunnelIP) {
			now = time.Now()
			_, err = interfaces.NewServiceClient(vppConn).SwInterfaceAddDelAddress(ctx, &interfaces.SwInterfaceAddDelAddress{
				SwIfIndex: swIfIndex,
				IsAdd:     true,
				Prefix:    types.ToVppAddressWithPrefix(addr.IPNet),
			})
			if err != nil {
				return nil, err
			}
			log.FromContext(ctx).
				WithField("swIfIndex", swIfIndex).
				WithField("prefix", addr.IPNet).
				WithField("isAdd", true).
				WithField("duration", time.Since(now)).
				WithField("vppapi", "SwInterfaceAddDelAddress").Debug("completed")
		}
	}
	ipRouteAddDel := &ip.IPRouteAddDel{
		IsAdd: true,
		Route: ip.IPRoute{
			StatsIndex: 0,
			NPaths:     1,
			Paths: []fib_types.FibPath{
				{
					SwIfIndex: uint32(swIfIndex),
					TableID:   0,
					RpfID:     0,
					Weight:    1,
					Type:      fib_types.FIB_API_PATH_TYPE_NORMAL,
					Flags:     fib_types.FIB_API_PATH_FLAG_NONE,
					Proto:     types.IsV6toFibProto(tunnelIP.To4() == nil),
				},
			},
		},
	}
	for _, route := range routes {
		ipRouteAddDel.Route.Prefix = types.ToVppPrefix(route.Dst)
		if route.Gw != nil {
			ipRouteAddDel.Route.Paths[0].Nh.Address = types.ToVppAddress(route.Gw).Un
		}
		now = time.Now()
		_, err = ip.NewServiceClient(vppConn).IPRouteAddDel(ctx, ipRouteAddDel)
		if err != nil {
			return nil, err
		}
		log.FromContext(ctx).
			WithField("swIfIndex", swIfIndex).
			WithField("prefix", ipRouteAddDel.Route.Prefix).
			WithField("isAdd", true).
			WithField("duration", time.Since(now)).
			WithField("vppapi", "IPRouteAddDel").Debug("completed")
	}
	return tunnelIP, nil
}

func createAfPacket(ctx context.Context, vppConn api.Connection, link netlink.Link) (interface_types.InterfaceIndex, error) {
	afPacketCreate := &af_packet.AfPacketCreate{
		HwAddr:     types.ToVppMacAddress(&link.Attrs().HardwareAddr),
		HostIfName: link.Attrs().Name,
	}
	now := time.Now()
	afPacketCreateRsp, err := af_packet.NewServiceClient(vppConn).AfPacketCreate(ctx, afPacketCreate)
	if err != nil {
		return 0, err
	}
	log.FromContext(ctx).
		WithField("swIfIndex", afPacketCreateRsp.SwIfIndex).
		WithField("duration", time.Since(now)).
		WithField("vppapi", "AfPacketCreate").Debug("completed")

	if err := setMtu(ctx, vppConn, link, afPacketCreateRsp.SwIfIndex); err != nil {
		return 0, err
	}
	return afPacketCreateRsp.SwIfIndex, nil
}

func setMtu(ctx context.Context, vppConn api.Connection, link netlink.Link, swIfIndex interface_types.InterfaceIndex) error {
	now := time.Now()
	setMtu := &interfaces.HwInterfaceSetMtu{
		SwIfIndex: swIfIndex,
		Mtu:       uint16(link.Attrs().MTU),
	}
	_, err := interfaces.NewServiceClient(vppConn).HwInterfaceSetMtu(ctx, setMtu)
	if err != nil {
		return err
	}
	log.FromContext(ctx).
		WithField("swIfIndex", setMtu.SwIfIndex).
		WithField("MTU", setMtu.Mtu).
		WithField("duration", time.Since(now)).
		WithField("vppapi", "HwInterfaceSetMtu").Debug("completed")
	return nil
}

func linkAddrsRoutes(ctx context.Context, tunnelIP net.IP) (netlink.Link, []netlink.Addr, []netlink.Route, error) {
	link, err := linkByIP(ctx, tunnelIP)
	if err != nil {
		return nil, nil, nil, err
	}
	if link == nil {
		return nil, nil, nil, nil
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "error getting addrs for link %s", link.Attrs().Name)
	}
	routes, err := netlink.RouteList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil, nil, nil, errors.Wrapf(err, "could not find routes for link %s", link.Attrs().Name)
	}
	return link, addrs, routes, nil
}

func defaultRouteLink(ctx context.Context) (netlink.Link, error) {
	now := time.Now()
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return nil, errors.Wrap(err, "unable to get routes")
	}

	log.FromContext(ctx).
		WithField("duration", time.Since(now)).
		WithField("netlink", "RouteList").Debug("completed")

	for _, route := range routes {
		// Is it a default route?
		if route.Dst != nil {
			ones, _ := route.Dst.Mask.Size()
			if ones == 0 && (route.Dst.IP.Equal(net.IPv4zero) || route.Dst.IP.Equal(net.IPv6zero)) {
				return netlink.LinkByIndex(route.LinkIndex)
			}
			continue
		}
		if route.Scope == netlink.SCOPE_UNIVERSE {
			return netlink.LinkByIndex(route.LinkIndex)
		}
	}
	return nil, errors.New("no link found for default route")
}

func linkByIP(ctx context.Context, ipaddress net.IP) (netlink.Link, error) {
	if ipaddress == nil {
		return defaultRouteLink(ctx)
	}
	links, err := netlink.LinkList()
	if err != nil {
		return nil, errors.Wrap(err, "unable to get links")
	}
	for _, link := range links {
		addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return nil, errors.Wrap(err, "could not find links for default routes")
		}
		for _, addr := range addrs {
			if addr.IPNet != nil && addr.IPNet.IP.Equal(ipaddress) {
				return link, nil
			}
		}
	}
	return nil, nil
}
