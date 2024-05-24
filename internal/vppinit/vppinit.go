// Copyright (c) 2024 OpenInfra Foundation Europe
//
// Copyright (c) 2020-2023 Cisco and/or its affiliates.
//
// Copyright (c) 2024 Nordix Foundation.
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

// Package vppinit contains initialization code for vpp
package vppinit

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-ping/ping"
	"github.com/safchain/ethtool"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"go.fd.io/govpp/api"

	"github.com/networkservicemesh/govpp/binapi/af_packet"
	"github.com/networkservicemesh/govpp/binapi/af_xdp"
	"github.com/networkservicemesh/govpp/binapi/fib_types"
	interfaces "github.com/networkservicemesh/govpp/binapi/interface"
	"github.com/networkservicemesh/govpp/binapi/interface_types"
	"github.com/networkservicemesh/govpp/binapi/ip"
	"github.com/networkservicemesh/govpp/binapi/ip6_nd"
	"github.com/networkservicemesh/govpp/binapi/ip_neighbor"
	"github.com/networkservicemesh/sdk-vpp/pkg/tools/types"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
)

// AfType represents socket address family
type AfType uint32

const (
	// AfPacket - AF_PACKET
	AfPacket AfType = 0
	// AfXDP - AF_XDP
	AfXDP AfType = 1
)

const (
	// Minimum required kernel version for AF_XDP
	afXdpMajorVer = 5
	afXdpMinorVer = 4

	// Maximum AF_XDP MTU
	afXdpMaxMTU = 3498
)

// Func - vpp initialization function
type Func struct {
	f func(ctx context.Context, vppConn api.Connection, tunnelIP net.IP) (net.IP, error)
}

// Execute vpp initialization function
func (f *Func) Execute(ctx context.Context, vppConn api.Connection, tunnelIP net.IP) (net.IP, error) {
	return f.f(ctx, vppConn, tunnelIP)
}

// Decode for envconfig to select correct vpp initialization function
func (f *Func) Decode(value string) error {
	switch value {
	case "AF_XDP":
		ver, err := getKernelVer()
		if err != nil {
			return err
		}
		if ver[0] > afXdpMajorVer || (ver[0] == afXdpMajorVer && ver[1] >= afXdpMinorVer) {
			f.f = func(ctx context.Context, vppConn api.Connection, tunnelIP net.IP) (net.IP, error) {
				return LinkToSocket(ctx, vppConn, tunnelIP, AfXDP)
			}
			return nil
		}
		log.FromContext(context.Background()).Warn("AF_XDP is not supported by this linux kernel version. AF_PACKET will be used")
		fallthrough
	case "AF_PACKET":
		f.f = func(ctx context.Context, vppConn api.Connection, tunnelIP net.IP) (net.IP, error) {
			return LinkToSocket(ctx, vppConn, tunnelIP, AfPacket)
		}
	case "NONE":
		f.f = None
	default:
		return errors.Errorf("%s invalid valud for VPP init function", value)
	}
	return nil
}

// Must - simple wrapper to panic in the event of an error
func Must(tunnelIP net.IP, err error) net.IP {
	if err != nil {
		panic(fmt.Sprintf("error: %+v", err))
	}
	return tunnelIP
}

// None - will perform no VPP initialization
func None(_ context.Context, _ api.Connection, tunnelIP net.IP) (net.IP, error) {
	return tunnelIP, nil
}

// Get Linux kernel version
// Example: 5.11.0-25-generic -> [5,11]
func getKernelVer() ([2]int, error) {
	var uname syscall.Utsname
	err := syscall.Uname(&uname)
	if err != nil {
		return [2]int{}, err
	}

	b := make([]byte, 0, len(uname.Release))
	for _, v := range uname.Release {
		if v == 0x00 {
			break
		}
		b = append(b, byte(v))
	}
	ver := strings.Split(string(b), ".")
	maj, err := strconv.Atoi(ver[0])
	if err != nil {
		return [2]int{}, err
	}
	min, err := strconv.Atoi(ver[1])
	if err != nil {
		return [2]int{}, err
	}
	return [2]int{maj, min}, nil
}

// LinkToSocket - will link vpp via af_packet or af_xdp to the interface having the tunnelIP
// if tunnelIP is nil, it will find the interface for the default route and use that instead.
// It returns the resulting tunnelIP
func LinkToSocket(ctx context.Context, vppConn api.Connection, tunnelIP net.IP, family AfType) (net.IP, error) {
	link, addrs, routes, err := linkAddrsRoutes(ctx, tunnelIP)
	if err != nil {
		return nil, err
	}
	if link == nil {
		return tunnelIP, nil
	}

	afFunc := createAfPacket
	if family == AfXDP {
		afFunc = createAfXDP
	}

	swIfIndex, err := afFunc(ctx, vppConn, link)
	if err != nil {
		return nil, err
	}

	if mtuErr := setMtu(ctx, vppConn, link, swIfIndex); err != nil {
		return nil, mtuErr
	}

	if aclErr := denyAllACLToInterface(ctx, vppConn, swIfIndex); aclErr != nil {
		return nil, aclErr
	}

	// Disable Router Advertisement on IPv6 tunnels
	if tunnelIP.To4() == nil {
		err = disableIPv6RA(ctx, vppConn, swIfIndex, link.Attrs().Name)
		if err != nil {
			return nil, err
		}
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
		WithField("hostIfName", link.Attrs().Name).
		WithField("duration", time.Since(now)).
		WithField("vppapi", "SwInterfaceSetFlags").Debug("completed")

	err = addIPNeighbor(ctx, vppConn, swIfIndex, link.Attrs().Index, routes)
	if err != nil {
		return nil, err
	}
	err = addHostLinksAsNeighbours(ctx, vppConn, link, swIfIndex)
	if err != nil {
		return nil, err
	}

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
				WithField("hostIfName", link.Attrs().Name).
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
	for i := range routes {
		route := routes[i]
		if route.Gw != nil {
			routeIsIpv6 := route.Gw.To4() == nil
			ipRouteAddDel.Route.Paths[0].Nh.Address = types.ToVppAddress(route.Gw).Un
			ipRouteAddDel.Route.Paths[0].Proto = types.IsV6toFibProto(routeIsIpv6)
			if route.Dst == nil {
				var netString string
				if routeIsIpv6 {
					netString = "::0/0"
				} else {
					netString = "0.0.0.0/0"
				}
				var ipNet *net.IPNet
				_, ipNet, err = net.ParseCIDR(netString)
				if err != nil {
					return nil, err
				}
				route.Dst = ipNet
			}
		}
		ipRouteAddDel.Route.Prefix = types.ToVppPrefix(route.Dst)
		now = time.Now()
		_, err = ip.NewServiceClient(vppConn).IPRouteAddDel(ctx, ipRouteAddDel)
		if err != nil {
			return nil, err
		}
		log.FromContext(ctx).
			WithField("swIfIndex", swIfIndex).
			WithField("hostIfName", link.Attrs().Name).
			WithField("nh.address", types.FromVppIPAddressUnion(ipRouteAddDel.Route.Paths[0].Nh.Address, route.Gw.To4() == nil)).
			WithField("prefix", ipRouteAddDel.Route.Prefix).
			WithField("isAdd", true).
			WithField("duration", time.Since(now)).
			WithField("vppapi", "IPRouteAddDel").Debug("completed")
	}

	return tunnelIP, nil
}

func createAfPacket(ctx context.Context, vppConn api.Connection, link netlink.Link) (interface_types.InterfaceIndex, error) {
	c := GetAfPacketValues(ctx)
	var afPacketCreate *af_packet.AfPacketCreateV3 = &af_packet.AfPacketCreateV3{
		Mode:             c.Mode,
		HwAddr:           types.ToVppMacAddress(&link.Attrs().HardwareAddr),
		HostIfName:       link.Attrs().Name,
		RxFrameSize:      c.RxFrameSize,
		TxFrameSize:      c.TxFrameSize,
		RxFramesPerBlock: c.RxFramesPerBlock,
		TxFramesPerBlock: c.TxFramesPerBlock,
		NumRxQueues:      c.NumRxQueues,
		NumTxQueues:      c.NumTxQueues,
		Flags:            c.Flags,
	}
	now := time.Now()
	afPacketCreateRsp, err := af_packet.NewServiceClient(vppConn).AfPacketCreateV3(ctx, afPacketCreate)
	if err != nil {
		return 0, err
	}
	log.FromContext(ctx).
		WithField("swIfIndex", afPacketCreateRsp.SwIfIndex).
		WithField("HostIfName", link.Attrs().Name).
		WithField("mode", afPacketCreate.Mode).
		WithField("hwaddr", afPacketCreate.HwAddr).
		WithField("hostIfName", afPacketCreate.HostIfName).
		WithField("flags", afPacketCreate.Flags).
		WithField("duration", time.Since(now)).
		WithField("vppapi", "AfPacketCreateV3").Debug("completed")

	return afPacketCreateRsp.SwIfIndex, nil
}

func createAfXDP(ctx context.Context, vppConn api.Connection, link netlink.Link) (interface_types.InterfaceIndex, error) {
	// AF_XDP requires some tweaks on the host side
	rxqNum, err := afxdpHostSettings(ctx, link)
	if err != nil {
		return 0, err
	}
	c := GetAfXdpValues(ctx)
	afXDPCreate := &af_xdp.AfXdpCreate{
		HostIf:  link.Attrs().Name,
		RxqSize: c.RxqSize,
		TxqSize: c.TxqSize,
		RxqNum:  rxqNum,
		Mode:    c.Mode,
		Flags:   c.Flags,
		Prog:    "/bin/afxdp.o",
	}

	now := time.Now()
	afXDPCreateRsp, err := af_xdp.NewServiceClient(vppConn).AfXdpCreate(ctx, afXDPCreate)
	if err != nil {
		log.FromContext(ctx).
			WithField("hostIfName", afXDPCreate.HostIf).
			WithField("duration", time.Since(now)).
			WithField("vppapi", "AfXdpCreate").Error(err)
		return 0, err
	}
	log.FromContext(ctx).
		WithField("swIfIndex", afXDPCreateRsp.SwIfIndex).
		WithField("hostIfName", afXDPCreate.HostIf).
		WithField("duration", time.Since(now)).
		WithField("vppapi", "AfXdpCreate").Debug("completed")

	now = time.Now()
	if _, err = interfaces.NewServiceClient(vppConn).SwInterfaceSetRxMode(ctx, &interfaces.SwInterfaceSetRxMode{
		SwIfIndex: afXDPCreateRsp.SwIfIndex,
		Mode:      interface_types.RX_MODE_API_ADAPTIVE,
	}); err != nil {
		return 0, errors.Wrap(err, "vppapi SwInterfaceSetRxMode returned error")
	}
	log.FromContext(ctx).
		WithField("swIfIndex", afXDPCreateRsp.SwIfIndex).
		WithField("HostIfName", link.Attrs().Name).
		WithField("mode", interface_types.RX_MODE_API_ADAPTIVE).
		WithField("duration", time.Since(now)).
		WithField("vppapi", "SwInterfaceSetRxMode").Debug("completed")

	now = time.Now()
	_, err = interfaces.NewServiceClient(vppConn).SwInterfaceSetMacAddress(ctx, &interfaces.SwInterfaceSetMacAddress{
		SwIfIndex:  afXDPCreateRsp.SwIfIndex,
		MacAddress: types.ToVppMacAddress(&link.Attrs().HardwareAddr),
	})
	if err != nil {
		log.FromContext(ctx).
			WithField("swIfIndex", afXDPCreateRsp.SwIfIndex).
			WithField("HostIfName", link.Attrs().Name).
			WithField("duration", time.Since(now)).
			WithField("vppapi", "SwInterfaceSetMacAddress").Error(err)
		return 0, err
	}
	log.FromContext(ctx).
		WithField("swIfIndex", afXDPCreateRsp.SwIfIndex).
		WithField("HostIfName", link.Attrs().Name).
		WithField("hwaddr", types.ToVppMacAddress(&link.Attrs().HardwareAddr)).
		WithField("duration", time.Since(now)).
		WithField("vppapi", "SwInterfaceSetMacAddress").Debug("completed")

	return afXDPCreateRsp.SwIfIndex, nil
}

func afxdpHostSettings(ctx context.Context, link netlink.Link) (uint16, error) {
	// /sys/fs/bpf - the default dir of BPF filesystem
	err := syscall.Mount("bpffs", "/sys/fs/bpf", "bpf", 0, "")
	if err != nil {
		log.FromContext(ctx).WithField("func", "syscall.Mount").Error(err)
		return 0, err
	}

	// Based on VPP guidelines
	err = netlink.SetPromiscOn(link)
	if err != nil {
		log.FromContext(ctx).WithField("func", "netlink.SetPromiscOn").Error(err)
		return 0, err
	}

	// Limit MTU
	if link.Attrs().MTU > afXdpMaxMTU {
		link.Attrs().MTU = afXdpMaxMTU
		err = netlink.LinkSetMTU(link, afXdpMaxMTU)
		if err != nil {
			log.FromContext(ctx).WithField("func", "netlink.LinkSetMTU").Error(err)
			return 0, err
		}
	}

	// Set the number of queues. We got an error on AWS cluster:
	// # dmesg
	// # Failed to set xdp program, the Rx/Tx channel count should be at most half of the maximum allowed channel count. The current queue count (4), the maximal queue count (4)
	etht, err := ethtool.NewEthtool()
	if err != nil {
		log.FromContext(ctx).WithField("func", "ethtool.NewEthtool").Error(err)
		return 0, err
	}
	channels, err := etht.GetChannels(link.Attrs().Name)
	if err != nil {
		log.FromContext(ctx).WithField("func", "ethtool.GetChannels").Error(err)
		return 0, err
	}
	if channels.MaxTx > 1 && channels.TxCount*2 > channels.MaxTx {
		channels.TxCount = channels.MaxTx / 2
	}
	if channels.MaxRx > 1 && channels.RxCount*2 > channels.MaxRx {
		channels.RxCount = channels.MaxRx / 2
	}
	if channels.MaxCombined > 1 && channels.CombinedCount*2 > channels.MaxCombined {
		channels.CombinedCount = channels.MaxCombined / 2
	}
	_, err = etht.SetChannels(link.Attrs().Name, channels)
	if err != nil {
		log.FromContext(ctx).WithField("func", "ethtool.SetChannels").Error(err)
		return 0, err
	}

	return uint16(channels.CombinedCount), err
}

func addIPNeighbor(ctx context.Context, vppConn api.Connection, swIfIndex interface_types.InterfaceIndex, linkIdx int, routes []netlink.Route) error {
	// Get all gateways for a given interface and send ping requests.
	// This will allow us to resolve the neighbors.
	for i := 0; i < len(routes); i++ {
		if routes[i].Gw == nil {
			continue
		}
		pi := ping.New(routes[i].Gw.String())
		pi.Count = 1
		pi.Timeout = time.Millisecond * 100
		pi.SetPrivileged(true)
		err := pi.Run()
		if err == nil {
			log.FromContext(ctx).Infof("Gateway %v was resolved", routes[0].Gw.String())
		}
	}

	neighList, err := netlink.NeighList(linkIdx, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}
	for i := range neighList {
		entry := neighList[i]
		if entry.State != netlink.NUD_PERMANENT && entry.State != netlink.NUD_REACHABLE {
			continue
		}

		now := time.Now()
		ipNeighborAddDel := &ip_neighbor.IPNeighborAddDel{
			IsAdd: true,
			Neighbor: ip_neighbor.IPNeighbor{
				SwIfIndex:  swIfIndex,
				MacAddress: types.ToVppMacAddress(&entry.HardwareAddr),
				IPAddress:  types.ToVppAddress(entry.IP),
			},
		}
		_, err = ip_neighbor.NewServiceClient(vppConn).IPNeighborAddDel(ctx, ipNeighborAddDel)
		if err != nil {
			return err
		}
		log.FromContext(ctx).
			WithField("swIfIndex", swIfIndex).
			WithField("ipAddress", entry.IP.String()).
			WithField("macAddress", entry.HardwareAddr.String()).
			WithField("duration", time.Since(now)).
			WithField("vppapi", "IPNeighborAddDel").Debug("completed")
	}
	return nil
}

func setMtu(ctx context.Context, vppConn api.Connection, link netlink.Link, swIfIndex interface_types.InterfaceIndex) error {
	now := time.Now()
	setMtu := &interfaces.SwInterfaceSetMtu{
		SwIfIndex: swIfIndex,
		Mtu:       []uint32{uint32(link.Attrs().MTU), uint32(link.Attrs().MTU), uint32(link.Attrs().MTU), uint32(link.Attrs().MTU)},
	}
	_, err := interfaces.NewServiceClient(vppConn).SwInterfaceSetMtu(ctx, setMtu)
	if err != nil {
		return err
	}
	log.FromContext(ctx).
		WithField("swIfIndex", setMtu.SwIfIndex).
		WithField("hostIfName", link.Attrs().Name).
		WithField("MTU", setMtu.Mtu).
		WithField("duration", time.Since(now)).
		WithField("vppapi", "SwInterfaceSetMtu").Debug("completed")
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

	for i := range routes {
		route := routes[i]
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

func disableIPv6RA(ctx context.Context, vppConn api.Connection, swIfIndex interface_types.InterfaceIndex, linkName string) error {
	now := time.Now()
	_, err := ip.NewServiceClient(vppConn).SwInterfaceIP6EnableDisable(ctx,
		&ip.SwInterfaceIP6EnableDisable{
			SwIfIndex: swIfIndex,
			Enable:    true,
		},
	)
	if err != nil {
		log.FromContext(ctx).
			WithField("duration", time.Since(now)).
			WithField("swIfIndex", swIfIndex).
			WithField("swIfName", linkName).
			WithField("vppapi", "SwInterfaceIP6Enable").Error(err)
		return err
	}
	log.FromContext(ctx).
		WithField("duration", time.Since(now)).
		WithField("swIfIndex", swIfIndex).
		WithField("swIfName", linkName).
		WithField("vppapi", "SwInterfaceIP6Enable").Debug("completed")

	now = time.Now()
	_, err = ip6_nd.NewServiceClient(vppConn).SwInterfaceIP6ndRaConfig(ctx, &ip6_nd.SwInterfaceIP6ndRaConfig{
		SwIfIndex: swIfIndex,
		Suppress:  1,
		Cease:     1,
	})
	if err != nil {
		log.FromContext(ctx).
			WithField("duration", time.Since(now)).
			WithField("swIfIndex", swIfIndex).
			WithField("swIfName", linkName).
			WithField("vppapi", "SwInterfaceIP6ndRaConfig").Error(err)
		return err
	}
	log.FromContext(ctx).
		WithField("duration", time.Since(now)).
		WithField("swIfIndex", swIfIndex).
		WithField("swIfName", linkName).
		WithField("vppapi", "SwInterfaceIP6ndRaConfig").Debug("completed")

	return nil
}

func addHostLinksAsNeighbours(ctx context.Context, vppConn api.Connection, link netlink.Link, swIfIndex interface_types.InterfaceIndex) error {
	// Add host links as neighbors. We have no other way to make an ARP request
	hostLinks, err := netlink.LinkList()
	if err != nil {
		return err
	}

	for _, hl := range hostLinks {
		if link.Attrs().Index == hl.Attrs().Index || len(hl.Attrs().HardwareAddr) == 0 {
			continue
		}
		var ips []netlink.Addr
		ips, err = netlink.AddrList(hl, netlink.FAMILY_ALL)
		if err != nil {
			return err
		}
		for _, hlIP := range ips {
			ipNeighborAddDel := &ip_neighbor.IPNeighborAddDel{
				IsAdd: true,
				Neighbor: ip_neighbor.IPNeighbor{
					SwIfIndex:  swIfIndex,
					MacAddress: types.ToVppMacAddress(&hl.Attrs().HardwareAddr),
					IPAddress:  types.ToVppAddress(hlIP.IP),
				},
			}
			_, err = ip_neighbor.NewServiceClient(vppConn).IPNeighborAddDel(ctx, ipNeighborAddDel)
			if err != nil {
				return err
			}
			log.FromContext(ctx).Infof("host link was added as a neighbor: IP: %v, MAC: %v", hlIP.IP.String(), hl.Attrs().HardwareAddr.String())
		}
	}
	return err
}
