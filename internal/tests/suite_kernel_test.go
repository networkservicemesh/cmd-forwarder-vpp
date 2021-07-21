// Copyright (c) 2020-2021 Cisco and/or its affiliates.
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
	"os"

	"github.com/edwarnicke/exechelper"
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"google.golang.org/grpc"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/cls"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"

	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/client"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	kernelmechanism "github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/kernel"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/sendfd"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/chain"
	"github.com/networkservicemesh/sdk/pkg/networkservice/ipam/point2pointipam"
	"github.com/networkservicemesh/sdk/pkg/tools/token"

	"github.com/thanhpk/randstr"

	"github.com/networkservicemesh/cmd-forwarder-vpp/internal/tests/ns"
)

type verifiable interface {
	VerifyConnection(conn *networkservice.Connection) error
	VerifyClose(conn *networkservice.Connection) error
}

type verifiableEndpoint interface {
	verifiable
	endpoint.Endpoint
}

type verifiableClient interface {
	verifiable
	networkservice.NetworkServiceClient
}

type kernelVerifiableEndpoint struct {
	ctx              context.Context
	endpointNSName   string
	endpointNSHandle netns.NsHandle
	endpoint.Endpoint
}

func newKernelVerifiableEndpoint(ctx context.Context,
	prefix1, prefix2 *net.IPNet,
	tokenGenerator token.GeneratorFunc,
) verifiableEndpoint {
	rootNSHandle, err := netns.Get()
	if err != nil {
		panic(fmt.Sprintf("unable to get root netNs: %+v", err))
	}
	endpointNSName := fmt.Sprintf("nse-%s", randstr.Hex(4))
	endpointNSHandle, err := netns.NewNamed(endpointNSName)
	if err != nil {
		panic(fmt.Sprintf("unable create netNs %s: %+v", endpointNSName, err))
	}
	go func(endpointNsName string) {
		<-ctx.Done()
		_ = netns.DeleteNamed(endpointNsName)
	}(endpointNSName)
	return &kernelVerifiableEndpoint{
		ctx:              ctx,
		endpointNSName:   endpointNSName,
		endpointNSHandle: endpointNSHandle,
		Endpoint: endpoint.NewServer(
			ctx,
			tokenGenerator,
			endpoint.WithName("kernelVerifiableEndpoint"),
			endpoint.WithAuthorizeServer(authorize.NewServer()),
			endpoint.WithAdditionalFunctionality(
				point2pointipam.NewServer(prefix1),
				point2pointipam.NewServer(prefix2),
				mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
					kernel.MECHANISM: chain.NewNetworkServiceServer(
						kernelmechanism.NewServer(kernelmechanism.WithInterfaceName(endpointNSName)),
					),
				}),
				ns.NewServer(endpointNSHandle),
				sendfd.NewServer(),
				ns.NewServer(rootNSHandle),
			),
		),
	}
}

func (k *kernelVerifiableEndpoint) VerifyConnection(conn *networkservice.Connection) error {
	namingConn := conn.Clone()
	namingConn.Id = conn.GetPath().GetPathSegments()[len(conn.GetPath().GetPathSegments())-1].GetId()
	namingConn.Mechanism = &networkservice.Mechanism{
		Cls:  cls.LOCAL,
		Type: kernel.MECHANISM,
		Parameters: map[string]string{
			kernel.InterfaceNameKey: k.endpointNSName,
		},
	}
	if err := checkKernelInterface(namingConn, conn.GetContext().GetIpContext().GetDstIPNets(), k.endpointNSHandle); err != nil {
		return err
	}
	for _, ip := range conn.GetContext().GetIpContext().GetSrcIPNets() {
		if err := pingKernel(ip, k.endpointNSHandle); err != nil {
			return err
		}
	}
	return nil
}

func (k *kernelVerifiableEndpoint) VerifyClose(conn *networkservice.Connection) error {
	return checkNoKernelInterface(conn, k.endpointNSHandle)
}

type kernelVerifiableClient struct {
	ctx            context.Context
	clientNSHandle netns.NsHandle
	networkservice.NetworkServiceClient
}

func newKernelVerifiableClient(ctx context.Context, sutCC grpc.ClientConnInterface) verifiableClient {
	rootNSHandle, err := netns.Get()
	if err != nil {
		panic(fmt.Sprintf("unable to get root netNs: %+v", err))
	}
	clientNSName := fmt.Sprintf("client-%s", randstr.Hex(4))
	clientNSHandle, err := netns.NewNamed(clientNSName)
	if err != nil {
		panic(fmt.Sprintf("unable create netNs %s: %+v", clientNSName, err))
	}
	go func(clientNSName string) {
		<-ctx.Done()
		_ = netns.DeleteNamed(clientNSName)
	}(clientNSName)

	rv := &kernelVerifiableClient{
		ctx:            ctx,
		clientNSHandle: clientNSHandle,
		NetworkServiceClient: client.NewClientFactory(
			client.WithName("kernelVerifiableClient"),
			client.WithAdditionalFunctionality(
				ns.NewClient(clientNSHandle),
				kernelmechanism.NewClient(),
				sendfd.NewClient(),
				ns.NewClient(rootNSHandle),
			),
		)(ctx, sutCC),
	}
	return rv
}

func (k *kernelVerifiableClient) VerifyConnection(conn *networkservice.Connection) error {
	if err := checkKernelInterface(conn, conn.GetContext().GetIpContext().GetSrcIPNets(), k.clientNSHandle); err != nil {
		return err
	}
	for _, ip := range conn.GetContext().GetIpContext().GetDstIPNets() {
		if err := pingKernel(ip, k.clientNSHandle); err != nil {
			return err
		}
	}
	return nil
}

func (k *kernelVerifiableClient) VerifyClose(conn *networkservice.Connection) error {
	return checkNoKernelInterface(conn, k.clientNSHandle)
}

func checkKernelInterface(conn *networkservice.Connection, ipNets []*net.IPNet, nsHandle netns.NsHandle) error {
	if mechanism := kernel.ToMechanism(conn.GetMechanism()); mechanism != nil {
		curNetNS, err := netns.Get()
		if err != nil {
			return errors.Wrap(err, "unable to get current netns")
		}
		netlinkHandle, err := netlink.NewHandleAtFrom(nsHandle, curNetNS)
		if err != nil {
			return errors.Wrap(err, "unable to get netlink Handle in target netNs")
		}
		ifaceName := mechanism.GetInterfaceName()
		link, err := netlinkHandle.LinkByName(ifaceName)
		if err != nil {
			return errors.Wrapf(err, "unable to find interface %q", ifaceName)
		}
		addrs, err := netlinkHandle.AddrList(link, netlink.FAMILY_ALL)
		if err != nil {
			return errors.Wrapf(err, "unable to list addresses for interface %q", ifaceName)
		}
		for _, ipNet := range ipNets {
			found := false
			for _, addr := range addrs {
				if addr.IP.Equal(ipNet.IP) && addr.Mask.String() == ipNet.Mask.String() {
					found = true
					break
				}
			}
			if !found {
				return errors.Errorf("Did not find expected addr %q on interface %q", ipNet, ifaceName)
			}
		}
		return nil
	}
	return errors.New("not a kernel mechanism")
}

func checkNoKernelInterface(conn *networkservice.Connection, nsHandle netns.NsHandle) error {
	if mechanism := kernel.ToMechanism(conn.GetMechanism()); mechanism != nil {
		curNetNS, err := netns.Get()
		if err != nil {
			return errors.Wrap(err, "unable to get current netns")
		}
		netlinkHandle, err := netlink.NewHandleAtFrom(nsHandle, curNetNS)
		if err != nil {
			return errors.Wrap(err, "unable to get netlink Handle in target netNs")
		}
		ifaceName := mechanism.GetInterfaceName()
		_, err = netlinkHandle.LinkByName(ifaceName)
		if err == nil {
			return errors.Errorf("found interface %q", ifaceName)
		}
	}
	return nil
}

func pingKernel(ipnet *net.IPNet, handle netns.NsHandle) error {
	if ipnet == nil {
		return nil
	}
	pingStr := fmt.Sprintf("ping -c 1 %s", ipnet.IP.String())
	if err := exechelper.Run(pingStr,
		exechelper.WithEnvirons(os.Environ()...),
		exechelper.WithStdout(os.Stdout),
		exechelper.WithStderr(os.Stderr),
		exechelper.WithNetNS(handle),
	); err != nil {
		return errors.Wrapf(err, "failed to ping with command %q", pingStr)
	}
	return nil
}
