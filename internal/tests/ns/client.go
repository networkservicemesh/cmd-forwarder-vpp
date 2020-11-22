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

// +build !windows

// Package ns - simple NetworkServiceClient chain element that will change the nsNet of the client to ns before
// calling the next chain element and return it to its original netNS before returning
package ns

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/vishvananda/netns"
	"google.golang.org/grpc"

	"github.com/networkservicemesh/api/pkg/api/networkservice"

	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
)

type nsClient struct {
	ns netns.NsHandle
}

// NewClient - simple client that will change the nsNet of the client to ns before calling the next chain element
// and return it to its original netNS before returning
func NewClient(ns netns.NsHandle) networkservice.NetworkServiceClient {
	return &nsClient{ns: ns}
}

func (n *nsClient) Request(ctx context.Context, request *networkservice.NetworkServiceRequest, opts ...grpc.CallOption) (*networkservice.Connection, error) {
	curNetns, err := netns.Get()
	if err != nil {
		return nil, err
	}
	err = netns.Set(n.ns)
	if err != nil {
		return nil, err
	}
	conn, err := next.Client(ctx).Request(ctx, request, opts...)
	if err != nil {
		return nil, err
	}
	err = netns.Set(curNetns)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (n *nsClient) Close(ctx context.Context, conn *networkservice.Connection, opts ...grpc.CallOption) (*empty.Empty, error) {
	curNetns, err := netns.Get()
	if err != nil {
		return nil, err
	}
	err = netns.Set(n.ns)
	if err != nil {
		return nil, err
	}
	_, err = next.Client(ctx).Close(ctx, conn, opts...)
	if err != nil {
		return nil, err
	}
	err = netns.Set(curNetns)
	if err != nil {
		return nil, err
	}
	return &empty.Empty{}, nil
}
