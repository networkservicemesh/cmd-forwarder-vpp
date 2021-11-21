// Copyright (c) 2021 Cisco and/or its affiliates.
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

// Package routes provides a simple cahin element for adding routes
package routes

import (
	"context"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
)

type testRoutesServer struct {
	srcRoutes []*networkservice.Route
	dstRoutes []*networkservice.Route
}

// NewServer - add routes to response
func NewServer(srcRoutes, dstRoutes []*networkservice.Route) networkservice.NetworkServiceServer {
	return &testRoutesServer{
		srcRoutes: srcRoutes,
		dstRoutes: dstRoutes,
	}
}

func (r *testRoutesServer) Request(ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {
	if request.GetConnection() == nil {
		request.Connection = &networkservice.Connection{}
	}
	if request.GetConnection().GetContext() == nil {
		request.GetConnection().Context = &networkservice.ConnectionContext{}
	}
	if request.GetConnection().GetContext().GetIpContext() == nil {
		request.GetConnection().GetContext().IpContext = &networkservice.IPContext{}
	}
	request.GetConnection().GetContext().GetIpContext().SrcRoutes = append(request.GetConnection().GetContext().GetIpContext().SrcRoutes, r.srcRoutes...)
	request.GetConnection().GetContext().GetIpContext().DstRoutes = append(request.GetConnection().GetContext().GetIpContext().DstRoutes, r.dstRoutes...)
	return next.Server(ctx).Request(ctx, request)
}

func (r *testRoutesServer) Close(ctx context.Context, conn *networkservice.Connection) (*emptypb.Empty, error) {
	return next.Server(ctx).Close(ctx, conn)
}
