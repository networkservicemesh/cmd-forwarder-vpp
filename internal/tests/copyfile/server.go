// Copyright (c) 2020 Doc.ai and/or its affiliates.
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

// Package copyfile provides the necessary mechanisms to request and inject a kernel interface.
package copyfile

import (
	"context"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
	"net/url"
)

type copyFileServer struct{
	name string
}

// NewServer - creates a NetworkServiceServer that requests a kernel interface and populates the netns inode
func NewServer(name string) networkservice.NetworkServiceServer {
	return &copyFileServer{
		name: name,
	}
}

func (m *copyFileServer) Request(ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {
	if mechanism := kernel.ToMechanism(request.GetConnection().GetMechanism()); mechanism != nil {
		//nsHandle, err := mechutils.ToNSHandle(mechanism)
		//fd, err := syscall.Open("/run/netns/" + m.name,  unix.O_RDONLY|unix.O_CLOEXEC, 0)
		//if err != nil {
		//	return nil, err
		//}
		//filename := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), fd)
		mechanism.SetNetNSURL((&url.URL{Scheme: "file", Path: "/run/netns/" + m.name}).String())
	}
	return next.Server(ctx).Request(ctx, request)
}

func (m *copyFileServer) Close(ctx context.Context, conn *networkservice.Connection) (*empty.Empty, error) {
	return next.Server(ctx).Close(ctx, conn)
}

