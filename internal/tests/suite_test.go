// Copyright (c) 2020-2023 Cisco and/or its affiliates.
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
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"

	"github.com/networkservicemesh/vpphelper"

	"github.com/networkservicemesh/api/pkg/api/registry"

	"github.com/networkservicemesh/cmd-forwarder-vpp/internal/config"
)

type ForwarderTestSuite struct {
	suite.Suite
	ctx    context.Context
	cancel context.CancelFunc
	config config.Config

	sutErrCh <-chan error
	sutCC    grpc.ClientConnInterface

	// Spire stuff
	spireErrCh <-chan error
	x509source x509svid.Source
	x509bundle x509bundle.Source

	// vppServer stuff
	vppServerConn  vpphelper.Connection
	vppServerRoot  string
	vppServerErrCh <-chan error

	// vppClient stuff
	vppClientConn  vpphelper.Connection
	vppClientRoot  string
	vppClientErrCh <-chan error

	// registry server stuff
	registryServer   registry.NetworkServiceEndpointRegistryServer
	registryNSServer registry.NetworkServiceRegistryServer
}

func TestForwarderTestSuite(t *testing.T) {
	suite.Run(t, new(ForwarderTestSuite))
}
