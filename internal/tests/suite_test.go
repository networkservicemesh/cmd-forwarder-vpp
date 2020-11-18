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

package tests

import (
	"context"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"

	"github.com/edwarnicke/vpphelper"
)

// Config - configuration for cmd-forwarder-vpp
type Config struct {
	Name             string        `default:"forwarder" desc:"Name of Endpoint"`
	NSName           string        `default:"xconnectns" desc:"Name of Network Service to Register with Registry"`
	TunnelIP         net.IP        `desc:"IP to use for tunnels" split_words:"true"`
	ConnectTo        url.URL       `default:"unix:///connect.to.socket" desc:"url to connect to" split_words:"true"`
	MaxTokenLifetime time.Duration `default:"24h" desc:"maximum lifetime of tokens" split_words:"true"`
}

type ForwarderTestSuite struct {
	suite.Suite
	ctx    context.Context
	cancel context.CancelFunc
	config Config
	// Spire stuff
	spireErrCh <-chan error
	sutErrCh   <-chan error
	x509source x509svid.Source
	x509bundle x509bundle.Source
	sutCC      grpc.ClientConnInterface

	// vppServer stuff
	vppServerConn         vpphelper.Connection
	vppServerRoot         string
	vppServerLastSocketID uint32
	vppServerErrCh        <-chan error

	// vppClient stuff
	vppClientConn         vpphelper.Connection
	vppClientRoot         string
	vppClientLastSocketID uint32
	vppClientErrCh        <-chan error
}

func TestForwarderTestSuite(t *testing.T) {
	suite.Run(t, new(ForwarderTestSuite))
}
