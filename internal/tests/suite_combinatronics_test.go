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

package tests

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/edwarnicke/grpcfd"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk/pkg/tools/logger"
	"github.com/networkservicemesh/sdk/pkg/tools/logger/logruslogger"
	"github.com/networkservicemesh/sdk/pkg/tools/spiffejwt"
)

const (
	kernelName = "Kernel"
	memifName  = "Memif"
)

func (f *ForwarderTestSuite) TestCombinations() {
	_, prefix, err := net.ParseCIDR("10.0.0.0/24")
	f.Require().NoError(err)
	endpoints := map[string]func(ctx context.Context) verifiableEndpoint{
		kernelName: func(ctx context.Context) verifiableEndpoint {
			return newKernelVerifiableEndpoint(ctx,
				prefix,
				spiffejwt.TokenGeneratorFunc(f.x509source, f.config.MaxTokenLifetime),
			)
		},
		memifName: func(ctx context.Context) verifiableEndpoint {
			return newMemifVerifiableEndpoint(ctx, prefix,
				spiffejwt.TokenGeneratorFunc(f.x509source, f.config.MaxTokenLifetime),
				f.vppServerConn,
				f.vppServerRoot,
				&f.vppServerLastSocketID,
			)
		},
	}
	clients := map[string]func(ctx context.Context) verifiableClient{
		kernelName: func(ctx context.Context) verifiableClient {
			return newKernelVerifiableClient(ctx,
				spiffejwt.TokenGeneratorFunc(f.x509source, f.config.MaxTokenLifetime),
				f.sutCC,
			)
		},
		memifName: func(ctx context.Context) verifiableClient {
			return newMemifVerifiableClient(ctx,
				spiffejwt.TokenGeneratorFunc(f.x509source, f.config.MaxTokenLifetime),
				f.sutCC,
				f.vppClientConn,
				&f.vppClientLastSocketID,
				f.vppClientRoot,
			)
		},
	}
	for endpointMechanism, epF := range endpoints {
		for clientMechanism, clFunc := range clients {
			networkserviceName := fmt.Sprintf("%sTo%s", clientMechanism, endpointMechanism)
			epFunc := epF
			clientFunc := clFunc
			f.T().Run(networkserviceName, func(t *testing.T) {
				starttime := time.Now()
				// Create ctx for test
				ctx, cancel := context.WithTimeout(f.ctx, contextTimeout)
				defer cancel()
				ctx, _ = logruslogger.New(
					logger.WithFields(ctx, map[string]interface{}{"test": t.Name()}),
				)
				networkserviceName := "ns"
				// Create testRequest
				testRequest := &networkservice.NetworkServiceRequest{
					Connection: &networkservice.Connection{
						NetworkService: networkserviceName,
					},
				}
				// ********************************************************************************
				logger.Log(f.ctx).Infof("Launching %s test server (time since start: %s)", t.Name(), time.Since(starttime))
				// ********************************************************************************
				now := time.Now()
				serverCreds := credentials.NewTLS(tlsconfig.MTLSServerConfig(f.x509source, f.x509bundle, tlsconfig.AuthorizeAny()))
				serverCreds = grpcfd.TransportCredentials(serverCreds)
				server := grpc.NewServer(grpc.Creds(serverCreds))
				ep := epFunc(ctx)
				networkservice.RegisterNetworkServiceServer(server, ep)
				networkservice.RegisterMonitorConnectionServer(server, ep)
				serverErrCh := f.ListenAndServe(ctx, server)
				logger.Log(ctx).Infof("Launching %s test server (took : %s)", t.Name(), time.Since(now))

				// ********************************************************************************
				logger.Log(f.ctx).Infof("Sending Request to forwarder (time since start: %s)", time.Since(starttime))
				// ********************************************************************************
				now = time.Now()
				client := clientFunc(ctx)
				conn, err := client.Request(ctx, testRequest)
				require.NoError(t, err)
				require.NotNil(t, conn)
				logger.Log(ctx).Infof("Sending Request to forwarder (took : %s)", time.Since(now))

				// ********************************************************************************
				logger.Log(f.ctx).Infof("Verifying Connection (time since start: %s)", time.Since(starttime))
				// ********************************************************************************
				now = time.Now()
				require.NoError(t, client.VerifyConnection(conn))
				require.NoError(t, ep.VerifyConnection(conn))
				logger.Log(ctx).Infof("Verifying Connection (took : %s)", time.Since(now))

				// ********************************************************************************
				logger.Log(f.ctx).Infof("Sending Close to forwarder (time since start: %s)", time.Since(starttime))
				// ********************************************************************************
				now = time.Now()
				_, err = client.Close(ctx, conn)
				require.NoError(t, err)
				logger.Log(ctx).Infof("Sending Close to forwarder (took : %s)", time.Since(now))

				// ********************************************************************************
				logger.Log(f.ctx).Infof("Verifying Connection Closed (time since start: %s)", time.Since(starttime))
				// ********************************************************************************
				now = time.Now()
				require.NoError(t, client.VerifyClose(conn))
				require.NoError(t, ep.VerifyClose(conn))
				logger.Log(ctx).Infof("Verifying Connection Closed (took : %s)", time.Since(now))
				// ********************************************************************************
				logger.Log(f.ctx).Infof("Canceling ctx to end test (time since start: %s)", time.Since(starttime))
				// ********************************************************************************
				cancel()
				err = <-serverErrCh
				require.NoError(t, err)
				// ********************************************************************************
				logger.Log(f.ctx).Infof("%s completed (time since start: %s)", t.Name(), time.Since(starttime))
				// ********************************************************************************
			})
		}
	}
}
