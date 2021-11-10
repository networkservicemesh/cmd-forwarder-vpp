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
	"net"
	"strings"
	"testing"
	"time"

	"github.com/edwarnicke/grpcfd"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/kernel"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/memif"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/vxlan"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/wireguard"
	"github.com/networkservicemesh/api/pkg/api/networkservice/payload"
	"github.com/networkservicemesh/api/pkg/api/registry"
	"github.com/networkservicemesh/sdk/pkg/registry/core/adapters"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"github.com/networkservicemesh/sdk/pkg/tools/log/logruslogger"
	"github.com/networkservicemesh/sdk/pkg/tools/spiffejwt"
)

func (f *ForwarderTestSuite) TestCombinations() {
	_, prefix1, err := net.ParseCIDR("10.0.0.0/24")
	f.Require().NoError(err)
	_, prefix2, err := net.ParseCIDR("fc00::/7")
	f.Require().NoError(err)
	endpoints := map[string]func(ctx context.Context) verifiableEndpoint{
		kernel.MECHANISM: func(ctx context.Context) verifiableEndpoint {
			return newKernelVerifiableEndpoint(ctx,
				prefix1,
				prefix2,
				spiffejwt.TokenGeneratorFunc(f.x509source, f.config.MaxTokenLifetime),
			)
		},
		memif.MECHANISM: func(ctx context.Context) verifiableEndpoint {
			return newMemifVerifiableEndpoint(ctx, prefix1, prefix2,
				spiffejwt.TokenGeneratorFunc(f.x509source, f.config.MaxTokenLifetime),
				f.vppServerConn,
			)
		},
		vxlan.MECHANISM: func(ctx context.Context) verifiableEndpoint {
			return newVxlanVerifiableEndpoint(ctx, prefix1, prefix2,
				spiffejwt.TokenGeneratorFunc(f.x509source, f.config.MaxTokenLifetime),
				f.vppServerConn,
			)
		},
		wireguard.MECHANISM: func(ctx context.Context) verifiableEndpoint {
			return newWireguardVerifiableEndpoint(ctx, prefix1, prefix2,
				spiffejwt.TokenGeneratorFunc(f.x509source, f.config.MaxTokenLifetime),
				f.vppServerConn,
			)
		},
	}
	clients := map[string]func(ctx context.Context) verifiableClient{
		kernel.MECHANISM: func(ctx context.Context) verifiableClient {
			return newKernelVerifiableClient(ctx,
				f.sutCC,
			)
		},
		memif.MECHANISM: func(ctx context.Context) verifiableClient {
			return newMemifVerifiableClient(ctx,
				f.sutCC,
				f.vppClientConn,
			)
		},
		vxlan.MECHANISM: func(ctx context.Context) verifiableClient {
			return newVxlanVerifiableClient(ctx,
				f.sutCC,
				f.vppClientConn,
			)
		},
		wireguard.MECHANISM: func(ctx context.Context) verifiableClient {
			return newWireguardVerifiableClient(ctx,
				f.sutCC,
				f.vppClientConn,
			)
		},
	}

	payloads := map[string][]string{
		payload.IP: {
			kernel.MECHANISM,
			memif.MECHANISM,
			// wireguard.MECHANISM,
		},
		payload.Ethernet: {
			kernel.MECHANISM,
			memif.MECHANISM,
			// vxlan.MECHANISM,
		},
	}
	for _, pl := range []string{payload.Ethernet, payload.IP} {
		payloadName := pl
		f.T().Run(strings.Title(strings.ToLower(payloadName)), func(t *testing.T) {
			for _, cm := range payloads[payloadName] {
				clientMechanism := cm
				t.Run(strings.Title(strings.ToLower(clientMechanism)), func(t *testing.T) {
					for _, em := range payloads[payloadName] {
						endpointMechanism := em
						epFunc := endpoints[endpointMechanism]
						clientFunc := clients[clientMechanism]
						t.Run(strings.Title(strings.ToLower(endpointMechanism)), func(t *testing.T) {
							starttime := time.Now()
							// Create ctx for test
							ctx, cancel := context.WithTimeout(f.ctx, contextTimeout)
							defer cancel()
							ctx = log.WithFields(ctx, map[string]interface{}{"test": t.Name()})
							ctx = log.WithLog(ctx, logruslogger.New(ctx))
							networkserviceName := "ns"

							_, err = adapters.NetworkServiceEndpointServerToClient(f.registryServer).Register(ctx, &registry.NetworkServiceEndpoint{
								Name:                "nse",
								NetworkServiceNames: []string{"ns"},
								Url:                 f.config.ConnectTo.String(),
							})
							f.Require().NoError(err)

							_, err = adapters.NetworkServiceServerToClient(f.registryNSServer).Register(ctx, &registry.NetworkService{
								Name:    "ns",
								Payload: payloadName,
							})
							f.Require().NoError(err)

							testRequest := &networkservice.NetworkServiceRequest{
								Connection: &networkservice.Connection{
									NetworkService: networkserviceName,
									Payload:        payloadName,
								},
							}
							// ********************************************************************************
							log.FromContext(f.ctx).Infof("Launching %s test server (time since start: %s)", t.Name(), time.Since(starttime))
							// ********************************************************************************
							now := time.Now()
							serverCreds := credentials.NewTLS(tlsconfig.MTLSServerConfig(f.x509source, f.x509bundle, tlsconfig.AuthorizeAny()))
							serverCreds = grpcfd.TransportCredentials(serverCreds)
							server := grpc.NewServer(grpc.Creds(serverCreds))
							ep := epFunc(ctx)
							networkservice.RegisterNetworkServiceServer(server, ep)
							networkservice.RegisterMonitorConnectionServer(server, ep)
							registry.RegisterNetworkServiceEndpointRegistryServer(server, f.registryServer)
							registry.RegisterNetworkServiceRegistryServer(server, f.registryNSServer)
							serverErrCh := f.ListenAndServe(ctx, server)
							log.FromContext(ctx).Infof("Launching %s test server (took : %s)", t.Name(), time.Since(now))

							// ********************************************************************************
							log.FromContext(f.ctx).Infof("Sending Request to forwarder (time since start: %s)", time.Since(starttime))
							// ********************************************************************************
							now = time.Now()
							client := clientFunc(ctx)
							conn, err := client.Request(ctx, testRequest)
							assert.NoError(t, err)
							assert.NotNil(t, conn)
							log.FromContext(ctx).Infof("Sending Request to forwarder (took : %s)", time.Since(now))
							if err == nil {
								// ********************************************************************************
								log.FromContext(f.ctx).Infof("Verifying Connection (time since start: %s)", time.Since(starttime))
								// ********************************************************************************
								now = time.Now()
								assert.NoError(t, client.VerifyConnection(conn))
								assert.NoError(t, ep.VerifyConnection(conn))
								log.FromContext(ctx).Infof("Verifying Connection (took : %s)", time.Since(now))
							}

							// ********************************************************************************
							log.FromContext(f.ctx).Infof("Sending Close to forwarder (time since start: %s)", time.Since(starttime))
							// ********************************************************************************
							now = time.Now()
							_, err = client.Close(ctx, conn)
							require.NoError(t, err)
							log.FromContext(ctx).Infof("Sending Close to forwarder (took : %s)", time.Since(now))

							// ********************************************************************************
							log.FromContext(f.ctx).Infof("Verifying Connection Closed (time since start: %s)", time.Since(starttime))
							// ********************************************************************************
							now = time.Now()
							require.NoError(t, client.VerifyClose(conn))
							require.NoError(t, ep.VerifyClose(conn))
							log.FromContext(ctx).Infof("Verifying Connection Closed (took : %s)", time.Since(now))

							// ********************************************************************************
							log.FromContext(f.ctx).Infof("Canceling ctx to end test (time since start: %s)", time.Since(starttime))
							// ********************************************************************************
							cancel()
							err = <-serverErrCh
							require.NoError(t, err)
							// ********************************************************************************
							log.FromContext(f.ctx).Infof("%s completed (time since start: %s)", t.Name(), time.Since(starttime))
							// ********************************************************************************
						})
					}
				})
			}
		})
	}
}
