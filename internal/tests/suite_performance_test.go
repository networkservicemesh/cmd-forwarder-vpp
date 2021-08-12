// Copyright (c) 2021 Doc.ai and/or its affiliates.
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
	"git.fd.io/govpp.git/api"
	"github.com/edwarnicke/exechelper"
	"github.com/edwarnicke/govpp/binapi/vpe"
	"github.com/edwarnicke/grpcfd"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/payload"
	"github.com/networkservicemesh/api/pkg/api/registry"
	"github.com/networkservicemesh/cmd-forwarder-vpp/internal/tests/iperf"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"github.com/networkservicemesh/sdk/pkg/tools/log/logruslogger"
	"github.com/networkservicemesh/sdk/pkg/tools/spiffejwt"
	"github.com/pkg/errors"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netns"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const N = 10
const M = 1

type clientInfo struct {
	cancels        []func()
	clientWithConn map[verifiableClient]*networkservice.Connection
}

var latencyTable = map[string][]string{}
var errTable = map[string][]string{}

func (f *ForwarderTestSuite) TestKernelToKernelPerformance() {
	//time.Sleep(time.Hour)
	f.T().Skip()
	//create endpoint
	epCtx, epCancel := context.WithCancel(f.ctx)

	serverCreds := credentials.NewTLS(tlsconfig.MTLSServerConfig(f.x509source, f.x509bundle, tlsconfig.AuthorizeAny()))
	serverCreds = grpcfd.TransportCredentials(serverCreds)
	server := grpc.NewServer(grpc.Creds(serverCreds))

	_, prefix1, err := net.ParseCIDR("10.0.0.0/24")
	f.Require().NoError(err)
	_, prefix2, err := net.ParseCIDR("fc00::/7")
	f.Require().NoError(err)

	ep := newKernelVerifiableEndpoint(epCtx,
		prefix1,
		prefix2,
		spiffejwt.TokenGeneratorFunc(f.x509source, f.config.MaxTokenLifetime),
	)

	networkservice.RegisterNetworkServiceServer(server, ep)
	networkservice.RegisterMonitorConnectionServer(server, ep)
	registry.RegisterNetworkServiceEndpointRegistryServer(server, f.registryServer)
	serverErrCh := f.ListenAndServe(epCtx, server)

	clInfo := &clientInfo{
		clientWithConn: map[verifiableClient]*networkservice.Connection{},
	}
	for i := 0; i < N; i++ {
		f.T().Run(fmt.Sprintf("Kernel%v", i+1), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(f.ctx, contextTimeout)
			clInfo.cancels = append(clInfo.cancels, cancel)

			ctx = log.WithLog(ctx, logruslogger.New(ctx))
			networkserviceName := "ns"
			// Create testRequest
			testRequest := &networkservice.NetworkServiceRequest{
				Connection: &networkservice.Connection{
					NetworkService: networkserviceName,
					Payload:        payload.IP,
				},
			}

			client := newKernelVerifiableClient(ctx, f.sutCC)
			conn, err := client.Request(ctx, testRequest)
			assert.NoError(t, err)
			assert.NotNil(t, conn)

			clInfo.clientWithConn[client] = conn
			//if conn != nil {
			//	latencyTable[conn.Id] = []string{}
			//}

			if err == nil {
				assert.NoError(t, ep.VerifyConnection(conn))
				assert.NoError(t, client.VerifyConnection(conn))
			}
		})
	}

	for _, v := range clInfo.clientWithConn {
		e, ok2 := ep.(*kernelVerifiableEndpoint)
		if !ok2 {
			continue
		}
		v2 := v
		for _, ip := range v2.GetContext().GetIpContext().GetDstIPNets() {
			ip2 := ip
			log.FromContext(f.ctx).Infof(ip2.IP.String())
			go func() {
				_ = iperf.StartServer(ip2, e.endpointNSHandle)
			}()
			time.Sleep(time.Second * 10)
		}
	}
	wg := sync.WaitGroup{}
	for k, v := range clInfo.clientWithConn {
		cl, ok := k.(*kernelVerifiableClient)
		_, ok2 := ep.(*kernelVerifiableEndpoint)
		if !ok || !ok2 {
			continue
		}
		wg.Add(1)
		conn := v
		go func() {
			_ = iperfMeasure(conn, cl)
			wg.Done()
		}()
	}
	wg.Wait()

	_ = iperf.WriteFile("kernel", "kernel", N, M)

	for _, c := range clInfo.cancels {
		c()
	}

	//writeFile("kernel", "kernel", N, M)

	epCancel()

	err = <-serverErrCh
}

func (f *ForwarderTestSuite) TestKernelToVxlanToKernelPerformance() {
	//time.Sleep(time.Hour)
	//f.T().Skip()
	//create endpoint
	epCtx, epCancel := context.WithCancel(f.ctx)

	serverCreds := credentials.NewTLS(tlsconfig.MTLSServerConfig(f.x509source, f.x509bundle, tlsconfig.AuthorizeAny()))
	serverCreds = grpcfd.TransportCredentials(serverCreds)
	server := grpc.NewServer(grpc.Creds(serverCreds))

	_, prefix1, err := net.ParseCIDR("10.0.0.0/24")
	f.Require().NoError(err)
	_, prefix2, err := net.ParseCIDR("fc00::/7")
	f.Require().NoError(err)

	ep := newKernelToVxlanVerifiableEndpoint(epCtx,
		prefix1,
		prefix2,
		spiffejwt.TokenGeneratorFunc(f.x509source, f.config.MaxTokenLifetime),
		f.vppServerConn,
	)

	networkservice.RegisterNetworkServiceServer(server, ep)
	networkservice.RegisterMonitorConnectionServer(server, ep)
	registry.RegisterNetworkServiceEndpointRegistryServer(server, f.registryServer)
	serverErrCh := f.ListenAndServe(epCtx, server)

	clInfo := &clientInfo{
		clientWithConn: map[verifiableClient]*networkservice.Connection{},
	}
	for i := 0; i < N; i++ {
		f.T().Run(fmt.Sprintf("Kernel%v", i+1), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(f.ctx, contextTimeout * 100)
			clInfo.cancels = append(clInfo.cancels, cancel)

			ctx = log.WithLog(ctx, logruslogger.New(ctx))
			networkserviceName := "ns"
			// Create testRequest
			testRequest := &networkservice.NetworkServiceRequest{
				Connection: &networkservice.Connection{
					NetworkService: networkserviceName,
					Payload:        payload.Ethernet,
				},
			}

			client := newKernelVerifiableClient(ctx, f.sutCC)
			conn, err := client.Request(ctx, testRequest)
			assert.NoError(t, err)
			assert.NotNil(t, conn)

			clInfo.clientWithConn[client] = conn
			//if conn != nil {
			//	latencyTable[conn.Id] = []string{}
			//}

			if err == nil {
				assert.NoError(t, client.VerifyConnection(conn))
				assert.NoError(t, ep.VerifyConnection(conn))
			}
		})
	}

	//for _, v := range clInfo.clientWithConn {
	//	e, ok2 := ep.(*kernelToVxlanVerifiableEndpoint)
	//	if !ok2 {
	//		continue
	//	}
	//	v2 := v
	//	for _, ip := range v2.GetContext().GetIpContext().GetDstIPNets() {
	//		ip2 := ip
	//		log.FromContext(f.ctx).Infof(ip2.IP.String())
	//		go func() {
	//			_ = iperf.StartServer(ip2, e.endpointNSHandle)
	//		}()
	//		time.Sleep(time.Second * 10)
	//	}
	//}
	//wg := sync.WaitGroup{}
	//for k, v := range clInfo.clientWithConn {
	//	cl, ok := k.(*kernelVerifiableClient)
	//	_, ok2 := ep.(*kernelToVxlanVerifiableEndpoint)
	//	if !ok || !ok2 {
	//		continue
	//	}
	//	wg.Add(1)
	//	conn := v
	//	go func() {
	//		_ = iperfMeasure(conn, cl)
	//		wg.Done()
	//	}()
	//}
	//wg.Wait()
	//
	//_ = iperf.WriteFile("kernelToWireguardTo", "kernel", N, M)

	for _, c := range clInfo.cancels {
		c()
	}

	//writeFile("kernel", "kernel", N, M)

	epCancel()

	err = <-serverErrCh
}

func iperfMeasure(conn *networkservice.Connection, k *kernelVerifiableClient) error {
	for _, ip := range conn.GetContext().GetIpContext().GetDstIPNets() {
		var err error
		for i := 0; i < 20; i++ {
			err = iperf.Cmd(ip, k.clientNSHandle, conn)
			if err == nil {
				break
			}
		}
	}

	return nil
}

func checkPingKernel(conn *networkservice.Connection, k *kernelVerifiableClient) error {
	for _, ip := range conn.GetContext().GetIpContext().GetDstIPNets() {
		if err := pingKernelCmd(ip, k.clientNSHandle, conn); err != nil {
			errTable[conn.Id] = append(errTable[conn.Id], err.Error())
			return err
		}
	}

	return nil
}

func pingKernelCmd(ipnet *net.IPNet, handle netns.NsHandle, conn *networkservice.Connection) error {
	if ipnet == nil {
		return nil
	}

	var strBuilder strings.Builder
	pingStr := fmt.Sprintf("ping -c 1 %s", ipnet.IP.String())
	if err := exechelper.Run(pingStr,
		exechelper.WithEnvirons(os.Environ()...),
		exechelper.WithStdout(io.MultiWriter(os.Stdout, &strBuilder)),
		exechelper.WithStderr(os.Stderr),
		exechelper.WithNetNS(handle),
	); err != nil {
		return errors.Wrapf(err, "failed to ping with command %q", pingStr)
	}

	appendKernelPingResults(strBuilder.String(), conn.Id)

	return nil
}

func appendKernelPingResults(str, connId string) {
	if strings.Contains(str, "100% packet loss") {
		return
	}
	latencyParts := strings.Split(str, "min/avg/max/mdev =")
	if len(latencyParts) < 2 {
		return
	}

	latNums := strings.Split(latencyParts[1], "/")
	if len(latNums) < 2 {
		return
	}

	if _, ok := latencyTable[connId]; ok {
		latencyTable[connId] = append(latencyTable[connId], latNums[1])
	}
}

func writeFile(clientMech, endpointMech string, cN, eN int) {
	err := os.Mkdir("results", 0755)
	if err != nil {
		return
	}

	filename := fmt.Sprintf("results/%v_to_%v_%v_to_%v.txt", clientMech, endpointMech, cN, eN)
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)

	if err != nil {
		return
	}
	var oldRows [][]string
	for k, v := range latencyTable {
		oldRows = append(oldRows, append([]string{k}, v...))
	}
	if len(oldRows) == 0 {
		return
	}
	sort.Slice(oldRows, func(i, j int) bool {
		return len(oldRows[i]) > len(oldRows[j])
	})
	for _, r := range oldRows {
		diff := len(oldRows[0]) - len(r)
		if diff > 0 {
			r = append(r, make([]string, diff)...)
		}
	}

	var transposedRows = make([][]string, len(oldRows[0]))
	for i, col := range oldRows {
		for j := range col {
			if len(transposedRows[j]) == 0 {
				transposedRows[j] = make([]string, len(oldRows[0]))
			}
			transposedRows[j][i] = oldRows[i][j]
		}
	}

	for i, r := range transposedRows {
		_, err = file.WriteString(strings.Join(append([]string{fmt.Sprintf("%v", i)}, r...), ","))
		_, err = file.WriteString("\n")
	}

	// write errors
	if len(errTable) == 0 {
		return
	}
	errFilename := fmt.Sprintf("results/%v_to_%v_%v_to_%v_errors.txt", clientMech, endpointMech, cN, eN)
	errFile, err := os.OpenFile(errFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return
	}
	for k, v := range errTable {
		_, err = errFile.WriteString(fmt.Sprintf("%v,", k))
		_, err = errFile.WriteString(strings.Join(v, ","))
		_, err = errFile.WriteString("\n")
	}
}

const memN = 3
const memM = 1

func (f *ForwarderTestSuite) TestMemifToMemifPerformance() {
	f.T().Skip()
	//create endpoint
	epCtx, epCancel := context.WithCancel(f.ctx)

	serverCreds := credentials.NewTLS(tlsconfig.MTLSServerConfig(f.x509source, f.x509bundle, tlsconfig.AuthorizeAny()))
	serverCreds = grpcfd.TransportCredentials(serverCreds)
	server := grpc.NewServer(grpc.Creds(serverCreds))

	_, prefix1, err := net.ParseCIDR("10.0.0.0/24")
	f.Require().NoError(err)
	_, prefix2, err := net.ParseCIDR("fc00::/7")
	f.Require().NoError(err)

	ep := newMemifVerifiableEndpoint(epCtx,
		prefix1,
		prefix2,
		spiffejwt.TokenGeneratorFunc(f.x509source, f.config.MaxTokenLifetime),
		f.vppServerConn,
	)

	networkservice.RegisterNetworkServiceServer(server, ep)
	networkservice.RegisterMonitorConnectionServer(server, ep)
	registry.RegisterNetworkServiceEndpointRegistryServer(server, f.registryServer)
	serverErrCh := f.ListenAndServe(epCtx, server)

	type clientInfo struct {
		cancels        []func()
		clientWithConn map[verifiableClient]*networkservice.Connection
	}

	clInfo := &clientInfo{
		clientWithConn: map[verifiableClient]*networkservice.Connection{},
	}
	for i := 0; i < memN; i++ {
		f.T().Run(fmt.Sprintf("Memif%v", i+1), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(f.ctx, contextTimeout)
			clInfo.cancels = append(clInfo.cancels, cancel)

			ctx = log.WithLog(ctx, logruslogger.New(ctx))
			networkserviceName := "ns"
			// Create testRequest
			testRequest := &networkservice.NetworkServiceRequest{
				Connection: &networkservice.Connection{
					NetworkService: networkserviceName,
					Payload:        payload.Ethernet,
				},
			}

			client := newMemifVerifiableClient(ctx, f.sutCC, f.vppClientConn)
			conn, err := client.Request(ctx, testRequest)
			assert.NoError(t, err)
			assert.NotNil(t, conn)

			clInfo.clientWithConn[client] = conn
			if conn != nil {
				latencyTable[conn.Id] = []string{}
			}

			if err == nil {
				assert.NoError(t, ep.VerifyConnection(conn))
				assert.NoError(t, client.VerifyConnection(conn))
			}
		})
	}

	//for _, v := range clInfo.clientWithConn {
	//	e, ok2 := ep.(*kernelVerifiableEndpoint)
	//	if !ok2 {
	//		continue
	//	}
	//	v2 := v
	//	for _, ip := range v2.GetContext().GetIpContext().GetDstIPNets() {
	//		ip2 := ip
	//		log.FromContext(f.ctx).Infof(ip2.IP.String())
	//		go func() {
	//			_ = iperf.StartServer(ip2, e.endpointNSHandle)
	//		}()
	//		time.Sleep(time.Second*10)
	//	}
	//}
	//wg := sync.WaitGroup{}
	//for k, v := range clInfo.clientWithConn {
	//	cl, ok := k.(*kernelVerifiableClient)
	//	e, ok2 := ep.(*kernelVerifiableEndpoint)
	//	if !ok || !ok2 {
	//		continue
	//	}
	//	wg.Add(1)
	//	conn := v
	//	go func() {
	//		_ = iperfMeasure(conn, cl, e)
	//		wg.Done()
	//	}()
	//}
	//wg.Wait()
	//
	//_ = iperf.WriteFile("memif", "memif", memN, memM)

	for _, c := range clInfo.cancels {
		c()
	}

	//writeFile("memif", "memif", memN, memM)

	epCancel()

	err = <-serverErrCh
}

func verifyMemif(conn *networkservice.Connection, m *memifVerifiableClient) error {
	for _, ip := range conn.GetContext().GetIpContext().GetDstIpAddrs() {
		if err := pingvpp(m.ctx, m.vppConn, ip, conn.Id); err != nil {
			errTable[conn.Id] = append(errTable[conn.Id], err.Error())
			return err
		}
	}
	return nil
}

func pingvpp(ctx context.Context, vppConn api.Connection, ipaddress, connId string) error {
	ip, _, err := net.ParseCIDR(ipaddress)
	if err != nil {
		return errors.WithStack(err)
	}
	pingCmd := &vpe.CliInband{
		Cmd: fmt.Sprintf("ping %s interval 0.1 repeat 1 verbose", ip.String()),
	}

	// Prime the pump, vpp doesn't arp until needed, and so the first ping will fail
	now := time.Now()
	pingRsp, err := vpe.NewServiceClient(vppConn).CliInband(ctx, pingCmd)
	if err != nil {
		return errors.WithStack(err)
	}
	log.FromContext(ctx).
		WithField("vppapi", "CliInband").
		WithField("Cmd", pingCmd).
		WithField("Reply", pingRsp.Reply).
		WithField("duration", time.Since(now)).Debug("completed")

	now = time.Now()
	if pingRsp, err = vpe.NewServiceClient(vppConn).CliInband(ctx, pingCmd); err != nil {
		errTable[connId] = append(errTable[connId], err.Error())
		return errors.WithStack(err)
	}
	log.FromContext(ctx).
		WithField("vppapi", "CliInband").
		WithField("Cmd", pingCmd).
		WithField("Reply", pingRsp.Reply).
		WithField("duration", time.Since(now)).Debug("completed")

	if regexp.MustCompile(" 0% packet loss").MatchString(pingRsp.Reply) {
		appendVppPingResult(connId, pingRsp.Reply)
		return nil
	}
	return errors.New("Ping failed")
}

func appendVppPingResult(connId, res string) {
	if len(res) == 0 {
		return
	}

	arr := strings.Split(res, "time=")
	if len(arr) < 2 {
		return
	}

	ind := strings.Index(arr[1], "ms")
	if ind == -1 {
		return
	}

	if strings.Contains(arr[1], "ms") {
		arr = strings.Split(arr[1], "ms")
	}
	if len(arr) == 0 {
		return
	}

	latencyTable[connId] = append(latencyTable[connId], arr[0])
}
