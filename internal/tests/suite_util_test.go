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
	"time"

	"github.com/pkg/errors"
	"google.golang.org/grpc"

	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
)

const (
	contextTimeout = 100 * time.Second
)

func (f *ForwarderTestSuite) ListenAndServe(ctx context.Context, server *grpc.Server) <-chan error {
	errCh := grpcutils.ListenAndServe(ctx, &f.config.ConnectTo, server)
	select {
	case err, ok := <-errCh:
		f.Require().True(ok)
		f.Require().NoError(err)
	default:
	}
	returnErrCh := make(chan error, len(errCh)+1)
	go func(errCh <-chan error, returnErrCh chan<- error) {
		for err := range errCh {
			if err != nil {
				returnErrCh <- errors.Wrap(err, "ListenAndServe")
			}
		}
		close(returnErrCh)
	}(errCh, returnErrCh)
	return returnErrCh
}
