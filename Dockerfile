ARG VPP_VERSION=v23.02-rc0-189-g0359d19f2
FROM ghcr.io/edwarnicke/govpp/vpp:${VPP_VERSION} as go
COPY --from=golang:1.18.2-buster /usr/local/go/ /go
ENV PATH ${PATH}:/go/bin
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOBIN=/bin
RUN rm -r /etc/vpp
RUN go install github.com/go-delve/delve/cmd/dlv@v1.8.2
RUN go install github.com/grpc-ecosystem/grpc-health-probe@v0.4.1
ADD https://github.com/spiffe/spire/releases/download/v1.2.2/spire-1.2.2-linux-x86_64-glibc.tar.gz .
RUN tar xzvf spire-1.2.2-linux-x86_64-glibc.tar.gz -C /bin --strip=2 spire-1.2.2/bin/spire-server spire-1.2.2/bin/spire-agent

FROM go as build
WORKDIR /build
COPY go.mod go.sum ./
COPY ./local ./local
COPY ./internal/imports ./internal/imports
RUN go build ./internal/imports
COPY . .
RUN go build -o /bin/forwarder .

FROM build as test
CMD go test -test.v ./...

FROM test as debug
WORKDIR /build/internal/tests/
CMD dlv -l :40000 --headless=true --api-version=2 test -test.v .

FROM ghcr.io/edwarnicke/govpp/vpp:${VPP_VERSION} as runtime
ARG user=nsm-user
ARG group=nsm-user
ARG uid=10001
ARG gid=10001
RUN groupadd -g ${gid} ${user} && useradd -g ${gid} -l -M -u ${uid} ${user}
COPY --from=build /bin/forwarder /bin/forwarder
RUN setcap cap_dac_override,cap_sys_admin,cap_net_admin=eip /bin/forwarder
RUN setcap cap_ipc_lock,cap_net_raw,cap_sys_ptrace,cap_dac_override,cap_sys_admin,cap_net_admin,cap_setgid=eip /usr/bin/vpp
COPY --from=build /bin/grpc-health-probe /bin/grpc-health-probe
ENTRYPOINT [ "/bin/forwarder" ]
