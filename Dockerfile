ARG VPP_VERSION=v23.02-rc0-189-g766031bdb
FROM ghcr.io/networkservicemesh/govpp/vpp:${VPP_VERSION} as go
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
RUN apt update
RUN apt install -f -y libbpf-dev clang
WORKDIR /build
COPY go.mod go.sum ./
COPY ./local ./local
COPY ./internal/imports ./internal/imports
COPY ./internal/afxdp/afxdp.c ./internal/afxdp/
RUN clang -O3 -g -Wextra -Wall -target bpf -I/usr/include/x86_64-linux-gnu -I/usr/include -c -o /bin/afxdp.o ./internal/afxdp/afxdp.c
RUN go build ./internal/imports
COPY . .
RUN go build -o /bin/forwarder .

FROM build as test
CMD go test -test.v ./...

FROM test as debug
WORKDIR /build/internal/tests/
CMD dlv -l :40000 --headless=true --api-version=2 test -test.v .

FROM ghcr.io/networkservicemesh/govpp/vpp:${VPP_VERSION} as runtime
RUN apt-get update
RUN apt install -f -y libbpf-dev
COPY --from=build /bin/forwarder /bin/forwarder
COPY --from=build /bin/afxdp.o /bin/afxdp.o
COPY --from=build /bin/grpc-health-probe /bin/grpc-health-probe
ENTRYPOINT [ "/bin/forwarder" ]
