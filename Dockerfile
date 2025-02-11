ARG VPP_VERSION=v24.10.0-4-ga9d527a67
FROM ghcr.io/networkservicemesh/govpp/vpp:${VPP_VERSION} AS go
COPY --from=golang:1.23.1 /usr/local/go/ /go
ENV PATH=${PATH}:/go/bin
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOBIN=/bin
ARG BUILDARCH=amd64
RUN rm -r /etc/vpp
RUN go install github.com/go-delve/delve/cmd/dlv@v1.23.1
RUN go install github.com/grpc-ecosystem/grpc-health-probe@v0.4.25
ADD https://github.com/spiffe/spire/releases/download/v1.8.0/spire-1.8.0-linux-${BUILDARCH}-musl.tar.gz .
RUN tar xzvf spire-1.8.0-linux-${BUILDARCH}-musl.tar.gz -C /bin --strip=2 spire-1.8.0/bin/spire-server spire-1.8.0/bin/spire-agent

FROM go AS build
RUN apt update
RUN apt install -f -y libbpf-dev clang
WORKDIR /build
COPY go.mod go.sum ./
COPY ./local ./local
COPY ./internal/imports ./internal/imports
COPY ./internal/afxdp/afxdp.c ./internal/afxdp/
RUN clang -O3 -g -Wextra -Wall -target bpf -I/usr/include/$(uname -m)-linux-gnu -I/usr/include -c -o /bin/afxdp.o ./internal/afxdp/afxdp.c
RUN go build ./internal/imports
COPY . .
RUN go build -o /bin/forwarder .

FROM build AS test
CMD go test -test.v ./...

FROM test AS debug
WORKDIR /build/internal/tests/
CMD dlv -l :40000 --headless=true --api-version=2 test -test.v .

FROM ghcr.io/networkservicemesh/govpp/vpp:${VPP_VERSION} AS runtime
RUN apt-get update
RUN apt install -f -y libbpf-dev
COPY --from=build /bin/forwarder /bin/forwarder
COPY --from=build /bin/afxdp.o /bin/afxdp.o
COPY --from=build /bin/grpc-health-probe /bin/grpc-health-probe
ENTRYPOINT [ "/bin/forwarder" ]
