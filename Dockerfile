FROM ghcr.io/edwarnicke/govpp/vpp:20.09 as go
COPY --from=golang:1.15.3-buster /usr/local/go/ /go
ENV PATH ${PATH}:/go/bin
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOBIN=/bin
RUN rm -r /etc/vpp
RUN go get github.com/go-delve/delve/cmd/dlv@v1.5.0
RUN go get github.com/edwarnicke/dl
RUN dl \
    https://github.com/spiffe/spire/releases/download/v0.9.3/spire-0.9.3-linux-x86_64-glibc.tar.gz | \
    tar -xzvf - -C /bin --strip=3 ./spire-0.9.3/bin/spire-server ./spire-0.9.3/bin/spire-agent

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
CMD dlv -l :40000 --headless=true --api-version=2 test -test.v ./...

FROM ghcr.io/edwarnicke/govpp/vpp:20.09 as runtime
COPY --from=build /bin/forwarder /bin/forwarder
CMD /bin/forwarder
