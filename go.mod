module github.com/networkservicemesh/cmd-forwarder-vpp

go 1.15

require (
	git.fd.io/govpp.git v0.3.6-0.20200903151113-c94a96227985
	github.com/antonfisher/nested-logrus-formatter v1.3.0
	github.com/edwarnicke/debug v1.0.0
	github.com/edwarnicke/exechelper v1.0.3
	github.com/edwarnicke/govpp v0.0.0-20210130172618-d3c6251cbbe7
	github.com/edwarnicke/grpcfd v0.0.0-20201107002751-f220aed0c5c8
	github.com/edwarnicke/signalctx v0.0.0-20201105214533-3a35840b3011
	github.com/edwarnicke/vpphelper v0.0.0-20201229173204-87a3b197f1e1
	github.com/golang/protobuf v1.4.3
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/networkservicemesh/api v0.0.0-20210202152048-ec956057eb3a
	github.com/networkservicemesh/sdk v0.0.0-20210203050851-8b5ea6279bbc
	github.com/networkservicemesh/sdk-vpp v0.0.0-20210203051609-bdf7ec55a2ab
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/spiffe/go-spiffe/v2 v2.0.0-beta.2
	github.com/stretchr/testify v1.6.1
	github.com/thanhpk/randstr v1.0.4
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae
	google.golang.org/grpc v1.33.2
)
