module github.com/networkservicemesh/cmd-forwarder-vpp

go 1.16

require (
	git.fd.io/govpp.git v0.3.6-0.20210927044411-385ccc0d8ba9
	github.com/antonfisher/nested-logrus-formatter v1.3.1
	github.com/edwarnicke/debug v1.0.0
	github.com/edwarnicke/exechelper v1.0.3
	github.com/edwarnicke/govpp v0.0.0-20211126025848-29218cd40e80
	github.com/edwarnicke/grpcfd v0.1.1
	github.com/edwarnicke/vpphelper v0.0.0-20210512223648-f914b171f679
	github.com/golang/protobuf v1.5.2
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/networkservicemesh/api v1.1.0
	github.com/networkservicemesh/sdk v1.1.0
	github.com/networkservicemesh/sdk-k8s v1.1.0
	github.com/networkservicemesh/sdk-sriov v0.0.0-20211126230449-b49c0afa1eee
	github.com/networkservicemesh/sdk-vpp v0.0.0-20211126203820-6ff1fa7c47b0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/spiffe/go-spiffe/v2 v2.0.0-beta.2
	github.com/stretchr/testify v1.7.0
	github.com/thanhpk/randstr v1.0.4
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae
	google.golang.org/grpc v1.38.0
)
