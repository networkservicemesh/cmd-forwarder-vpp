module github.com/networkservicemesh/cmd-forwarder-vpp

go 1.16

require (
	git.fd.io/govpp.git v0.3.6-0.20210615121054-5de7f6b85458
	github.com/antonfisher/nested-logrus-formatter v1.3.0
	github.com/edwarnicke/debug v1.0.0
	github.com/edwarnicke/exechelper v1.0.3
	github.com/edwarnicke/govpp v0.0.0-20210831163558-1534cf6ada42
	github.com/edwarnicke/grpcfd v0.1.0
	github.com/edwarnicke/vpphelper v0.0.0-20210512223648-f914b171f679
	github.com/golang/protobuf v1.5.2
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/networkservicemesh/api v1.0.1-0.20210907194827-9a36433d7d6e
	github.com/networkservicemesh/sdk v0.5.1-0.20210923121729-a96ead921c0e
	github.com/networkservicemesh/sdk-k8s v0.0.0-20210901072442-2e531cc7f2be
	github.com/networkservicemesh/sdk-sriov v0.0.0-20210914141410-e098156e4221
	github.com/networkservicemesh/sdk-vpp v0.0.0-20210914141416-15df58636081
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/spiffe/go-spiffe/v2 v2.0.0-beta.2
	github.com/stretchr/testify v1.7.0
	github.com/thanhpk/randstr v1.0.4
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae
	google.golang.org/grpc v1.38.0
)
