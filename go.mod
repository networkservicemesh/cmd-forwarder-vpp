module github.com/networkservicemesh/cmd-forwarder-vpp

go 1.16

require (
	git.fd.io/govpp.git v0.3.6-0.20210927044411-385ccc0d8ba9
	github.com/antonfisher/nested-logrus-formatter v1.3.1
	github.com/edwarnicke/debug v1.0.0
	github.com/edwarnicke/exechelper v1.0.3
	github.com/edwarnicke/govpp v0.0.0-20211201170712-7828460e6d2f
	github.com/edwarnicke/grpcfd v0.1.1
	github.com/edwarnicke/vpphelper v0.0.0-20210512223648-f914b171f679
	github.com/golang/protobuf v1.5.2
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/networkservicemesh/api v1.1.2-0.20220119092736-21eda250c390
	github.com/networkservicemesh/sdk v0.5.1-0.20220130184745-953f555cc4e0
	github.com/networkservicemesh/sdk-k8s v0.0.0-20220126203132-0cd73d38680a
	github.com/networkservicemesh/sdk-sriov v0.0.0-20220127194319-723f27bc2105
	github.com/networkservicemesh/sdk-vpp v0.0.0-20220130185711-0865427ebbd5
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.1
	github.com/spiffe/go-spiffe/v2 v2.0.0-beta.2
	github.com/stretchr/testify v1.7.0
	github.com/thanhpk/randstr v1.0.4
	github.com/vishvananda/netlink v1.1.1-0.20220118170537-d6b03fdeb845
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74
	google.golang.org/grpc v1.42.0
)
