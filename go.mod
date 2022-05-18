module github.com/networkservicemesh/cmd-forwarder-vpp

go 1.16

require (
	git.fd.io/govpp.git v0.3.6-0.20210927044411-385ccc0d8ba9
	github.com/antonfisher/nested-logrus-formatter v1.3.1
	github.com/edwarnicke/debug v1.0.0
	github.com/edwarnicke/exechelper v1.0.3
	github.com/edwarnicke/govpp v0.0.0-20220509171552-731995b8f574
	github.com/edwarnicke/grpcfd v1.1.2
	github.com/edwarnicke/vpphelper v0.0.0-20210512223648-f914b171f679
	github.com/golang/protobuf v1.5.2
	github.com/google/uuid v1.2.0
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/networkservicemesh/api v1.3.2-0.20220516230921-edaa6f46d6ab
	github.com/networkservicemesh/sdk v0.5.1-0.20220518154856-dd9b496ef8a4
	github.com/networkservicemesh/sdk-k8s v0.0.0-20220516232434-a8a196c68e37
	github.com/networkservicemesh/sdk-sriov v0.0.0-20220518181926-0fd4b42d16c0
	github.com/networkservicemesh/sdk-vpp v0.0.0-20220518182025-f5e57262f6de
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.1
	github.com/spiffe/go-spiffe/v2 v2.0.0
	github.com/stretchr/testify v1.7.0
	github.com/thanhpk/randstr v1.0.4
	github.com/vishvananda/netlink v1.1.1-0.20220118170537-d6b03fdeb845
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74
	google.golang.org/grpc v1.42.0
)
