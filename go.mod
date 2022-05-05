module github.com/networkservicemesh/cmd-forwarder-vpp

go 1.16

require (
	git.fd.io/govpp.git v0.3.6-0.20210927044411-385ccc0d8ba9
	github.com/antonfisher/nested-logrus-formatter v1.3.1
	github.com/edwarnicke/debug v1.0.0
	github.com/edwarnicke/exechelper v1.0.3
	github.com/edwarnicke/govpp v0.0.0-20220311182453-f32f292e0e91
	github.com/edwarnicke/grpcfd v1.1.2
	github.com/edwarnicke/vpphelper v0.0.0-20210512223648-f914b171f679
	github.com/golang/protobuf v1.5.2
	github.com/google/uuid v1.2.0
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/networkservicemesh/api v1.3.0-rc.1.0.20220405210054-fbcde048efa5
	github.com/networkservicemesh/sdk v0.5.1-0.20220505102418-8d6762737896
	github.com/networkservicemesh/sdk-k8s v0.0.0-20220505103040-16488cbb4872
	github.com/networkservicemesh/sdk-sriov v0.0.0-20220504134851-545a79cf58b3
	github.com/networkservicemesh/sdk-vpp v0.0.0-20220505140013-fdb5bed3d9fd
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.1
	github.com/spiffe/go-spiffe/v2 v2.0.0
	github.com/stretchr/testify v1.7.0
	github.com/thanhpk/randstr v1.0.4
	github.com/vishvananda/netlink v1.1.1-0.20220118170537-d6b03fdeb845
	github.com/vishvananda/netns v0.0.0-20211101163701-50045581ed74
	google.golang.org/grpc v1.42.0
)
