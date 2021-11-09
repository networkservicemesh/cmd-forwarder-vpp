module github.com/networkservicemesh/cmd-forwarder-vpp

go 1.16

require (
	git.fd.io/govpp.git v0.3.6-0.20210927044411-385ccc0d8ba9
	github.com/antonfisher/nested-logrus-formatter v1.3.1
	github.com/edwarnicke/debug v1.0.0
	github.com/edwarnicke/exechelper v1.0.3
	github.com/edwarnicke/govpp v0.0.0-20211023203533-76f2c92be8d5
	github.com/edwarnicke/grpcfd v0.1.1
	github.com/edwarnicke/vpphelper v0.0.0-20210512223648-f914b171f679
	github.com/golang/protobuf v1.5.2
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/networkservicemesh/api v1.0.1-0.20211108174538-15c88bce33f3
	github.com/networkservicemesh/sdk v0.5.1-0.20211108225443-65796945d24d
	github.com/networkservicemesh/sdk-k8s v0.0.0-20211103091718-33b5af79cf03
	github.com/networkservicemesh/sdk-sriov v0.0.0-20211103092011-23a720ab62a6
	github.com/networkservicemesh/sdk-vpp v0.0.0-20211108233028-6925316542f1
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/spiffe/go-spiffe/v2 v2.0.0-beta.2
	github.com/stretchr/testify v1.7.0
	github.com/thanhpk/randstr v1.0.4
	github.com/vishvananda/netlink v1.1.0
	github.com/vishvananda/netns v0.0.0-20200728191858-db3c7e526aae
	google.golang.org/grpc v1.38.0
)
