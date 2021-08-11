package tests

import (
	"context"
	"fmt"
	"git.fd.io/govpp.git/api"
	"github.com/edwarnicke/vpphelper"
	"github.com/google/uuid"
	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/api/pkg/api/networkservice/mechanisms/cls"
	"github.com/networkservicemesh/cmd-forwarder-vpp/internal/tests/copyfile"
	"github.com/networkservicemesh/cmd-forwarder-vpp/internal/tests/ns"
	"github.com/networkservicemesh/sdk-kernel/pkg/kernel/networkservice/connectioncontextkernel"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/connectioncontext"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/connectioncontext/mtu"

	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/mechanisms/kernel"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/mechanisms/memif"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/mechanisms/vxlan"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/mechanisms/wireguard"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/pinhole"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/stats"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/tag"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/up"
	"github.com/networkservicemesh/sdk-vpp/pkg/networkservice/xconnect"
	"github.com/networkservicemesh/sdk/pkg/networkservice/chains/endpoint"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms"
	kernelmechanism "github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanisms/kernel"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/mechanismtranslation"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/refresh"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/serialize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/common/updatepath"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/adapters"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/chain"
	"github.com/networkservicemesh/sdk/pkg/networkservice/ipam/point2pointipam"
	"github.com/networkservicemesh/sdk/pkg/networkservice/utils/metadata"
	"github.com/networkservicemesh/sdk/pkg/tools/token"
	"github.com/thanhpk/randstr"
	"github.com/vishvananda/netns"
	"net"
)

type kernelToVxlanVerifiableEndpoint struct {
	ctx     context.Context
	vppConn api.Connection
	endpointNSHandle netns.NsHandle
	endpoint.Endpoint
}

func newKernelToVxlanVerifiableEndpoint(ctx context.Context,
	prefix1, prefix2 *net.IPNet,
	tokenGenerator token.GeneratorFunc,
	vppConn vpphelper.Connection) verifiableEndpoint {

	rootNSHandle, err := netns.Get()
	if err != nil {
		panic(fmt.Sprintf("unable to get root netNs: %+v", err))
	}
	endpointNSName := fmt.Sprintf("endpoint-%s", randstr.Hex(4))
	endpointNSHandle, err := netns.NewNamed(endpointNSName)
	if err != nil {
		panic(fmt.Sprintf("unable create netNs %s: %+v", endpointNSName, err))
	}
	go func(endpointNsName string) {
		<-ctx.Done()
		_ = netns.DeleteNamed(endpointNsName)
	}(endpointNSName)

	rv := &kernelToVxlanVerifiableEndpoint{
		ctx:     ctx,
		vppConn: vppConn,
		endpointNSHandle: endpointNSHandle,
	}
	name := "vxlanVerifiableEndpoint"
	rv.Endpoint = endpoint.NewServer(ctx,
		tokenGenerator,
		endpoint.WithName(name),
		endpoint.WithAuthorizeServer(authorize.NewServer()),
		endpoint.WithAdditionalFunctionality(
			metadata.NewServer(),
			connectioncontext.NewServer(vppConn),
			up.NewServer(ctx, vppConn),
			xconnect.NewServer(vppConn),
			connectioncontextkernel.NewServer(),
			tag.NewServer(ctx, vppConn),
			mtu.NewServer(vppConn),
			pinhole.NewServer(vppConn),
			mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
				vxlan.MECHANISM: vxlan.NewServer(vppConn, net.ParseIP(serverIP)),
			}),
			adapters.NewClientToServer(clientChain(ctx, vppConn, net.ParseIP(serverIP))),
			updatepath.NewServer("ep-" + uuid.New().String()),
			//metadata.NewServer(),
			point2pointipam.NewServer(prefix1),
			point2pointipam.NewServer(prefix2),
			mechanisms.NewServer(map[string]networkservice.NetworkServiceServer{
				kernel.MECHANISM: chain.NewNetworkServiceServer(
					kernelmechanism.NewServer(),
				),
			}),
			ns.NewServer(endpointNSHandle),
			copyfile.NewServer(endpointNSName),
			ns.NewServer(rootNSHandle),
		),
	)

	return rv
}

func clientChain(ctx context.Context, vppConn vpphelper.Connection, tunnelIP net.IP) networkservice.NetworkServiceClient{
	return chain.NewNetworkServiceClient(
		[]networkservice.NetworkServiceClient{
			mechanismtranslation.NewClient(),
			updatepath.NewClient("client-" + uuid.New().String()),
			serialize.NewClient(),
			refresh.NewClient(ctx),
			metadata.NewClient(),
			mechanismtranslation.NewClient(),
			connectioncontextkernel.NewClient(),
			stats.NewClient(ctx),
			up.NewClient(ctx, vppConn),
			mtu.NewClient(vppConn),
			tag.NewClient(ctx, vppConn),
			// mechanisms
			memif.NewClient(vppConn),
			kernel.NewClient(vppConn),
			vxlan.NewClient(vppConn, tunnelIP),
			wireguard.NewClient(vppConn, tunnelIP),
			pinhole.NewClient(vppConn),
		}...)
}

func (v *kernelToVxlanVerifiableEndpoint) VerifyConnection(conn *networkservice.Connection) error {
	//namingConn := conn.Clone()
	//namingConn.Id = conn.GetPath().GetPathSegments()[len(conn.GetPath().GetPathSegments())-1].GetId()
	//namingConn.Mechanism = &networkservice.Mechanism{
	//	Cls:  cls.LOCAL,
	//	Type: kernel.MECHANISM,
	//	Parameters: map[string]string{
	//		krnl.InterfaceNameKey : "ns-",
	//	},
	//}
	////rootNSHandle, err := netns.Get()
	////if err != nil {
	////	panic(fmt.Sprintf("unable to get root netNs: %+v", err))
	////}
	//if err := checkKernelInterface(namingConn, conn.GetContext().GetIpContext().GetDstIPNets(), v.endpointNSHandle); err != nil {
	//	return err
	//}
	namingConn := conn.Clone()
	namingConn.Id = conn.GetPath().GetPathSegments()[len(conn.GetPath().GetPathSegments())-1].GetId()
	namingConn.Mechanism = &networkservice.Mechanism{
		Cls:  cls.LOCAL,
		Type: kernel.MECHANISM,
	}
	if err := checkKernelInterface(namingConn, conn.GetContext().GetIpContext().GetDstIPNets(), v.endpointNSHandle); err != nil {
		return err
	}
	for _, ip := range conn.GetContext().GetIpContext().GetSrcIPNets() {
		if err := pingKernel(ip, v.endpointNSHandle); err != nil {
			return err
		}
	}
	return nil
}

func (v *kernelToVxlanVerifiableEndpoint) VerifyClose(conn *networkservice.Connection) error {
	return checkNoKernelInterface(conn, v.endpointNSHandle)
}
