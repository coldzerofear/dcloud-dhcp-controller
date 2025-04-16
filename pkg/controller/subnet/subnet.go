package subnet

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"

	networkv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	kubeovnv1 "github.com/kubeovn/kube-ovn/pkg/apis/kubeovn/v1"
	ovnutil "github.com/kubeovn/kube-ovn/pkg/util"
	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"tydic.io/dcloud-dhcp-controller/pkg/controller/pod"
	"tydic.io/dcloud-dhcp-controller/pkg/util"
)

func (c *Controller) handlerDHCPV4(subnet *kubeovnv1.Subnet, provider string, networkStatus networkv1.NetworkStatus) error {
	// 1. check need dhcp v4 server
	if !needDHCPV4Server(subnet) {
		// If not needed, stop the server
		return c.deleteDHCPV4(subnet.Name, provider, subnet, networkStatus)
	}

	// 2. parse dhcpv4 options
	dhcpv4Options := strings.ReplaceAll(subnet.Spec.DHCPv4Options, " ", "")
	dhcpv4OptionsMap := util.ParseDHCPOptions(dhcpv4Options)

	// 3. build ovn subnet
	ovnSubnet, err := util.BuildOVNSubnetByIPV4Options(subnet, networkStatus, dhcpv4OptionsMap)
	if err != nil {
		c.recorder.Event(subnet, corev1.EventTypeWarning, "SubnetError", err.Error())
		return err
	}

	// 4. add or update subnet
	oldOVNSubnet, ok := c.dhcpV4.GetSubnet(subnet.Name)
	c.dhcpV4.AddOrUpdateSubnet(subnet.Name, *ovnSubnet)

	if ok && !reflect.DeepEqual(oldOVNSubnet, *ovnSubnet) { // if update dhcpv4 options, send recorder event
		c.recorder.Event(subnet, corev1.EventTypeNormal, "DHCPServer", "DHCPv4 options updated successfully")
	} else if !ok && provider != subnet.Spec.Provider {
		msg := fmt.Sprintf("Add subnet to the dhcp privider <%s> DHCPv4 server", provider)
		c.recorder.Event(subnet, corev1.EventTypeNormal, "DHCPServer", msg)
	}

	// 5. check dhcpv4 server already exists
	if exist := c.dhcpV4.HasDHCPServer(networkStatus.Interface); exist {
		log.Warnf("(subnet.handlerDHCPV4) Subnet <%s> network provider %s DHCP service already exists", subnet.Name, provider)
		// update dhcp v4 server gauge
		c.metrics.UpdateDHCPv4ServerInfo(networkStatus.Name, networkStatus.Interface, ovnSubnet.ServerIP.String(), ovnSubnet.ServerMac)
		return nil
	}

	// 6. if dhcpv4 server non-existent, add and run
	if err := c.dhcpV4.AddAndRun(networkStatus); err != nil {
		c.recorder.Event(subnet, corev1.EventTypeWarning, "DHCPServerError",
			fmt.Sprintf("The DHCPv4 server of network provider <%s> failed to start", provider))
		return fmt.Errorf("network provider <%s> DHCPv4 service Startup failed: %v", provider, err)
	}

	// 7. update dhcp v4 server gauge
	c.metrics.UpdateDHCPv4ServerInfo(networkStatus.Name, networkStatus.Interface, ovnSubnet.ServerIP.String(), ovnSubnet.ServerMac)

	c.recorder.Event(subnet, corev1.EventTypeNormal, "DHCPServer",
		fmt.Sprintf("The DHCPv4 server of network provider <%s> has been successfully started", provider))

	return nil
}

func (c *Controller) handlerDHCPV6(subnet *kubeovnv1.Subnet, provider string, networkStatus networkv1.NetworkStatus) error {
	// 1. check need dhcp v6 server
	if !needDHCPV6Server(subnet) {
		// If not needed, stop the server
		return c.deleteDHCPV6(subnet.Name, provider, subnet, networkStatus)
	}

	// 2. parse dhcpv6 options
	dhcpv6Options := strings.ReplaceAll(subnet.Spec.DHCPv6Options, " ", "")
	dhcpv6OptionsMap := util.ParseDHCPOptions(dhcpv6Options)

	// 3. build ovn subnet
	ovnSubnet, err := util.BuildOVNSubnetByIPV6Options(networkStatus, dhcpv6OptionsMap)
	if err != nil {
		c.recorder.Event(subnet, corev1.EventTypeWarning, "SubnetError", err.Error())
		return err
	}

	// 4. add or update subnet
	oldOVNSubnet, ok := c.dhcpV6.GetSubnet(subnet.Name)
	c.dhcpV6.AddOrUpdateSubnet(subnet.Name, *ovnSubnet)

	if ok && !reflect.DeepEqual(oldOVNSubnet, *ovnSubnet) { // if update dhcpv4 options, send recorder event
		c.recorder.Event(subnet, corev1.EventTypeNormal, "DHCPServer", "DHCPv6 options updated successfully")
	} else if !ok && provider != subnet.Spec.Provider {
		msg := fmt.Sprintf("Add subnet to the dhcp privider <%s> DHCPv6 server", provider)
		c.recorder.Event(subnet, corev1.EventTypeNormal, "DHCPServer", msg)
	}

	// 5. check dhcpv6 server already exists
	if exist := c.dhcpV6.HasDHCPServer(networkStatus.Interface); exist {
		log.Warnf("(subnet.handlerDHCPV6) Subnet <%s> network provider <%s> DHCP service already exists", subnet.Name, provider)
		// update dhcp v4 server gauge
		c.metrics.UpdateDHCPv4ServerInfo(networkStatus.Name, networkStatus.Interface, ovnSubnet.ServerIP.String(), ovnSubnet.ServerMac)
		return nil
	}

	// 6. if dhcpv6 server non-existent, add and run
	if err := c.dhcpV6.AddAndRun(networkStatus.Interface); err != nil {
		c.recorder.Event(subnet, corev1.EventTypeWarning, "DHCPServerError",
			fmt.Sprintf("The DHCPv6 server of network provider <%s> failed to start", provider))
		return fmt.Errorf("network provider <%s> DHCPv6 service Startup failed: %v", provider, err)
	}

	// 7. update dhcp v6 server gauge
	c.metrics.UpdateDHCPv6ServerInfo(networkStatus.Name, networkStatus.Interface, ovnSubnet.ServerIP.String(), ovnSubnet.ServerMac)

	c.recorder.Event(subnet, corev1.EventTypeNormal, "DHCPServer",
		fmt.Sprintf("The DHCPv6 server of network provider <%s> has been successfully started", provider))

	return nil
}

func (c *Controller) CreateOrUpdateDHCPServer(ctx context.Context, subnet *kubeovnv1.Subnet, provider string) error {
	// 1.check enable dhcp
	if !subnet.Spec.EnableDHCP {
		log.Infof("(subnet.CreateOrUpdateDHCPServer) Subnet <%s> did not enable DHCP", subnet.Name)
		return nil
	}

	// 2.check provider
	networkStatus, err := c.checkNetworkProvider(provider)
	if err != nil {
		log.Warnf("(subnet.CreateOrUpdateDHCPServer) Subnet <%s>: %v, skip it", subnet.Name, err)
		return nil
	}

	var errMsgs []string

	// 3.handler dhcp v4
	if err := c.handlerDHCPV4(subnet, provider, *networkStatus); err != nil {
		log.Errorf("(subnet.CreateOrUpdateDHCPServer) Subnet <%s> handlerDHCPV4 failed: %v", subnet.Name, err)
		errMsgs = append(errMsgs, fmt.Sprintf("handlerDHCPV4 error: %s", err.Error()))
	}

	// 4.handler dhcp v6
	if err := c.handlerDHCPV6(subnet, provider, *networkStatus); err != nil {
		log.Errorf("(subnet.CreateOrUpdateDHCPServer) Subnet <%s> handlerDHCPV6 failed: %v", subnet.Name, err)
		errMsgs = append(errMsgs, fmt.Sprintf("handlerDHCPV6 error: %s", err.Error()))
	}

	// 5.update subnet gauge
	c.metrics.UpdateDHCPSubnetInfo(subnet.Name, provider, subnet.Spec.CIDRBlock,
		ovnutil.CheckProtocol(subnet.Spec.CIDRBlock), subnet.Spec.Gateway, needDHCPV4Server(subnet), needDHCPV6Server(subnet))

	// 6.notify the update of pod lease gauge
	c.NotifyPods(subnet.Name)

	if len(errMsgs) > 0 {
		return fmt.Errorf(strings.Join(errMsgs, "; "))
	}

	return nil
}

// Insert all pods of the relevant subnet into the queue for coordination
func (c *Controller) NotifyPods(subnetName string) {
	notifyPodKeys := sets.New[types.NamespacedName]()
	podKeys, _ := c.dhcpV4.GetPodKeys(subnetName)
	key, _ := c.dhcpV6.GetPodKeys(subnetName)
	podKeys = append(podKeys, key...)
	for _, podKey := range podKeys {
		if split := strings.Split(podKey, string(types.Separator)); len(split) == 2 {
			notifyPodKeys.Insert(types.NamespacedName{
				Name:      split[1],
				Namespace: split[0],
			})
		}
	}
	for podKey := range notifyPodKeys {
		c.podNotify.EnQueue(pod.Event{ObjKey: podKey, Operation: pod.UPDATE})
	}
}

func (c *Controller) DeleteNetworkProvider(ctx context.Context, subnetKey types.NamespacedName, subnet *kubeovnv1.Subnet, provider string) error {
	// 1.check provider
	networkStatus, err := c.checkNetworkProvider(provider)
	if err != nil {
		log.Warnf("(subnet.DeleteNetworkProvider) Subnet <%s>: %v, skip deletion", subnetKey.Name, err)
		return nil
	}

	// 2. delete and stop dhcp v4 server
	err = c.deleteDHCPV4(subnetKey.Name, provider, subnet, *networkStatus)
	if err != nil {
		log.Errorf("(subnet.DeleteNetworkProvider) Subnet <%s> deleteDHCPV4 error: %v", subnetKey.Name, err)
		return err
	}

	// 3. delete and stop dhcp v6 server
	err = c.deleteDHCPV6(subnetKey.Name, provider, subnet, *networkStatus)
	if err != nil {
		log.Errorf("(subnet.DeleteNetworkProvider) Subnet <%s> deleteDHCPV4 error: %v", subnetKey.Name, err)
		return err
	}

	// 4.delete subnet gauge
	c.metrics.DeleteDHCPSubnetInfo(subnetKey.Name)

	// 5.notify the update of pod lease gauge
	c.NotifyPods(subnetKey.Name)

	return nil
}

func needDHCPV4Server(subnet *kubeovnv1.Subnet) bool {
	if subnet.Spec.EnableDHCP {
		protocol := ovnutil.CheckProtocol(subnet.Spec.CIDRBlock)
		return protocol == kubeovnv1.ProtocolIPv4 || protocol == kubeovnv1.ProtocolDual
	}
	return false
}

func needDHCPV6Server(subnet *kubeovnv1.Subnet) bool {
	if subnet.Spec.EnableDHCP {
		protocol := ovnutil.CheckProtocol(subnet.Spec.CIDRBlock)
		return protocol == kubeovnv1.ProtocolIPv6 || protocol == kubeovnv1.ProtocolDual
	}
	return false
}

func (c *Controller) deleteDHCPV4(subnetName, provider string, subnet *kubeovnv1.Subnet, networkStatus networkv1.NetworkStatus) error {
	// 1. remove dhcp ovn subnet
	_ = c.dhcpV4.DeleteSubnet(subnetName)

	// 2. check Other subnet references
	subnets, err := c.GetSubnetsByDHCPProvider(provider)
	if err != nil {
		return fmt.Errorf("GetSubnetsByNetProvider error: %v", err)
	}

	exist := slices.ContainsFunc(subnets, func(subnet *kubeovnv1.Subnet) bool {
		return subnet.Name != subnetName && needDHCPV4Server(subnet)
	})

	sendEvent := subnet != nil && provider == subnet.Spec.Provider

	if exist {
		log.Warnf("(subnet.deleteDHCPV4) Subnet <%s> dhcp provider <%s> has other subnets in use and cannot delete the DHCP service", subnetName, provider)
		if sendEvent {
			c.recorder.Event(subnet, corev1.EventTypeWarning, "DHCPServer", "There are other subnets using the DHCPv4 server and it cannot be stopped")
		}
		return nil
	}

	// interface using count > 1, indicates multiple references
	interfaceBusy := c.networkCache.GetInterfaceCount(networkStatus.Interface) > 1
	if interfaceBusy {
		log.Warnf("(subnet.deleteDHCPV4) Subnet <%s> Multiple providers using interface <%s> have been detected, "+
			"and the DHCP server cannot be stopped due to busy network interfaces", subnetName, networkStatus.Interface)
	}

	// 3. delete and stop dhcp v4 server
	if !interfaceBusy && c.dhcpV4.HasDHCPServer(networkStatus.Interface) {
		if err = c.dhcpV4.DelAndStop(networkStatus.Interface); err != nil {
			return fmt.Errorf("stopping the DHCPv4 server of network provider <%s> failed: %v", provider, err)
		}
		if sendEvent {
			c.recorder.Event(subnet, corev1.EventTypeNormal, "DHCPServer", "The DHCPv4 server has been successfully shutdown")
		}
	}

	// 4. delete dhcp v4 server gauge
	c.metrics.DeleteDHCPv4ServerInfo(networkStatus.Name)

	return nil
}

func (c *Controller) deleteDHCPV6(subnetName, provider string, subnet *kubeovnv1.Subnet, networkStatus networkv1.NetworkStatus) error {
	// 1. remove dhcp ovn subnet
	_ = c.dhcpV6.DeleteSubnet(subnetName)

	// 2. check Other subnet references
	subnets, err := c.GetSubnetsByDHCPProvider(provider)
	if err != nil {
		return fmt.Errorf("GetSubnetsByNetProvider error: %v", err)
	}

	exist := slices.ContainsFunc(subnets, func(subnet *kubeovnv1.Subnet) bool {
		return subnet.Name != subnetName && needDHCPV6Server(subnet)
	})

	sendEvent := subnet != nil && provider == subnet.Spec.Provider

	if exist {
		log.Warnf("(subnet.deleteDHCPV6) Subnet <%s> dhcp provider <%s> has other subnets in use and cannot delete the DHCP service", subnetName, provider)
		if sendEvent {
			c.recorder.Event(subnet, corev1.EventTypeWarning, "DHCPServer", "There are other subnets using the DHCPv6 server and it cannot be stopped")
		}
		return nil
	}

	// interface using count > 1, indicates multiple references
	interfaceBusy := c.networkCache.GetInterfaceCount(networkStatus.Interface) > 1
	if interfaceBusy {
		log.Warnf("(subnet.deleteDHCPV6) Subnet <%s> Multiple providers using interface <%s> have been detected, "+
			"and the DHCP server cannot be stopped due to busy network interfaces", subnetName, networkStatus.Interface)
	}

	// 3. delete and stop dhcp v6 server
	if !interfaceBusy && c.dhcpV6.HasDHCPServer(networkStatus.Interface) {
		if err = c.dhcpV6.DelAndStop(networkStatus.Interface); err != nil {
			return fmt.Errorf("stopping the DHCPv6 server of network provider <%s> failed: %v", provider, err)
		}
		if sendEvent {
			c.recorder.Event(subnet, corev1.EventTypeNormal, "DHCPServer", "The DHCPv6 server has been successfully shutdown")
		}
	}

	// 4. delete dhcp v6 server gauge
	c.metrics.DeleteDHCPv6ServerInfo(networkStatus.Name)

	return nil
}

func (c *Controller) checkNetworkProvider(provider string) (*networkv1.NetworkStatus, error) {
	split := strings.Split(provider, ".")
	if len(split) != 2 {
		return nil, fmt.Errorf("invalid network provider <%s>", provider)
	}
	multusName, multusNamespace := split[0], split[1]
	nadName := fmt.Sprintf("%s/%s", multusNamespace, multusName)
	networkStatus, ok := c.networkCache.GetNetworkStatus(nadName)
	if !ok {
		return nil, fmt.Errorf("unsupported network provider <%s>", provider)
	}
	return networkStatus, nil
}
