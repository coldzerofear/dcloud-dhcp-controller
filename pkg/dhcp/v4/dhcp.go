package v4

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	networkv1 "github.com/k8snetworkplumbingwg/network-attachment-definition-client/pkg/apis/k8s.cni.cncf.io/v1"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"
)

type OVNSubnet struct {
	ServerMac  string // dhcp server mac
	ServerIP   net.IP // dhcp server ip
	SubnetMask net.IPMask
	MTU        uint32
	Routers    []net.IP // default router=$ipv4_gateway
	NTP        []net.IP
	DNS        []net.IP
	LeaseTime  int // dhcp lease time (second), default: 3600
}

type DHCPLease struct {
	ClientIP  net.IP
	SubnetKey string
}

type DHCPAllocator struct {
	ctx     context.Context
	subnets map[string]OVNSubnet
	leases  map[string]DHCPLease
	// Mac and Pod related indexes
	macPodKeys map[string]sets.String // Mac       -> PodKeys mapping
	podkeyMACs map[string]sets.String // PodKey    -> MACs    mapping

	// Subnet and Pod related indexes
	subnetPodKeys map[string]sets.String // SubnetKey -> PodKeys    mapping
	podkeySubnets map[string]sets.String // PodKey    -> SubnetKeys mapping

	servers map[string]Server
	mutex   sync.RWMutex
}

func New(ctx context.Context) *DHCPAllocator {
	return NewDHCPAllocator(ctx)
}

func NewDHCPAllocator(ctx context.Context) *DHCPAllocator {
	subnets := make(map[string]OVNSubnet)
	leases := make(map[string]DHCPLease)
	macPodKeys := make(map[string]sets.String)
	podkeyMACs := make(map[string]sets.String)
	subnetPodKeys := make(map[string]sets.String)
	podkeySubnets := make(map[string]sets.String)
	servers := make(map[string]Server)

	return &DHCPAllocator{
		ctx:           ctx,
		subnets:       subnets,
		leases:        leases,
		macPodKeys:    macPodKeys,
		podkeyMACs:    podkeyMACs,
		subnetPodKeys: subnetPodKeys,
		podkeySubnets: podkeySubnets,
		servers:       servers,
	}
}

func (a *DHCPAllocator) GetSubnet(name string) (OVNSubnet, bool) {
	a.mutex.RLock()
	subnet, ok := a.subnets[name]
	a.mutex.RUnlock()
	return subnet, ok
}

func (a *DHCPAllocator) AddOrUpdateSubnet(subnetKey string, subnet OVNSubnet) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	_, ok := a.subnets[subnetKey]
	a.subnets[subnetKey] = subnet

	if ok {
		log.Debugf("(dhcpv4.AddOrUpdateSubnet) Subnet <%s> updated", subnetKey)
	} else {
		log.Debugf("(dhcpv4.AddOrUpdateSubnet) Subnet <%s> added", subnetKey)
	}

	return
}

func (a *DHCPAllocator) DeleteSubnet(subnetKey string) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if subnetKey == "" {
		return fmt.Errorf("subnetKey is empty")
	}

	if _, ok := a.subnets[subnetKey]; ok {
		delete(a.subnets, subnetKey)
		log.Debugf("(dhcpv4.DeleteSubnet) Subnet <%s> deleted", subnetKey)
	} else {
		log.Debugf("(dhcpv4.DeleteSubnet) Subnet <%s> is not found", subnetKey)
		return fmt.Errorf("subnet <%s> is not found", subnetKey)
	}

	return nil
}

func (a *DHCPAllocator) GetDHCPLease(hwAddr string) (DHCPLease, bool) {
	a.mutex.RLock()
	lease, ok := a.leases[hwAddr]
	a.mutex.RUnlock()
	return lease, ok
}

func (a *DHCPAllocator) HasPodDHCPLease(hwAddr, podKey string, dhcpLease DHCPLease) bool {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	macSet, existPod := a.podkeyMACs[podKey]
	if !existPod || !macSet.Has(hwAddr) {
		return false
	}
	podSet, existMac := a.macPodKeys[hwAddr]
	if !existMac || !podSet.Has(podKey) {
		return false
	}
	subnetKey := dhcpLease.SubnetKey
	subSet, existPod := a.podkeySubnets[podKey]
	if !existPod || !subSet.Has(subnetKey) {
		return false
	}
	podSet, existSub := a.subnetPodKeys[subnetKey]
	if !existSub || !podSet.Has(podKey) {
		return false
	}
	lease, existLease := a.leases[hwAddr]
	if !existLease {
		return false
	}
	return reflect.DeepEqual(lease, dhcpLease)
}

func (a *DHCPAllocator) AddPodDHCPLease(hwAddr, podKey string, dhcpLease DHCPLease) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if hwAddr == "" {
		return fmt.Errorf("hwaddr is empty")
	}

	if podKey == "" {
		return fmt.Errorf("podKey is empty")
	}

	subnetKey := dhcpLease.SubnetKey
	if subnetKey == "" {
		return fmt.Errorf("subnetKey is empty")
	}

	if _, err := net.ParseMAC(hwAddr); err != nil {
		return fmt.Errorf("hwaddr <%s> is not valid", hwAddr)
	}

	a.leases[hwAddr] = dhcpLease

	// add mac to podKeys mapping
	if keySet, ok := a.macPodKeys[hwAddr]; ok {
		a.macPodKeys[hwAddr] = keySet.Insert(podKey)
	} else {
		a.macPodKeys[hwAddr] = sets.NewString(podKey)
	}
	// add podKeys to macs mapping
	if macSet, ok := a.podkeyMACs[podKey]; ok {
		a.podkeyMACs[podKey] = macSet.Insert(hwAddr)
	} else {
		a.podkeyMACs[podKey] = sets.NewString(hwAddr)
	}

	// add subnetKey to podKeys mapping
	if keySet, ok := a.subnetPodKeys[subnetKey]; ok {
		a.subnetPodKeys[subnetKey] = keySet.Insert(podKey)
	} else {
		a.subnetPodKeys[subnetKey] = sets.NewString(podKey)
	}
	// add podKey to subnetKeys mapping
	if keySet, ok := a.podkeySubnets[podKey]; ok {
		a.podkeySubnets[podKey] = keySet.Insert(subnetKey)
	} else {
		a.podkeySubnets[podKey] = sets.NewString(subnetKey)
	}

	log.Debugf("(dhcpv4.AddDHCPLease) lease added for hardware address: %s", hwAddr)

	return nil
}

func (a *DHCPAllocator) GetPodMacAddress(podKey string) ([]string, bool) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	macSet, ok := a.podkeyMACs[podKey]
	if ok {
		return macSet.List(), ok
	}
	return nil, ok
}

func (a *DHCPAllocator) GetPodKeys(subnetKey string) ([]string, bool) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	keySet, ok := a.subnetPodKeys[subnetKey]
	if ok {
		return keySet.List(), ok
	}
	return nil, ok
}

func (a *DHCPAllocator) DeletePodDHCPLease(podKey string) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if podKey == "" {
		return fmt.Errorf("pod key is empty")
	}

	macSet, ok := a.podkeyMACs[podKey]
	if !ok {
		log.Debugf("(dhcpv4.DeletePodDHCPLease) Pod <%s> not found in podkeyMACs", podKey)
		return fmt.Errorf("pod <%s> not found in podkeyMACs", podKey)
	}

	subnets, ok := a.podkeySubnets[podKey]
	if !ok {
		log.Debugf("(dhcpv4.DeletePodDHCPLease) Pod <%s> not found in podkeySubnets", podKey)
		return fmt.Errorf("pod <%s> not found in podkeySubnets", podKey)
	}

	var delMacList []string
	for _, macAddr := range macSet.List() {
		keySet, ok := a.macPodKeys[macAddr]
		if ok && keySet.Equal(sets.NewString(podKey)) {
			delete(a.leases, macAddr)
			delete(a.macPodKeys, macAddr)
			delMacList = append(delMacList, macAddr)
		} else if ok {
			a.macPodKeys[macAddr] = keySet.Delete(podKey)
		}
	}
	delete(a.podkeyMACs, podKey)
	log.Debugf("(dhcpv4.DeletePodDHCPLease) Pod <%s> lease deleted for hardware address: %+v", podKey, delMacList)

	for _, subnetKey := range subnets.List() {
		keySet, ok := a.subnetPodKeys[subnetKey]
		if ok && keySet.Equal(sets.NewString(podKey)) {
			delete(a.subnetPodKeys, subnetKey)
		} else if ok {
			a.subnetPodKeys[subnetKey] = keySet.Delete(podKey)
		}
	}
	delete(a.podkeySubnets, podKey)

	log.Debugf("(dhcpv4.AddDHCPLease) lease deleted for pod <%s>", podKey)

	return nil
}

func (a *DHCPAllocator) dhcpHandler(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	if m == nil {
		log.Errorf("(dhcpv4.dhcpHandler) packet is nil!")
		return
	}

	log.Tracef("(dhcpv4.dhcpHandler) INCOMING PACKET=%s", m.Summary())

	if m.OpCode != dhcpv4.OpcodeBootRequest {
		log.Errorf("(dhcpv4.dhcpHandler) not a BootRequest!")
		return
	}

	reply, err := dhcpv4.NewReplyFromRequest(m)
	if err != nil {
		log.Errorf("(dhcpv4.dhcpHandler) NewReplyFromRequest failed: %v", err)
		return
	}

	lease, ok := a.GetDHCPLease(m.ClientHWAddr.String())
	if !ok || lease.ClientIP == nil {
		log.Warnf("(dhcpv4.dhcpHandler) NO LEASE FOUND: hwaddr=%s", m.ClientHWAddr.String())
		return
	}

	subnet, ok := a.GetSubnet(lease.SubnetKey)
	if !ok {
		log.Warnf("(dhcpv4.dhcpHandler) NO MATCHED SUBNET FOUND FOR LEASE: hwaddr=%s", m.ClientHWAddr.String())
		return
	}

	log.Debugf("(dhcpv4.dhcpHandler) LEASE FOUND: hwaddr=%s, serverip=%s, clientip=%s, mask=%s, router=%+v, dns=%+v, ntp=%+v, leasetime=%d",
		m.ClientHWAddr.String(),
		subnet.ServerIP.String(),
		lease.ClientIP.String(),
		subnet.SubnetMask.String(),
		subnet.Routers,
		subnet.DNS,
		subnet.NTP,
		subnet.LeaseTime,
	)

	reply.ClientIPAddr = lease.ClientIP
	reply.ServerIPAddr = subnet.ServerIP
	reply.YourIPAddr = lease.ClientIP
	reply.TransactionID = m.TransactionID
	reply.ClientHWAddr = m.ClientHWAddr
	reply.Flags = m.Flags
	reply.GatewayIPAddr = m.GatewayIPAddr

	reply.UpdateOption(dhcpv4.OptServerIdentifier(subnet.ServerIP))
	reply.UpdateOption(dhcpv4.OptSubnetMask(subnet.SubnetMask))
	reply.UpdateOption(dhcpv4.OptRouter(subnet.Routers...))

	if subnet.MTU > 0 && reply.IsOptionRequested(dhcpv4.OptionInterfaceMTU) {
		reply.UpdateOption(dhcpv4.OptGeneric(
			dhcpv4.OptionInterfaceMTU, dhcpv4.Uint16(subnet.MTU).ToBytes()))
	}
	if len(subnet.DNS) > 0 {
		reply.UpdateOption(dhcpv4.OptDNS(subnet.DNS...))
	}

	//if pool.DomainName != "" {
	//	reply.UpdateOption(dhcpv4.OptDomainName(pool.DomainName))
	//}
	//
	//if len(pool.DomainSearch) > 0 {
	//	dsl := rfc1035label.NewLabels()
	//	dsl.Labels = append(dsl.Labels, pool.DomainSearch...)
	//
	//	reply.UpdateOption(dhcpv4.OptDomainSearch(dsl))
	//}
	//
	if len(subnet.NTP) > 0 {
		reply.UpdateOption(dhcpv4.OptNTPServers(subnet.NTP...))
	}

	reply.UpdateOption(dhcpv4.OptIPAddressLeaseTime(time.Duration(subnet.LeaseTime) * time.Second))

	switch mt := m.MessageType(); mt {
	case dhcpv4.MessageTypeDiscover:
		log.Debugf("(dhcpv4.dhcpHandler) DHCPDISCOVER: %+v", m)
		reply.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeOffer))
		log.Debugf("(dhcpv4.dhcpHandler) DHCPOFFER: %+v", reply)
	case dhcpv4.MessageTypeRequest:
		log.Debugf("(dhcpv4.dhcpHandler) DHCPREQUEST: %+v", m)
		reply.UpdateOption(dhcpv4.OptMessageType(dhcpv4.MessageTypeAck))
		log.Debugf("(dhcpv4.dhcpHandler) DHCPACK: %+v", reply)
	default:
		log.Warnf("(dhcpv4.dhcpHandler) Unhandled message type for hwaddr [%s]: %v", m.ClientHWAddr.String(), mt)
		return
	}

	if _, err := conn.WriteTo(reply.ToBytes(), peer); err != nil {
		log.Errorf("(dhcpv4.dhcpHandler) Cannot reply to client: %v", err)
	}
}

func (a *DHCPAllocator) HasDHCPServer(nic string) bool {
	a.mutex.RLock()
	_, exist := a.servers[nic]
	a.mutex.RUnlock()
	return exist
}

func IsIPv4(ipAddr string) bool {
	ip := net.ParseIP(ipAddr)
	return ip != nil && strings.Contains(ipAddr, ".")
}

func GetFirstIPV4Addr(status networkv1.NetworkStatus) net.IP {
	for _, ip := range status.IPs {
		if IsIPv4(ip) {
			return net.ParseIP(ip)
		}
	}
	return nil
}

func (a *DHCPAllocator) AddAndRun(networkStatus networkv1.NetworkStatus) (err error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()
	nic := networkStatus.Interface

	log.Infof("(dhcpv4.AddAndRun) starting DHCP service on nic <%s>", nic)

	if _, exist := a.servers[nic]; exist {
		return fmt.Errorf("DHCPv4 server on nic <%s> already exists", nic)
	}

	var serverOpt Option
	switch {
	case networkStatus.DeviceInfo != nil && networkStatus.DeviceInfo.Type == "pci" &&
		networkStatus.DeviceInfo.Pci != nil && len(networkStatus.DeviceInfo.Pci.PciAddress) > 0:
		var opts []ServerOpt
		if log.StandardLogger().GetLevel() >= log.DebugLevel {
			opts = append(opts, WithDebugLogger())
		}
		pciAddress := networkStatus.DeviceInfo.Pci.PciAddress
		var server *DPDKServer
		serverIP := GetFirstIPV4Addr(networkStatus)
		opts = append(opts, WithServerIP(serverIP))
		if mac, err := net.ParseMAC(networkStatus.Mac); err == nil {
			opts = append(opts, WithMacAddress(mac))
		}
		server, err = NewDPDKServer(pciAddress, a.dhcpHandler, opts...)
		serverOpt = WithDPDKServer(server)
	default:
		// we need to listen on 0.0.0.0 otherwise client discovers will not be answered
		addr := net.UDPAddr{
			IP:   net.ParseIP("0.0.0.0"),
			Port: 67,
		}
		var opt server4.ServerOpt
		if log.StandardLogger().GetLevel() >= log.DebugLevel {
			opt = server4.WithDebugLogger()
		}
		var server *server4.Server
		server, err = server4.NewServer(nic, &addr, a.dhcpHandler, opt)
		serverOpt = WithServer(server)
	}

	if err != nil {
		return fmt.Errorf("error new DHCPv4 server on nic <%s>: %v", nic, err)
	}

	ctx, cancelFunc := context.WithCancel(a.ctx)
	server := NewDHCPServer(serverOpt, WithCancelFunc(cancelFunc))

	go func() {
		log.Infof("(dhcpv4.AddAndRun) serve: %v", server.Serve())
	}()

	a.servers[nic] = server

	go func() {
		select {
		case <-a.ctx.Done():
			log.Infof("(dhcpv4.AddAndRun) Main context done: %v", a.DelAndStop(nic))
		case <-ctx.Done():
		}
	}()

	log.Debugf("(dhcpv4.AddAndRun) DHCP server on nic <%s> has started", nic)

	return nil
}

func (a *DHCPAllocator) DelAndStop(nic string) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	log.Infof("(dhcpv4.DelAndStop) stopping DHCP service on nic <%s>", nic)

	dhcpServer, ok := a.servers[nic]
	if !ok {
		log.Warnf("(dhcpv4.DelAndStop) DHCP server on nic <%s> not found", nic)
		return nil
	}

	err := dhcpServer.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("error closing DHCPv4 server on nic <%s>: %v", nic, err)
	}

	delete(a.servers, nic)

	log.Debugf("(dhcpv4.DelAndStop) DHCP server on nic <%s> has stopped", nic)

	return nil
}
