package v6

import (
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/server6"
	"github.com/insomniacslk/dhcp/iana"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"
)

type OVNSubnet struct {
	ServerMac string   // dhcp server mac
	ServerIP  net.IP   // dhcp server ip
	NTP       []net.IP // ipv6 ntp地址
	DNS       []net.IP // ipv6 dns地址
	LeaseTime int      // dhcp lease time (second), default: 3600
}

type DHCPLease struct {
	ClientIP  net.IP
	SubnetKey string
}

type DHCPServer struct {
	server     *server6.Server
	cancelFunc context.CancelFunc
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

	servers map[string]DHCPServer
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
	servers := make(map[string]DHCPServer)

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
		log.Debugf("(dhcpv6.AddOrUpdateSubnet) Subnet <%s> updated", subnetKey)
	} else {
		log.Debugf("(dhcpv6.AddOrUpdateSubnet) Subnet <%s> added", subnetKey)
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
		log.Debugf("(dhcpv6.DeleteSubnet) Subnet <%s> deleted", subnetKey)
	} else {
		log.Debugf("(dhcpv6.DeleteSubnet) Subnet <%s> is not found", subnetKey)
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

	log.Debugf("(dhcpv6.AddDHCPLease) lease added for hardware address: %s", hwAddr)

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
		log.Debugf("(dhcpv6.DeletePodDHCPLease) Pod <%s> not found in podkeyMACs", podKey)
		return fmt.Errorf("pod <%s> not found in podkeyMACs", podKey)
	}

	subnets, ok := a.podkeySubnets[podKey]
	if !ok {
		log.Debugf("(dhcpv6.DeletePodDHCPLease) Pod <%s> not found in podkeySubnets", podKey)
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
	log.Debugf("(dhcpv6.DeletePodDHCPLease) Pod <%s> lease deleted for hardware address: %+v", podKey, delMacList)

	for _, subnetKey := range subnets.List() {
		keySet, ok := a.subnetPodKeys[subnetKey]
		if ok && keySet.Equal(sets.NewString(podKey)) {
			delete(a.subnetPodKeys, subnetKey)
		} else if ok {
			a.subnetPodKeys[subnetKey] = keySet.Delete(podKey)
		}
	}
	delete(a.podkeySubnets, podKey)

	log.Debugf("(dhcpv6.AddDHCPLease) lease deleted for pod <%s>", podKey)

	return nil
}

func (a *DHCPAllocator) dhcpHandler(conn net.PacketConn, peer net.Addr, m dhcpv6.DHCPv6) {

	if m == nil {
		log.Errorf("(dhcpv6.dhcpHandler) packet is nil!")
		return
	}

	log.Tracef("(dhcpv6.dhcpHandler) INCOMING PACKET=%s", m.Summary())

	msg, err := m.GetInnerMessage()
	if err != nil {
		log.Errorf("(dhcpv6.dhcpHandler) failed loading inner message: %s", err)
		return
	}

	hwaddr, err := dhcpv6.ExtractMAC(m)
	if err != nil {
		log.Errorf("(dhcpv6.dhcpHandler) error extracting hwaddr: %s", err)
		return
	}

	lease, ok := a.GetDHCPLease(hwaddr.String())
	if !ok || lease.ClientIP == nil {
		log.Warnf("(dhcpv6.dhcpHandler) NO LEASE FOUND: hwaddr=%s", hwaddr.String())
		return
	}

	subnet, ok := a.GetSubnet(lease.SubnetKey)
	if !ok {
		log.Warnf("(dhcpv6.dhcpHandler) NO MATCHED SUBNET FOUND FOR LEASE: hwaddr=%s", hwaddr.String())
		return
	}

	log.Debugf("(dhcpv6.dhcpHandler) LEASE FOUND: hwaddr=%s, serverip=%s, serverid=%s, clientip=%s, ntp=%+v, dns=%+v, leasetime=%d",
		hwaddr.String(),
		subnet.ServerIP.String(),
		subnet.ServerMac,
		lease.ClientIP.String(),
		subnet.NTP,
		subnet.DNS,
		subnet.LeaseTime,
	)
	serverMac, _ := net.ParseMAC(subnet.ServerMac)

	modifiers := []dhcpv6.Modifier{
		dhcpv6.WithIANA(dhcpv6.OptIAAddress{ // set ip lease
			IPv6Addr:          lease.ClientIP,
			PreferredLifetime: time.Duration(subnet.LeaseTime) * time.Second,
			ValidLifetime:     time.Duration(subnet.LeaseTime) * time.Second,
		}),
		dhcpv6.WithServerID(&dhcpv6.DUIDLLT{ // set server mac
			HWType:        iana.HWTypeEthernet,
			Time:          dhcpv6.GetTime(),
			LinkLayerAddr: serverMac,
		}),
	}

	if len(subnet.DNS) > 0 {
		modifiers = append(modifiers, dhcpv6.WithDNS(subnet.DNS...))
	}
	if len(subnet.NTP) > 0 {
		so := dhcpv6.NTPSuboptionSrvAddr(subnet.NTP[0])
		modifiers = append(modifiers, dhcpv6.WithOption(&so))
	}

	//if match.Hostname != "" {
	//	modifiers = append(modifiers,
	//		dhcpv6.WithFQDN(0, match.Hostname),
	//	)
	//}

	var resp *dhcpv6.Message

	switch msg.MessageType { //nolint:exhaustive
	case dhcpv6.MessageTypeSolicit:
		if msg.GetOneOption(dhcpv6.OptionRapidCommit) == nil {
			log.Debugf("(dhcpv6.dhcpHandler) DHCPSOLICIT: %+v", msg)
			resp, err = dhcpv6.NewAdvertiseFromSolicit(msg, modifiers...)
			log.Debugf("(dhcpv6.dhcpHandler) DHCPADVERTISE: %+v", resp)
		} else {
			// for DHCP clients that support fast allocation, simply return a reply
			log.Debugf("(dhcpv6.dhcpHandler) DHCPRAPIDCOMMIT: %+v", msg)
			resp, err = dhcpv6.NewReplyFromMessage(msg, modifiers...)
			log.Debugf("(dhcpv6.dhcpHandler) DHCPREPLY: %+v", resp)
		}
	default:
		log.Debugf("(dhcpv6.dhcpHandler) DHCPREQUEST: %+v", msg)
		resp, err = dhcpv6.NewReplyFromMessage(msg, modifiers...)
		log.Debugf("(dhcpv6.dhcpHandler) DHCPREPLY: %+v", resp)
	}

	if err != nil {
		log.Errorf("(dhcpv6.dhcpHandler) Failure building response: %s", err)
		return
	}

	ianaRequest := msg.Options.OneIANA()
	if ianaRequest != nil {
		ianaResponse := resp.Options.OneIANA()
		ianaResponse.IaId = ianaRequest.IaId
		resp.UpdateOption(ianaResponse)
	}

	if _, err = conn.WriteTo(resp.ToBytes(), peer); err != nil {
		log.Errorf("(dhcpv6.dhcpHandler) Failure sending response: %s", err)
	}
}

func (a *DHCPAllocator) HasDHCPServer(nic string) bool {
	a.mutex.RLock()
	_, exist := a.servers[nic]
	a.mutex.RUnlock()
	return exist
}

func (a *DHCPAllocator) AddAndRun(nic string) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	log.Infof("(dhcpv6.AddAndRun) starting DHCP service on nic <%s>", nic)

	if _, exist := a.servers[nic]; exist {
		return fmt.Errorf("DHCPv6 server on nic <%s> already exists", nic)
	}

	addr := net.UDPAddr{
		IP:   net.IPv6unspecified,
		Port: dhcpv6.DefaultServerPort,
	}

	var opt server6.ServerOpt
	if log.StandardLogger().GetLevel() == log.InfoLevel {
		opt = server6.WithSummaryLogger()
	}
	if log.StandardLogger().GetLevel() >= log.DebugLevel {
		opt = server6.WithDebugLogger()
	}

	server, err := server6.NewServer(nic, &addr, a.dhcpHandler, opt)
	if err != nil {
		return fmt.Errorf("error new DHCPv6 server on nic <%s>: %v", nic, err)
	}

	go func() {
		log.Infof("(dhcpv6.AddAndRun) serve: %v", server.Serve())
	}()

	ctx, cancelFunc := context.WithCancel(a.ctx)

	a.servers[nic] = DHCPServer{
		server:     server,
		cancelFunc: cancelFunc,
	}

	go func() {
		select {
		case <-a.ctx.Done():
			log.Infof("(dhcpv6.AddAndRun) Main context done: %v", a.DelAndStop(nic))
		case <-ctx.Done():
		}
	}()

	log.Debugf("(dhcpv6.AddAndRun) DHCP server on nic <%s> has started", nic)

	return nil
}

func (a *DHCPAllocator) DelAndStop(nic string) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	log.Infof("(dhcpv6.DelAndStop) stopping DHCP service on nic <%s>", nic)

	dhcpServer, ok := a.servers[nic]
	if !ok {
		log.Warnf("(dhcpv6.DelAndStop) DHCP server on nic <%s> not found", nic)
		return nil
	}

	err := dhcpServer.server.Close()
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("error closing DHCPv6 server on nic <%s>: %v", nic, err)
	}

	dhcpServer.cancelFunc()

	delete(a.servers, nic)

	log.Debugf("(dhcpv6.DelAndStop) DHCP server on nic <%s> has stopped", nic)

	return nil
}
