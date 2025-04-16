package v4

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/yerden/go-dpdk/eal"
	"github.com/yerden/go-dpdk/ethdev"
	"github.com/yerden/go-dpdk/mbuf"
	"github.com/yerden/go-dpdk/mempool"
)

type Server interface {
	// start server
	Serve() error
	// stop server
	Close() error
}

type DPDKServer struct {
	pciAddr   string
	devPort   ethdev.Port
	macAddr   net.HardwareAddr
	memPool   *mempool.Mempool
	handler   server4.Handler
	serverIp  net.IP
	logger    server4.Logger
	isRunning bool
}

// ServerOpt adds optional configuration to a server.
type ServerOpt func(s *DPDKServer)

// WithSummaryLogger logs one-line DHCPv4 message summaries when sent & received.
func WithSummaryLogger() ServerOpt {
	return func(s *DPDKServer) {
		s.logger = server4.ShortSummaryLogger{
			Printfer: log.New(os.Stderr, "[dhcpv4] ", log.LstdFlags),
		}
	}
}

// WithDebugLogger logs multi-line full DHCPv4 messages when sent & received.
func WithDebugLogger() ServerOpt {
	return func(s *DPDKServer) {
		s.logger = server4.DebugLogger{
			Printfer: log.New(os.Stderr, "[dhcpv4] ", log.LstdFlags),
		}
	}
}

func WithServerIP(ip net.IP) ServerOpt {
	return func(s *DPDKServer) {
		s.serverIp = ip
	}
}

func WithMacAddress(hw net.HardwareAddr) ServerOpt {
	return func(s *DPDKServer) {
		s.macAddr = hw
	}
}

func RTEBit64(n uint) uint64 {
	return 1 << n
}

var (
	RTE_ETH_RX_OFFLOAD_IPV4_CKSUM = RTEBit64(1) // 启用 ipv4 校验和硬件卸载
	RTE_ETH_RX_OFFLOAD_UDP_CKSUM  = RTEBit64(2) // 启用 UDP 校验和硬件卸载
	RTE_ETH_TX_OFFLOAD_IPV4_CKSUM = RTEBit64(1)
	RTE_ETH_TX_OFFLOAD_UDP_CKSUM  = RTEBit64(2)
)

var (
	ealInitOnce    = sync.Once{}
	ealInitSuccess = false
)

func EALInit() (err error) {
	ealInitOnce.Do(func() {
		_, err = eal.Init(os.Args)
		ealInitSuccess = err == nil
	})
	if err != nil {
		ealInitOnce = sync.Once{}
	}
	return err
}

func EALCleanup() (err error) {
	if ealInitSuccess {
		err = eal.Cleanup()
	}
	return err
}

func NewDPDKServer(pciAddress string, handler server4.Handler, opts ...ServerOpt) (*DPDKServer, error) {
	if err := EALInit(); err != nil {
		return nil, fmt.Errorf("failed to init EAL: %v", err)
	}
	port, err := ethdev.GetPortByName(pciAddress)
	if err != nil {
		return nil, fmt.Errorf("GetPortByName %s error: %v", pciAddress, err)
	}
	if !port.IsValid() {
		return nil, fmt.Errorf("prot is not valid")
	}
	macAddr := ethdev.MACAddr{}
	if err = port.MACAddrGet(&macAddr); err != nil {
		return nil, fmt.Errorf("MACAddrGet error: %v", err)
	}
	mpName := fmt.Sprintf("mbuf_rx0_%s", pciAddress)
	pool, err := mempool.CreateMbufPool(
		mpName,
		512,
		2048,
		mempool.OptPrivateDataSize(0),
		mempool.OptSocket(int(eal.SocketID())),
		mempool.OptCacheSize(0))
	if err != nil {
		return nil, fmt.Errorf("CreateMbufPool error: %v", err)
	}

	err = port.DevConfigure(
		1, 1,
		ethdev.OptRxMode(ethdev.RxMode{
			MqMode:   0, // 禁用多队列（单队列模式）
			MTU:      1500,
			Offloads: RTE_ETH_RX_OFFLOAD_IPV4_CKSUM | RTE_ETH_RX_OFFLOAD_UDP_CKSUM,
		}),
		ethdev.OptTxMode(ethdev.TxMode{
			MqMode:               0, // 禁用多队列（单队列模式）
			Pvid:                 0, // 不使用 VLAN
			Offloads:             RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM,
			HwVlanRejectTagged:   false,
			HwVlanRejectUntagged: false,
			HwVlanInsertPvid:     false,
		}))
	if err != nil {
		return nil, fmt.Errorf("DevConfigure error: %v", err)
	}
	// 启动接收队列
	err = port.RxqSetup(0, 512, pool,
		ethdev.OptSocket(int(eal.SocketID())))
	if err != nil {
		return nil, fmt.Errorf("RX queue setup failed: %v", err)
	}
	// 启动发送队列
	err = port.TxqSetup(0, 512,
		ethdev.OptSocket(int(eal.SocketID())))
	if err != nil {
		return nil, fmt.Errorf("TX queue setup failed: %v", err)
	}
	serv := &DPDKServer{
		pciAddr:  pciAddress,
		devPort:  port,
		macAddr:  macAddr.HardwareAddr(),
		memPool:  pool,
		handler:  handler,
		serverIp: net.ParseIP("0.0.0.0"),
		logger:   server4.EmptyLogger{},
	}
	for _, opt := range opts {
		opt(serv)
	}
	return serv, nil
}

func (s *DPDKServer) Serve() error {
	defer s.Close()

	if err := s.devPort.Start(); err != nil {
		return fmt.Errorf("dev port start failed: %v", err)
	}

	if err := s.devPort.PromiscEnable(); err != nil {
		return fmt.Errorf("PromiscEnable error: %v", err)
	}

	s.isRunning = true
	s.logger.Printf("Server running on %s", s.pciAddr)
	s.logger.Printf("Ready to handle requests")

	for s.isRunning {
		mbufs := make([]*mbuf.Mbuf, 32)
		numRx := s.devPort.RxBurst(0, mbufs)
		for i := uint16(0); i < numRx; i++ {
			go func(mbuff *mbuf.Mbuf) {
				defer mbuff.PktMbufFree()

				data := mbuff.Data()
				conn := NewDPDKConn(0, s.devPort, s.serverIp, s.macAddr, s.memPool)
				n, peer, err := conn.ReadFrom(data)
				if err != nil {
					s.logger.Printf("Error reading from packet conn: %v", err)
					return
				}
				s.logger.Printf("Handling request from %v", peer)
				pkt, err := dhcpv4.FromBytes(extractDHCPPayload(data[:n]))
				if err != nil {
					s.logger.Printf("Error parsing DHCPv4 request: %v", err)
					return
				}
				conn.DHCPReq = pkt
				upeer, ok := peer.(*net.UDPAddr)
				if !ok {
					s.logger.Printf("Not a UDP connection? Peer is %s", peer)
					return
				}
				// Set peer to broadcast if the client did not have an IP.
				if upeer.IP == nil || upeer.IP.To4().Equal(net.IPv4zero) {
					upeer.IP = net.IPv4bcast
				}
				s.handler(conn, upeer, pkt)
			}(mbufs[i])
		}
	}
	return nil
}

func (s *DPDKServer) Close() error {
	s.isRunning = false
	s.devPort.Stop()  // 停止网卡
	s.devPort.Close() // 关闭端口
	s.memPool.Free()
	return nil
}

type DHCPServer struct {
	server     *server4.Server
	dpdkServer *DPDKServer
	cancelFunc context.CancelFunc
}

type Option func(*DHCPServer)

func NewDHCPServer(opts ...Option) *DHCPServer {
	s := &DHCPServer{}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func WithServer(s *server4.Server) Option {
	return func(dhcpServer *DHCPServer) {
		dhcpServer.server = s
		dhcpServer.dpdkServer = nil
	}
}

func WithDPDKServer(s *DPDKServer) Option {
	return func(dhcpServer *DHCPServer) {
		dhcpServer.server = nil
		dhcpServer.dpdkServer = s
	}
}

func WithCancelFunc(c context.CancelFunc) Option {
	return func(dhcpServer *DHCPServer) {
		dhcpServer.cancelFunc = c
	}
}

func (s *DHCPServer) Serve() error {
	switch {
	case s.dpdkServer != nil:
		return s.dpdkServer.Serve()
	case s.server != nil:
		return s.server.Serve()
	}
	return nil
}

func (s *DHCPServer) Close() error {
	switch {
	case s.dpdkServer != nil:
		if err := s.dpdkServer.Close(); err != nil {
			return err
		}
	case s.server != nil:
		if err := s.server.Close(); err != nil {
			return err
		}
	}
	if s.cancelFunc != nil {
		s.cancelFunc()
	}
	return nil
}
