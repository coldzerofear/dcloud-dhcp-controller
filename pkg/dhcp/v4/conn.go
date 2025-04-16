package v4

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/yerden/go-dpdk/ethdev"
	"github.com/yerden/go-dpdk/mbuf"
	"github.com/yerden/go-dpdk/mempool"
)

var _ net.PacketConn = &DPDKConn{}

func NewDPDKConn(qid uint16, devPort ethdev.Port,
	serverIp net.IP, macAddr net.HardwareAddr,
	memPool *mempool.Mempool) *DPDKConn {
	return &DPDKConn{
		qid:      qid,
		devPort:  devPort,
		serverIp: serverIp,
		macAddr:  macAddr,
		memPool:  memPool,
	}
}

type DPDKConn struct {
	qid      uint16
	devPort  ethdev.Port
	serverIp net.IP
	macAddr  net.HardwareAddr
	memPool  *mempool.Mempool
	DHCPReq  *dhcpv4.DHCPv4
}

func extractDHCPPayload(data []byte) []byte {
	ipHeader := data[14:]
	ipIHL := int(ipHeader[0]&0x0F) * 4 // 实际 IP 头长度

	// 计算 DHCP 载荷起始位置
	payloadStart := 14 + ipIHL + 8 // 以太网头 + IP头 + UDP头
	if len(data) < payloadStart {
		return nil
	}

	return data[payloadStart:]
}

func parseIPv4DHCPRequest(data []byte) ([]byte, *net.UDPAddr, error) {
	// 1. 检查以太网帧长度是否足够
	if len(data) < 14+20+8 { // 以太网头(14) + 最小IP头(20) + UDP头(8)
		return nil, nil, fmt.Errorf("Insufficient Ethernet frame length")
	}
	// 2. 检查 EtherType 是否为 IPv4
	etherType := binary.BigEndian.Uint16(data[12:14])
	if etherType != 0x0800 {
		return nil, nil, fmt.Errorf("EtherType is not IPv4")
	}
	// 3. 解析 IPv4 头部
	ipHeader := data[14:]
	ipVersion := ipHeader[0] >> 4
	if ipVersion != 4 {
		return nil, nil, fmt.Errorf("It's not an IPv4 package") // 非 IPv4 包
	}
	// IP 头长度（字节）
	ipIHL := int(ipHeader[0]&0x0F) * 4
	if ipIHL < 20 || len(ipHeader) < ipIHL+8 { // 确保有 UDP 头
		return nil, nil, fmt.Errorf("Insufficient length of IP header")
	}
	// 4. 检查 IPv4 协议类型是否为 UDP (17)
	if ipHeader[9] != 17 {
		return nil, nil, fmt.Errorf("Not UDP protocol")
	}
	// 5. 定位 UDP 头部
	udpHeader := ipHeader[ipIHL:]
	udpDstPort := binary.BigEndian.Uint16(udpHeader[2:4])
	if udpDstPort != 67 && udpDstPort != 68 {
		return nil, nil, fmt.Errorf("It's not a DHCP request")
	}

	// 提取源 IP 地址
	addr := &net.UDPAddr{
		IP:   net.IP(ipHeader[12:16]),                      // IPv4 源地址位于 IP 头 12-15 字节
		Port: int(binary.BigEndian.Uint16(udpHeader[0:2])), // 提取源端口
	}

	payloadStart := 14 + ipIHL + 8 // 以太网头 + IP头 + UDP头
	if len(data) < payloadStart {
		return nil, addr, nil
	}
	return data[payloadStart:], addr, nil
}

func (c *DPDKConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	_, addr, err = parseIPv4DHCPRequest(p)
	if err != nil {
		return 0, nil, err
	}
	return len(p), addr, nil
}

func (c *DPDKConn) Close() error {
	return nil
}

func (c *DPDKConn) LocalAddr() net.Addr {
	return nil
}

func (c *DPDKConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *DPDKConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *DPDKConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *DPDKConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("addr type assertion failed")
	}
	// 1. 分配 mbuf 并将数据包 p 写入
	pkt := mbuf.PktMbufAlloc(c.memPool)
	frame := buildDHCPFrame(p,
		c.macAddr,
		c.DHCPReq.ClientHWAddr,
		c.serverIp, udpAddr.IP,
	)
	err = pkt.PktMbufAppend(frame)
	if err != nil {
		return 0, err
	}
	// 2. 通过 TxBurst 发送
	pkts := []*mbuf.Mbuf{pkt}
	numTx := c.devPort.TxBurst(c.qid, pkts)
	n = int(numTx)
	// 3.处理未发送成功的包
	if numTx < uint16(len(pkts)) {
		for i := numTx; i < uint16(len(pkts)); i++ {
			pkts[i].PktMbufFree()
		}
	}

	return
}

func buildDHCPFrame(
	dhcpData []byte,
	srcMAC, dstMAC net.HardwareAddr, // 以太网源/目标 MAC
	srcIP, dstIP net.IP, // IPv4 源/目标 IP
) []byte {

	// 1. 构造以太网帧头
	ethHeader := make([]byte, 14)
	copy(ethHeader[0:6], dstMAC)                         // 目标 MAC
	copy(ethHeader[6:12], srcMAC)                        // 源 MAC（服务器 MAC）
	binary.BigEndian.PutUint16(ethHeader[12:14], 0x0800) // 以太网类型 (IPv4)

	// 2. 构造 IPv4 头
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45                 // IPv4 + 头长度 20 (5*4)
	ipHeader[1] = 0x00                 // 服务类型 (TOS)
	totalLen := 20 + 8 + len(dhcpData) // IP头 + UDP头 + DHCP数据
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ipHeader[4:6], 0x0000) // 标识符
	ipHeader[6] = 0x40                                // Flags (Don't Fragment)
	ipHeader[7] = 0x00                                // Fragment Offset
	ipHeader[8] = 64                                  // TTL (64)
	ipHeader[9] = 17                                  // 协议 (UDP)
	//binary.BigEndian.PutUint16(ipHeader[10:12], 0x0000) // 校验和（可选，硬件可能自动计算）
	copy(ipHeader[12:16], srcIP.To4()) // 源 IP
	copy(ipHeader[16:20], dstIP.To4()) // 目标 IP

	// 3. 构造 UDP 头
	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], 67) // 源端口 (DHCP Server)
	binary.BigEndian.PutUint16(udpHeader[2:4], 68) // 目标端口 (DHCP Client)
	udpLength := 8 + len(dhcpData)
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(udpLength))
	//binary.BigEndian.PutUint16(udpHeader[6:8], 0x0000) // 校验和（可选，硬件可能自动计算）

	// 4. 合并所有部分
	frame := append(ethHeader, ipHeader...)
	frame = append(frame, udpHeader...)
	frame = append(frame, dhcpData...)

	return frame
}
