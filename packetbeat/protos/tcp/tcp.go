package tcp

import (
	"fmt"
	"time"
	//linked list library to buffer out-of-order tcp packets
	"container/list"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"

	"github.com/elastic/beats/packetbeat/protos"

	"github.com/tsg/gopacket/layers"
)

const TCP_MAX_DATA_IN_STREAM = 10 * (1 << 20)

const (
	TcpDirectionReverse  = 0
	TcpDirectionOriginal = 1
)

type Tcp struct {
	id        uint32
	streams   *common.Cache
	portMap   map[uint16]protos.Protocol
	protocols protos.Protocols
}

type Processor interface {
	Process(tcphdr *layers.TCP, pkt *protos.Packet)
}

var (
	debugf  = logp.MakeDebug("tcp")
	isDebug = false
)

func (tcp *Tcp) getId() uint32 {
	tcp.id += 1
	return tcp.id
}

func (tcp *Tcp) decideProtocol(tuple *common.IpPortTuple) protos.Protocol {
	protocol, exists := tcp.portMap[tuple.Src_port]
	if exists {
		return protocol
	}

	protocol, exists = tcp.portMap[tuple.Dst_port]
	if exists {
		return protocol
	}

	return protos.UnknownProtocol
}

func (tcp *Tcp) findStream(k common.HashableIpPortTuple) *TcpConnection {
	v := tcp.streams.Get(k)
	if v != nil {
		return v.(*TcpConnection)
	}
	return nil
}

//payload buffer (value in the list of unordered list)
type payload struct {
	tcphdr layers.TCP
	pkt    protos.Packet
	seq    uint32
}

type TcpConnection struct {
	id       uint32
	tuple    *common.IpPortTuple
	protocol protos.Protocol
	tcptuple common.TcpTuple
	tcp      *Tcp

	lastSeq [2]uint32
	//temporary list for unordered packets
	alist [2]list.List
	//number of fins recieved to deem a connection valid to close
	fincnt uint32
	// protocols private data
	data protos.ProtocolData
}

type TcpStream struct {
	conn *TcpConnection
	dir  uint8
}

func (conn *TcpConnection) String() string {
	return fmt.Sprintf("TcpStream id[%d] tuple[%s] protocol[%s] lastSeq[%d %d]",
		conn.id, conn.tuple, conn.protocol, conn.lastSeq[0], conn.lastSeq[1])
}

func (stream *TcpStream) addPacket(pkt *protos.Packet, tcphdr *layers.TCP) {
	conn := stream.conn
	mod := conn.tcp.protocols.GetTcp(conn.protocol)
	if mod == nil {
		if isDebug {
			protocol := conn.protocol
			debugf("Ignoring protocol for which we have no module loaded: %s",
				protocol)
		}
		return
	}

	if len(pkt.Payload) > 0 {
		conn.data = mod.Parse(pkt, &conn.tcptuple, stream.dir, conn.data)
	}
	//atleast two fins should be seen to close connection(one in each direction)
	if tcphdr.FIN && conn.fincnt >= 2 {
		conn.data = mod.ReceivedFin(&conn.tcptuple, stream.dir, conn.data)
	}
}

func (stream *TcpStream) gapInStream(nbytes int) (drop bool) {
	conn := stream.conn
	mod := conn.tcp.protocols.GetTcp(conn.protocol)
	conn.data, drop = mod.GapInStream(&conn.tcptuple, stream.dir, nbytes, conn.data)
	return drop
}

func (tcp *Tcp) Process(tcphdr *layers.TCP, pkt *protos.Packet) {
	// This Recover should catch all exceptions in
	// protocol modules.
	defer logp.Recover("Process tcp exception")

	stream, created := tcp.getStream(pkt)
	if stream.conn == nil {
		return
	}
	conn := stream.conn

	tcp_start_seq := tcphdr.Seq
	tcp_seq := tcp_start_seq + uint32(len(pkt.Payload))
	lastSeq := conn.lastSeq[stream.dir]
	if isDebug {
		debugf("pkt.start_seq=%v pkt.last_seq=%v stream.last_seq=%v (len=%d)",
			tcp_start_seq, tcp_seq, lastSeq, len(pkt.Payload))
	}
	if tcphdr.FIN {
		//count number of fins received(should we move this to addPacket, because retransmissions can cause issue)
		conn.fincnt += 1
	}
	//if FIN is reordered, it also has o go to the queue
	if (len(pkt.Payload) > 0 || tcphdr.FIN) && lastSeq != 0 {
		if tcpSeqBeforeEq(tcp_seq, lastSeq) {
			if isDebug {
				debugf("Ignoring retransmitted segment. pkt.seq=%v len=%v stream.seq=%v",
					tcphdr.Seq, len(pkt.Payload), lastSeq)
			}
			return
		}

		if tcpSeqBefore(lastSeq, tcp_start_seq) {
			if !created {
				//add out of order packets to buffer alist
				buffer := &payload{
					tcphdr: *tcphdr,
					pkt:    *pkt,
					seq:    tcp_start_seq,
				}
				insertUnordered(&conn.alist[stream.dir], buffer)
				return
			}
		}
	}

	if len(pkt.Payload) > 0 || tcphdr.FIN {
		conn.lastSeq[stream.dir] = tcp_seq
		stream.addPacket(pkt, tcphdr)
	}
	//iterate through list till we hit upon next gap
	for e := conn.alist[stream.dir].Front(); e != nil; {
		nexte := e.Next()
		unOrderedPayload := e.Value.(*payload)
		if unOrderedPayload.seq < conn.lastSeq[stream.dir] {
			conn.alist[stream.dir].Remove(e)
			//Dropping old pkts
		} else if unOrderedPayload.seq == conn.lastSeq[stream.dir] {
			tcphdr1 := &unOrderedPayload.tcphdr
			pkt1 := &unOrderedPayload.pkt
			conn.alist[stream.dir].Remove(e)
			tcp_start_seq = tcphdr1.Seq
			tcp_seq = tcp_start_seq + uint32(len(pkt1.Payload))
			conn.lastSeq[stream.dir] = tcp_seq
			stream.addPacket(pkt1, tcphdr1)
		} else {
			break
		}
		e = nexte
	}
}

//insert unordered packets in sorted linked list so that it can behave as a queue
func insertUnordered(l *list.List, buffer *payload) {
	if l.Len() == 0 {
		l.PushFront(buffer)
		return
	}
	for e := l.Front(); e != nil; e = e.Next() {
		buf := e.Value.(*payload)
		if buf.seq > buffer.seq {
			l.InsertBefore(buffer, e)
			return
		}
	}
	l.PushBack(buffer)
	return
}

func (tcp *Tcp) getStream(pkt *protos.Packet) (stream TcpStream, created bool) {
	if conn := tcp.findStream(pkt.Tuple.Hashable()); conn != nil {
		return TcpStream{conn: conn, dir: TcpDirectionOriginal}, false
	}

	if conn := tcp.findStream(pkt.Tuple.RevHashable()); conn != nil {
		return TcpStream{conn: conn, dir: TcpDirectionReverse}, false
	}

	protocol := tcp.decideProtocol(&pkt.Tuple)
	if protocol == protos.UnknownProtocol {
		// don't follow
		return TcpStream{}, false
	}

	var timeout time.Duration
	mod := tcp.protocols.GetTcp(protocol)
	if mod != nil {
		timeout = mod.ConnectionTimeout()
	}

	if isDebug {
		t := pkt.Tuple
		debugf("Connection src[%s:%d] dst[%s:%d] doesn't exist, creating new",
			t.Src_ip.String(), t.Src_port,
			t.Dst_ip.String(), t.Dst_port)
	}

	conn := &TcpConnection{
		id:       tcp.getId(),
		tuple:    &pkt.Tuple,
		protocol: protocol,
		tcp:      tcp}
	conn.tcptuple = common.TcpTupleFromIpPort(conn.tuple, conn.id)
	tcp.streams.PutWithTimeout(pkt.Tuple.Hashable(), conn, timeout)
	return TcpStream{conn: conn, dir: TcpDirectionOriginal}, true
}

func tcpSeqBefore(seq1 uint32, seq2 uint32) bool {
	return int32(seq1-seq2) < 0
}

func tcpSeqBeforeEq(seq1 uint32, seq2 uint32) bool {
	return int32(seq1-seq2) <= 0
}

func buildPortsMap(plugins map[protos.Protocol]protos.TcpProtocolPlugin) (map[uint16]protos.Protocol, error) {
	var res = map[uint16]protos.Protocol{}

	for proto, protoPlugin := range plugins {
		for _, port := range protoPlugin.GetPorts() {
			old_proto, exists := res[uint16(port)]
			if exists {
				if old_proto == proto {
					continue
				}
				return nil, fmt.Errorf("Duplicate port (%d) exists in %s and %s protocols",
					port, old_proto, proto)
			}
			res[uint16(port)] = proto
		}
	}

	return res, nil
}

// Creates and returns a new Tcp.
func NewTcp(p protos.Protocols) (*Tcp, error) {
	isDebug = logp.IsDebug("tcp")

	portMap, err := buildPortsMap(p.GetAllTcp())
	if err != nil {
		return nil, err
	}

	tcp := &Tcp{
		protocols: p,
		portMap:   portMap,
		streams: common.NewCache(
			protos.DefaultTransactionExpiration,
			protos.DefaultTransactionHashSize),
	}
	tcp.streams.StartJanitor(protos.DefaultTransactionExpiration)
	if isDebug {
		debugf("tcp", "Port map: %v", portMap)
	}

	return tcp, nil
}
