// Package wire encodes and decodes kolo-dht datagrams with kolo-codec: Marker ‖ uvarint(type) ‖ uint64(request id) ‖
// body ‖ bytes(zero padding), at most MaxSize bytes, and each value has one encoding.
package wire

import (
	"errors"
	"net/netip"

	kolocodec "github.com/ciranda-dev/kolo-codec"
)

// Marker is the first byte of every datagram; its two top bits are clear, so QUIC never parses it.
const Marker = 0x24

// MaxSize is the largest datagram, the QUIC minimum datagram size, so it is never fragmented.
const MaxSize = 1200

// Field sizes and list limits.
const (
	KeySize     = 32
	SigSize     = 64
	TokenSize   = 32
	PunchIDSize = 8
	ShareSize   = 32
	MACSize     = 32
	MaxNodes    = 20
	MaxRecords  = 16
	MaxAge      = 1<<16 - 1
)

var (
	// ErrInvalid means a datagram or field is malformed, or a value is out of range.
	ErrInvalid = errors.New("kolodht: invalid message")
	// ErrTooLarge means a message does not fit in the requested size or in MaxSize.
	ErrTooLarge = errors.New("kolodht: message too large")
)

// Type is a message type. A reply's type is its request's type plus one.
type Type uint64

// The message types.
const (
	TypePing Type = iota + 1
	TypePingReply
	TypeFindNode
	TypeFindNodeReply
	TypeLookup
	TypeLookupReply
	TypeAnnounce
	TypeAnnounceReply
	TypeConnect
	TypeConnectReply
	TypePunch
	TypePunchReply
	TypeProbe
)

// IsRequest reports whether t is a request type, which has a reply.
func IsRequest(t Type) bool { return t >= TypePing && t <= TypePunch && t%2 == 1 }

// ReplyType returns the type of the reply to request type t.
func ReplyType(t Type) Type { return t + 1 }

// Flags carries a node's ID choice r (bits 0 to 2) and whether it is a server (bit 3).
type Flags uint8

const (
	flagServer = 1 << 3
	maxFlags   = 0x0f
)

// NewFlags returns the flags for r (its low 3 bits) and server.
func NewFlags(r uint8, server bool) Flags {
	f := Flags(r & 7)
	if server {
		f |= flagServer
	}
	return f
}

// R returns the node's ID choice, 0 to 7.
func (f Flags) R() uint8 { return uint8(f & 7) }

// Server reports whether the node is a server.
func (f Flags) Server() bool { return f&flagServer != 0 }

// Status is the outcome carried in a reply.
type Status uint8

// The statuses.
const (
	StatusOK Status = iota
	StatusBadToken
	StatusFull
	StatusNotServer
	StatusNoRecord
	StatusUnreachable
	StatusRefused
	// StatusTryLater means the peer's budget refused a random-mapping punch.
	StatusTryLater
	maxStatus = StatusTryLater
)

// Class is a node's NAT mapping class.
type Class uint8

// The classes: unknown, the same mapping for every destination, or a different one.
const (
	ClassUnknown Class = iota
	ClassConsistent
	ClassRandom
	maxClass = ClassRandom
)

// Node is a server in a node list; its ID is derived from Addr and Flags.R.
type Node struct {
	Flags Flags
	Addr  netip.AddrPort
}

// Record is a signed announcement as returned by LOOKUP; Age is in seconds.
type Record struct {
	Key  [KeySize]byte
	Addr netip.AddrPort
	Age  uint16
	Sig  [SigSize]byte
}

// Message is one of the message types of this package.
type Message interface {
	Type() Type
	encode(e *enc) error
	decode(d *kolocodec.Decoder) error
}

type enc = kolocodec.Encoder

// Ping asks for a PingReply.
type Ping struct{ Flags Flags }

// PingReply tells the requester its observed address and gives it a token.
type PingReply struct {
	Observed netip.AddrPort
	Token    [TokenSize]byte
	Flags    Flags
}

// FindNode asks for the servers closest to Target.
type FindNode struct {
	Flags  Flags
	Target [32]byte
}

// FindNodeReply lists servers close to the target.
type FindNodeReply struct {
	Observed netip.AddrPort
	Token    [TokenSize]byte
	Flags    Flags
	Nodes    []Node
}

// Lookup asks for the servers closest to Topic and the records stored for it.
type Lookup struct {
	Flags Flags
	Topic [32]byte
}

// LookupReply lists servers close to the topic and records of it.
type LookupReply struct {
	Observed netip.AddrPort
	Token    [TokenSize]byte
	Flags    Flags
	Nodes    []Node
	Records  []Record
}

// Announce asks a server to store a signed record of Key at Addr for Topic. Share is the announcer's X25519 key for
// the punch secret of the record.
type Announce struct {
	Flags Flags
	Token [TokenSize]byte
	Topic [32]byte
	Key   [KeySize]byte
	Addr  netip.AddrPort
	Sig   [SigSize]byte
	Share [ShareSize]byte
}

// AnnounceReply says whether the record was stored. Share is the server's X25519 key for the punch secret.
type AnnounceReply struct {
	Observed netip.AddrPort
	Token    [TokenSize]byte
	Status   Status
	Share    [ShareSize]byte
}

// Connect asks a server to relay a punch request to the announcer of Target for Topic. NoRandom says the requester
// will not probe random ports, so a random-mapping announcer answers unreachable.
type Connect struct {
	Flags    Flags
	Token    [TokenSize]byte
	Topic    [32]byte
	Target   [KeySize]byte
	Key      [KeySize]byte
	Class    Class
	NoRandom bool
	PunchID  [PunchIDSize]byte
}

// ConnectReply carries the announcer's answer and, with StatusOK, its signature (see PunchReply).
type ConnectReply struct {
	Observed netip.AddrPort
	Token    [TokenSize]byte
	Status   Status
	Class    Class
	Sig      [SigSize]byte
}

// Punch is a relayed connect request, from the server to the announcer. Counter grows with every PUNCH the server
// sends, and MAC authenticates the rest with the punch secret of the announcer's record.
type Punch struct {
	Flags    Flags
	Topic    [32]byte
	Target   [KeySize]byte
	Key      [KeySize]byte
	Addr     netip.AddrPort
	Class    Class
	NoRandom bool
	PunchID  [PunchIDSize]byte
	Counter  uint64
	MAC      [MACSize]byte
}

// PunchReply is the announcer's answer to a Punch. With StatusOK, Sig is the announcer's signature of the punch, its
// class and its IP; otherwise it is zero.
type PunchReply struct {
	Status Status
	Class  Class
	Sig    [SigSize]byte
}

// Probe opens a NAT toward the peer of a punch and proves the peer's address: Nonce is the sender's, Echo the peer's
// nonce it received (zero if none yet). It has no reply.
type Probe struct {
	PunchID [PunchIDSize]byte
	Nonce   [PunchIDSize]byte
	Echo    [PunchIDSize]byte
}

// Type implements Message.
func (*Ping) Type() Type { return TypePing }

// Type implements Message.
func (*PingReply) Type() Type { return TypePingReply }

// Type implements Message.
func (*FindNode) Type() Type { return TypeFindNode }

// Type implements Message.
func (*FindNodeReply) Type() Type { return TypeFindNodeReply }

// Type implements Message.
func (*Lookup) Type() Type { return TypeLookup }

// Type implements Message.
func (*LookupReply) Type() Type { return TypeLookupReply }

// Type implements Message.
func (*Announce) Type() Type { return TypeAnnounce }

// Type implements Message.
func (*AnnounceReply) Type() Type { return TypeAnnounceReply }

// Type implements Message.
func (*Connect) Type() Type { return TypeConnect }

// Type implements Message.
func (*ConnectReply) Type() Type { return TypeConnectReply }

// Type implements Message.
func (*Punch) Type() Type { return TypePunch }

// Type implements Message.
func (*PunchReply) Type() Type { return TypePunchReply }

// Type implements Message.
func (*Probe) Type() Type { return TypeProbe }

func newMessage(t Type) Message {
	switch t {
	case TypePing:
		return &Ping{}
	case TypePingReply:
		return &PingReply{}
	case TypeFindNode:
		return &FindNode{}
	case TypeFindNodeReply:
		return &FindNodeReply{}
	case TypeLookup:
		return &Lookup{}
	case TypeLookupReply:
		return &LookupReply{}
	case TypeAnnounce:
		return &Announce{}
	case TypeAnnounceReply:
		return &AnnounceReply{}
	case TypeConnect:
		return &Connect{}
	case TypeConnectReply:
		return &ConnectReply{}
	case TypePunch:
		return &Punch{}
	case TypePunchReply:
		return &PunchReply{}
	case TypeProbe:
		return &Probe{}
	}
	return nil
}

// Encode returns the datagram for m with request id. With size 0 it is as short as possible;
// otherwise zero padding makes it size or size-1 bytes long (ErrTooLarge if m needs more, or size is over MaxSize).
func Encode(id uint64, m Message, size int) ([]byte, error) {
	if size > MaxSize {
		return nil, ErrTooLarge
	}
	var e enc
	e.PutFixed([]byte{Marker})
	e.PutUvarint(uint64(m.Type()))
	e.PutUint64(id)
	if err := m.encode(&e); err != nil {
		return nil, err
	}
	b := e.Bytes()
	pad := 0
	if size > 0 {
		pad = padding(size - len(b))
		if pad < 0 {
			return nil, ErrTooLarge
		}
	}
	e.PutBytes(make([]byte, pad))
	b = e.Bytes()
	if len(b) > MaxSize {
		return nil, ErrTooLarge
	}
	return b, nil
}

// padding returns the largest p whose uvarint length plus p is at most room, or -1.
func padding(room int) int {
	switch {
	case room < 1:
		return -1
	case room <= 128:
		return room - 1
	}
	return room - 2
}

// Fit encodes m in at most size bytes, dropping trailing records and then trailing nodes of a list reply until it fits.
// m itself is not modified.
func Fit(id uint64, m Message, size int) ([]byte, error) {
	switch v := m.(type) {
	case *FindNodeReply:
		c := *v
		for {
			b, err := Encode(id, &c, 0)
			if !errors.Is(err, ErrTooLarge) && (err != nil || len(b) <= size) {
				return b, err
			}
			if len(c.Nodes) == 0 {
				return nil, ErrTooLarge
			}
			c.Nodes = c.Nodes[:len(c.Nodes)-1]
		}
	case *LookupReply:
		c := *v
		for {
			b, err := Encode(id, &c, 0)
			if !errors.Is(err, ErrTooLarge) && (err != nil || len(b) <= size) {
				return b, err
			}
			switch {
			case len(c.Records) > 0:
				c.Records = c.Records[:len(c.Records)-1]
			case len(c.Nodes) > 0:
				c.Nodes = c.Nodes[:len(c.Nodes)-1]
			default:
				return nil, ErrTooLarge
			}
		}
	}
	b, err := Encode(id, m, 0)
	if err == nil && len(b) > size {
		return nil, ErrTooLarge
	}
	return b, err
}

// Decode parses a datagram and returns its request id and message.
func Decode(b []byte) (uint64, Message, error) {
	if len(b) == 0 || len(b) > MaxSize || b[0] != Marker {
		return 0, nil, ErrInvalid
	}
	d := kolocodec.NewDecoder(b[1:])
	t, err := d.Uvarint()
	if err != nil {
		return 0, nil, ErrInvalid
	}
	m := newMessage(Type(t))
	if m == nil {
		return 0, nil, ErrInvalid
	}
	id, err := d.Uint64()
	if err != nil {
		return 0, nil, ErrInvalid
	}
	if err := m.decode(d); err != nil {
		return 0, nil, ErrInvalid
	}
	pad, err := d.Bytes(MaxSize)
	if err != nil || d.Done() != nil {
		return 0, nil, ErrInvalid
	}
	for _, c := range pad {
		if c != 0 {
			return 0, nil, ErrInvalid
		}
	}
	return id, m, nil
}

// Peek returns the type and request id of a datagram without decoding its body.
func Peek(b []byte) (Type, uint64, bool) {
	if len(b) == 0 || len(b) > MaxSize || b[0] != Marker {
		return 0, 0, false
	}
	d := kolocodec.NewDecoder(b[1:])
	t, err := d.Uvarint()
	if err != nil {
		return 0, 0, false
	}
	id, err := d.Uint64()
	if err != nil {
		return 0, 0, false
	}
	return Type(t), id, true
}

// PutAddr writes ap as IPv4 address (4 bytes) ‖ uvarint(port); any IPv6 address, IPv4-mapped included, is ErrInvalid
// (v0.1.x is IPv4 only).
func PutAddr(e *kolocodec.Encoder, ap netip.AddrPort) error {
	ip := ap.Addr()
	if !ip.Is4() || ap.Port() == 0 {
		return ErrInvalid
	}
	e.PutFixed(ip.AsSlice())
	e.PutUvarint(uint64(ap.Port()))
	return nil
}

// Addr reads an address written by PutAddr.
func Addr(d *kolocodec.Decoder) (netip.AddrPort, error) {
	b, err := d.Fixed(4)
	if err != nil {
		return netip.AddrPort{}, ErrInvalid
	}
	port, err := d.UvarintMax(1<<16 - 1)
	if err != nil || port == 0 {
		return netip.AddrPort{}, ErrInvalid
	}
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte(b)), uint16(port)), nil
}

func putFlags(e *enc, f Flags) error {
	if f > maxFlags {
		return ErrInvalid
	}
	e.PutUvarint(uint64(f))
	return nil
}

func getFlags(d *kolocodec.Decoder) (Flags, error) {
	v, err := d.UvarintMax(maxFlags)
	return Flags(v), err
}

func putStatus(e *enc, s Status) error {
	if s > maxStatus {
		return ErrInvalid
	}
	e.PutUvarint(uint64(s))
	return nil
}

func getStatus(d *kolocodec.Decoder) (Status, error) {
	v, err := d.UvarintMax(uint64(maxStatus))
	return Status(v), err
}

func putClass(e *enc, c Class) error {
	if c > maxClass {
		return ErrInvalid
	}
	e.PutUvarint(uint64(c))
	return nil
}

func getClass(d *kolocodec.Decoder) (Class, error) {
	v, err := d.UvarintMax(uint64(maxClass))
	return Class(v), err
}

func putBool(e *enc, b bool) {
	v := uint64(0)
	if b {
		v = 1
	}
	e.PutUvarint(v)
}

func getBool(d *kolocodec.Decoder) (bool, error) {
	v, err := d.UvarintMax(1)
	return v == 1, err
}

func fixed(d *kolocodec.Decoder, dst []byte) error {
	b, err := d.Fixed(len(dst))
	if err != nil {
		return err
	}
	copy(dst, b)
	return nil
}

func putNodes(e *enc, nodes []Node) error {
	if len(nodes) > MaxNodes {
		return ErrTooLarge
	}
	e.PutUvarint(uint64(len(nodes)))
	for _, n := range nodes {
		if err := putFlags(e, n.Flags); err != nil {
			return err
		}
		if err := PutAddr(e, n.Addr); err != nil {
			return err
		}
	}
	return nil
}

func getNodes(d *kolocodec.Decoder) ([]Node, error) {
	n, err := d.UvarintMax(MaxNodes)
	if err != nil {
		return nil, err
	}
	var nodes []Node
	for range n {
		var node Node
		if node.Flags, err = getFlags(d); err != nil {
			return nil, err
		}
		if node.Addr, err = Addr(d); err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

func putRecords(e *enc, recs []Record) error {
	if len(recs) > MaxRecords {
		return ErrTooLarge
	}
	e.PutUvarint(uint64(len(recs)))
	for _, r := range recs {
		e.PutFixed(r.Key[:])
		if err := PutAddr(e, r.Addr); err != nil {
			return err
		}
		e.PutUvarint(uint64(r.Age))
		e.PutFixed(r.Sig[:])
	}
	return nil
}

func getRecords(d *kolocodec.Decoder) ([]Record, error) {
	n, err := d.UvarintMax(MaxRecords)
	if err != nil {
		return nil, err
	}
	var recs []Record
	for range n {
		var r Record
		if err := fixed(d, r.Key[:]); err != nil {
			return nil, err
		}
		if r.Addr, err = Addr(d); err != nil {
			return nil, err
		}
		age, err := d.UvarintMax(MaxAge)
		if err != nil {
			return nil, err
		}
		r.Age = uint16(age)
		if err := fixed(d, r.Sig[:]); err != nil {
			return nil, err
		}
		recs = append(recs, r)
	}
	return recs, nil
}

func putReplyHead(e *enc, observed netip.AddrPort, tok [TokenSize]byte) error {
	if err := PutAddr(e, observed); err != nil {
		return err
	}
	e.PutFixed(tok[:])
	return nil
}

func getReplyHead(d *kolocodec.Decoder, observed *netip.AddrPort, tok *[TokenSize]byte) error {
	var err error
	if *observed, err = Addr(d); err != nil {
		return err
	}
	return fixed(d, tok[:])
}

func (m *Ping) encode(e *enc) error { return putFlags(e, m.Flags) }

func (m *Ping) decode(d *kolocodec.Decoder) (err error) {
	m.Flags, err = getFlags(d)
	return err
}

func (m *PingReply) encode(e *enc) error {
	if err := putReplyHead(e, m.Observed, m.Token); err != nil {
		return err
	}
	return putFlags(e, m.Flags)
}

func (m *PingReply) decode(d *kolocodec.Decoder) (err error) {
	if err = getReplyHead(d, &m.Observed, &m.Token); err != nil {
		return err
	}
	m.Flags, err = getFlags(d)
	return err
}

func (m *FindNode) encode(e *enc) error {
	if err := putFlags(e, m.Flags); err != nil {
		return err
	}
	e.PutFixed(m.Target[:])
	return nil
}

func (m *FindNode) decode(d *kolocodec.Decoder) (err error) {
	if m.Flags, err = getFlags(d); err != nil {
		return err
	}
	return fixed(d, m.Target[:])
}

func (m *FindNodeReply) encode(e *enc) error {
	if err := putReplyHead(e, m.Observed, m.Token); err != nil {
		return err
	}
	if err := putFlags(e, m.Flags); err != nil {
		return err
	}
	return putNodes(e, m.Nodes)
}

func (m *FindNodeReply) decode(d *kolocodec.Decoder) (err error) {
	if err = getReplyHead(d, &m.Observed, &m.Token); err != nil {
		return err
	}
	if m.Flags, err = getFlags(d); err != nil {
		return err
	}
	m.Nodes, err = getNodes(d)
	return err
}

func (m *Lookup) encode(e *enc) error {
	if err := putFlags(e, m.Flags); err != nil {
		return err
	}
	e.PutFixed(m.Topic[:])
	return nil
}

func (m *Lookup) decode(d *kolocodec.Decoder) (err error) {
	if m.Flags, err = getFlags(d); err != nil {
		return err
	}
	return fixed(d, m.Topic[:])
}

func (m *LookupReply) encode(e *enc) error {
	if err := putReplyHead(e, m.Observed, m.Token); err != nil {
		return err
	}
	if err := putFlags(e, m.Flags); err != nil {
		return err
	}
	if err := putNodes(e, m.Nodes); err != nil {
		return err
	}
	return putRecords(e, m.Records)
}

func (m *LookupReply) decode(d *kolocodec.Decoder) (err error) {
	if err = getReplyHead(d, &m.Observed, &m.Token); err != nil {
		return err
	}
	if m.Flags, err = getFlags(d); err != nil {
		return err
	}
	if m.Nodes, err = getNodes(d); err != nil {
		return err
	}
	m.Records, err = getRecords(d)
	return err
}

func (m *Announce) encode(e *enc) error {
	if err := putFlags(e, m.Flags); err != nil {
		return err
	}
	e.PutFixed(m.Token[:])
	e.PutFixed(m.Topic[:])
	e.PutFixed(m.Key[:])
	if err := PutAddr(e, m.Addr); err != nil {
		return err
	}
	e.PutFixed(m.Sig[:])
	e.PutFixed(m.Share[:])
	return nil
}

func (m *Announce) decode(d *kolocodec.Decoder) (err error) {
	if m.Flags, err = getFlags(d); err != nil {
		return err
	}
	for _, f := range [][]byte{m.Token[:], m.Topic[:], m.Key[:]} {
		if err := fixed(d, f); err != nil {
			return err
		}
	}
	if m.Addr, err = Addr(d); err != nil {
		return err
	}
	if err := fixed(d, m.Sig[:]); err != nil {
		return err
	}
	return fixed(d, m.Share[:])
}

func (m *AnnounceReply) encode(e *enc) error {
	if err := putReplyHead(e, m.Observed, m.Token); err != nil {
		return err
	}
	if err := putStatus(e, m.Status); err != nil {
		return err
	}
	e.PutFixed(m.Share[:])
	return nil
}

func (m *AnnounceReply) decode(d *kolocodec.Decoder) (err error) {
	if err = getReplyHead(d, &m.Observed, &m.Token); err != nil {
		return err
	}
	if m.Status, err = getStatus(d); err != nil {
		return err
	}
	return fixed(d, m.Share[:])
}

func (m *Connect) encode(e *enc) error {
	if err := putFlags(e, m.Flags); err != nil {
		return err
	}
	e.PutFixed(m.Token[:])
	e.PutFixed(m.Topic[:])
	e.PutFixed(m.Target[:])
	e.PutFixed(m.Key[:])
	if err := putClass(e, m.Class); err != nil {
		return err
	}
	putBool(e, m.NoRandom)
	e.PutFixed(m.PunchID[:])
	return nil
}

func (m *Connect) decode(d *kolocodec.Decoder) (err error) {
	if m.Flags, err = getFlags(d); err != nil {
		return err
	}
	for _, f := range [][]byte{m.Token[:], m.Topic[:], m.Target[:], m.Key[:]} {
		if err := fixed(d, f); err != nil {
			return err
		}
	}
	if m.Class, err = getClass(d); err != nil {
		return err
	}
	if m.NoRandom, err = getBool(d); err != nil {
		return err
	}
	return fixed(d, m.PunchID[:])
}

func (m *ConnectReply) encode(e *enc) error {
	if err := putReplyHead(e, m.Observed, m.Token); err != nil {
		return err
	}
	if err := putStatus(e, m.Status); err != nil {
		return err
	}
	if err := putClass(e, m.Class); err != nil {
		return err
	}
	e.PutFixed(m.Sig[:])
	return nil
}

func (m *ConnectReply) decode(d *kolocodec.Decoder) (err error) {
	if err = getReplyHead(d, &m.Observed, &m.Token); err != nil {
		return err
	}
	if m.Status, err = getStatus(d); err != nil {
		return err
	}
	if m.Class, err = getClass(d); err != nil {
		return err
	}
	return fixed(d, m.Sig[:])
}

func (m *Punch) encode(e *enc) error {
	if err := putFlags(e, m.Flags); err != nil {
		return err
	}
	e.PutFixed(m.Topic[:])
	e.PutFixed(m.Target[:])
	e.PutFixed(m.Key[:])
	if err := PutAddr(e, m.Addr); err != nil {
		return err
	}
	if err := putClass(e, m.Class); err != nil {
		return err
	}
	putBool(e, m.NoRandom)
	e.PutFixed(m.PunchID[:])
	e.PutUint64(m.Counter)
	e.PutFixed(m.MAC[:])
	return nil
}

func (m *Punch) decode(d *kolocodec.Decoder) (err error) {
	if m.Flags, err = getFlags(d); err != nil {
		return err
	}
	for _, f := range [][]byte{m.Topic[:], m.Target[:], m.Key[:]} {
		if err := fixed(d, f); err != nil {
			return err
		}
	}
	if m.Addr, err = Addr(d); err != nil {
		return err
	}
	if m.Class, err = getClass(d); err != nil {
		return err
	}
	if m.NoRandom, err = getBool(d); err != nil {
		return err
	}
	if err := fixed(d, m.PunchID[:]); err != nil {
		return err
	}
	if m.Counter, err = d.Uint64(); err != nil {
		return err
	}
	return fixed(d, m.MAC[:])
}

func (m *PunchReply) encode(e *enc) error {
	if err := putStatus(e, m.Status); err != nil {
		return err
	}
	if err := putClass(e, m.Class); err != nil {
		return err
	}
	e.PutFixed(m.Sig[:])
	return nil
}

func (m *PunchReply) decode(d *kolocodec.Decoder) (err error) {
	if m.Status, err = getStatus(d); err != nil {
		return err
	}
	if m.Class, err = getClass(d); err != nil {
		return err
	}
	return fixed(d, m.Sig[:])
}

func (m *Probe) encode(e *enc) error {
	e.PutFixed(m.PunchID[:])
	e.PutFixed(m.Nonce[:])
	e.PutFixed(m.Echo[:])
	return nil
}

func (m *Probe) decode(d *kolocodec.Decoder) error {
	for _, f := range [][]byte{m.PunchID[:], m.Nonce[:], m.Echo[:]} {
		if err := fixed(d, f); err != nil {
			return err
		}
	}
	return nil
}
