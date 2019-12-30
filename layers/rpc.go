package layers

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log"
	"strconv"

	"github.com/google/gopacket"
)

// FizzleUUID fizzles 16 Byte UUID from big endian to little endian or vice versa
func FizzleUUID(uuidLE []byte) ([]byte, error) {
	if len(uuidLE) != 16 {
		return nil, errors.New("wrong size for uuid")
	}

	uuidBE := make([]byte, 16)
	uuidBE[0] = uuidLE[3]
	uuidBE[1] = uuidLE[2]
	uuidBE[2] = uuidLE[1]
	uuidBE[3] = uuidLE[0]

	uuidBE[4] = uuidLE[5]
	uuidBE[5] = uuidLE[4]

	uuidBE[6] = uuidLE[7]
	uuidBE[7] = uuidLE[6]

	copy(uuidBE[8:], uuidLE[8:])

	return uuidBE, nil
}

func RandomUUID() []byte {
	res := make([]byte, 16)
	rand.Read(res)
	return res
}

type RPCPacketType byte

const (
	RPCPacketTypeRequest          RPCPacketType = 0
	RPCPacketTypePing             RPCPacketType = 1
	RPCPacketTypeResponse         RPCPacketType = 2
	RPCPacketTypeFault            RPCPacketType = 3
	RPCPacketTypeWorking          RPCPacketType = 4
	RPCPacketTypeNoCall           RPCPacketType = 5
	RPCPacketTypeReject           RPCPacketType = 6
	RPCPacketTypeAck              RPCPacketType = 7
	RPCPacketTypeClCancel         RPCPacketType = 8
	RPCPacketTypeFack             RPCPacketType = 9
	RPCPacketTypeCancelAck        RPCPacketType = 10
	RPCPacketTypeBind             RPCPacketType = 11
	RPCPacketTypeBindAck          RPCPacketType = 12
	RPCPacketTypeBindNak          RPCPacketType = 13
	RPCPacketTypeAlterContext     RPCPacketType = 14
	RPCPacketTypeAlterContextResp RPCPacketType = 15
	RPCPacketTypeShutdown         RPCPacketType = 17
	RPCPacketTypeCoCancel         RPCPacketType = 18
	RPCPacketTypeOrphaned         RPCPacketType = 19
)

type RPCOpNumType uint16

const (
	RPCPNIOOpNumConnect      RPCOpNumType = 0
	RPCPNIOOpNumRelease      RPCOpNumType = 1
	RPCPNIOOpNumRead         RPCOpNumType = 2
	RPCPNIOOpNumWrite        RPCOpNumType = 3
	RPCPNIOOpNumControl      RPCOpNumType = 4
	RPCPNIOOpNumReadImplicit RPCOpNumType = 5

	RPCEPMapOpNumLookupReq        RPCOpNumType = 2
	RPCEPMapOpNumLookupHandleFree RPCOpNumType = 4
)

type IntegerRepresentationType uint8

const (
	IntegerRepresentationBigEndian    IntegerRepresentationType = 0
	IntegerRepresentationLittleEndian IntegerRepresentationType = 1
)

type CharacterRepresentationType uint8

const (
	CharacterRepresentationASCII  CharacterRepresentationType = 0
	CharacterRepresentationEBCDIC CharacterRepresentationType = 1
)

type FloatingPointRepresentationType uint8

const (
	FloatingPointRepresentationIEEE FloatingPointRepresentationType = 0
	FloatingPointRepresentationVAX  FloatingPointRepresentationType = 1
	FloatingPointRepresentationCRAY FloatingPointRepresentationType = 2
	FloatingPointRepresentationIBM  FloatingPointRepresentationType = 3
)

type RPCFormats struct {
	IntegerRepresentation       IntegerRepresentationType
	CharacterRepresentation     CharacterRepresentationType
	FloatingPointRepresentation FloatingPointRepresentationType
}

func getEncoding(data []byte) (RPCFormats, error) {
	var format RPCFormats

	if len(data) < 3 {
		return format, errors.New("encodings data too short. Need 3 Bytes")
	}

	format.IntegerRepresentation = IntegerRepresentationType(data[0] >> 4)
	format.CharacterRepresentation = CharacterRepresentationType(data[0] & 0x0f)
	format.FloatingPointRepresentation = FloatingPointRepresentationType(data[1])

	return format, nil
}

func (e RPCFormats) ToBytes(data []byte) {
	data[0] = uint8(e.CharacterRepresentation) | (uint8(e.IntegerRepresentation) << 4)
	data[1] = uint8(e.FloatingPointRepresentation)
}

// LLDPCapabilities Types
const (
	RPCFlags1LastFragment uint8 = 1 << 1
	RPCFlags1Fragment     uint8 = 1 << 2
	RPCFlags1NoFack       uint8 = 1 << 3
	RPCFlags1Maybe        uint8 = 1 << 4
	RPCFlags1Idempotent   uint8 = 1 << 5
	RPCFlags1Broadcast    uint8 = 1 << 6
)

type RPCFlags1 struct {
	LastFragment bool
	Fragment     bool
	NoFack       bool
	Maybe        bool
	Idempotent   bool
	Broadcast    bool
}

func getFlags1(d uint8) (f RPCFlags1) {
	f.LastFragment = (d&RPCFlags1LastFragment > 0)
	f.Fragment = (d&RPCFlags1Fragment > 0)
	f.NoFack = (d&RPCFlags1NoFack > 0)
	f.Maybe = (d&RPCFlags1Maybe > 0)
	f.Idempotent = (d&RPCFlags1Idempotent > 0)
	f.Broadcast = (d&RPCFlags1Broadcast > 0)
	return
}

func (f RPCFlags1) ToUint8() uint8 {
	var r uint8
	if f.LastFragment {
		r = r | RPCFlags1LastFragment
	}
	if f.Fragment {
		r = r | RPCFlags1Fragment
	}
	if f.NoFack {
		r = r | RPCFlags1NoFack
	}
	if f.Maybe {
		r = r | RPCFlags1Maybe
	}
	if f.Idempotent {
		r = r | RPCFlags1Idempotent
	}
	if f.Broadcast {
		r = r | RPCFlags1Broadcast
	}
	return r
}

type RPC struct {
	BaseLayer
	Version          uint8
	PacketType       RPCPacketType
	Flags1           RPCFlags1
	Flags2           uint8
	Encoding         RPCFormats
	SerialHigh       uint8
	ObjectID         []byte // 16 Byte
	InterfaceID      []byte // 16 Byte
	ActivityID       []byte // 16 Byte
	ServerBootTime   uint32
	InterfaceVersion uint32
	SequenceNum      uint32
	OpNum            RPCOpNumType
	InterfaceHint    uint16
	ActivityHint     uint16
	BodyLen          uint16
	FragmentNo       uint16
	AuthProto        uint8
	SerialLow        uint8
}

func (r RPC) LayerType() gopacket.LayerType { return LayerTypeRPC }

func NewRPCResFromReq(req *RPC) RPC {
	res := RPC{
		Version:          0x04,
		PacketType:       RPCPacketTypeResponse,
		Flags1:           RPCFlags1{Idempotent: true},
		Encoding:         RPCFormats{IntegerRepresentation: IntegerRepresentationBigEndian},
		SerialHigh:       0x00,
		ObjectID:         make([]byte, 16),
		InterfaceID:      make([]byte, 16),
		ActivityID:       make([]byte, 16),
		InterfaceVersion: uint32(1),
		SequenceNum:      req.SequenceNum,
		OpNum:            req.OpNum,
		InterfaceHint:    0xffff,
		ActivityHint:     0xffff,
		FragmentNo:       uint16(0),
		AuthProto:        uint8(0),
		SerialLow:        uint8(0),
	}
	copy(res.ObjectID, req.ObjectID)
	copy(res.InterfaceID, req.InterfaceID)
	copy(res.ActivityID, req.ActivityID)

	return res
}

func (r *RPC) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 80 {
		return errors.New("Malformed RPC packet. Too short")
	}

	r.Version = uint8(data[0])
	r.PacketType = RPCPacketType(data[1])
	r.Flags1 = getFlags1(data[2])
	r.Flags2 = uint8(data[3])
	r.Encoding, _ = getEncoding(data[4:7]) // after one byte of pad
	r.SerialHigh = uint8(data[7])
	if r.Encoding.IntegerRepresentation == IntegerRepresentationLittleEndian {
		// log.Println("\tLittle-Endian Encoding")
		r.ObjectID, _ = FizzleUUID(data[8:24])
		r.InterfaceID, _ = FizzleUUID(data[24:40])
		r.ActivityID, _ = FizzleUUID(data[40:56])
		r.ServerBootTime = binary.LittleEndian.Uint32(data[56:60])
		r.InterfaceVersion = binary.LittleEndian.Uint32(data[60:64])
		r.SequenceNum = binary.LittleEndian.Uint32(data[64:68])
		r.OpNum = RPCOpNumType(binary.LittleEndian.Uint16(data[68:70]))
		r.InterfaceHint = binary.LittleEndian.Uint16(data[70:72])
		r.ActivityHint = binary.LittleEndian.Uint16(data[72:74])
		r.BodyLen = binary.LittleEndian.Uint16(data[74:76])
		r.FragmentNo = binary.LittleEndian.Uint16(data[76:78])
	} else {
		// log.Println("\tBig-Endian Encoding")
		r.ObjectID = make([]byte, 16)
		copy(r.ObjectID, data[8:])
		r.InterfaceID = make([]byte, 16)
		copy(r.InterfaceID, data[24:])
		r.ActivityID = make([]byte, 16)
		copy(r.ActivityID, data[40:])
		r.ServerBootTime = binary.BigEndian.Uint32(data[56:60])
		r.InterfaceVersion = binary.BigEndian.Uint32(data[60:64])
		r.SequenceNum = binary.BigEndian.Uint32(data[64:68])
		r.OpNum = RPCOpNumType(binary.BigEndian.Uint16(data[68:70]))
		r.InterfaceHint = binary.BigEndian.Uint16(data[70:72])
		r.ActivityHint = binary.BigEndian.Uint16(data[72:74])
		r.BodyLen = binary.BigEndian.Uint16(data[74:76])
		r.FragmentNo = binary.BigEndian.Uint16(data[76:78])
	}
	r.AuthProto = uint8(data[78])
	r.SerialLow = uint8(data[79])

	r.Contents = data[:80]
	r.Payload = data[80:]

	return nil
}

func (r *RPC) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if opts.FixLengths {
		r.BodyLen = uint16(len(b.Bytes()))
	}

	bytes, err := b.PrependBytes(80)
	if err != nil {
		return err
	}

	bytes[0] = r.Version
	bytes[1] = byte(r.PacketType)
	bytes[2] = r.Flags1.ToUint8()
	bytes[3] = r.Flags2
	r.Encoding.ToBytes(bytes[4:])
	bytes[6] = 0
	bytes[7] = r.SerialHigh
	if r.Encoding.IntegerRepresentation == IntegerRepresentationBigEndian {
		copy(bytes[8:], r.ObjectID)
		copy(bytes[24:], r.InterfaceID)
		copy(bytes[40:], r.ActivityID)
		binary.BigEndian.PutUint32(bytes[56:60], uint32(r.ServerBootTime))
		binary.BigEndian.PutUint32(bytes[60:64], uint32(r.InterfaceVersion))
		binary.BigEndian.PutUint32(bytes[64:68], uint32(r.SequenceNum))
		binary.BigEndian.PutUint16(bytes[68:70], uint16(r.OpNum))
		binary.BigEndian.PutUint16(bytes[70:72], uint16(r.InterfaceHint))
		binary.BigEndian.PutUint16(bytes[72:74], uint16(r.ActivityHint))
		binary.BigEndian.PutUint16(bytes[74:76], uint16(r.BodyLen))
		binary.BigEndian.PutUint16(bytes[76:78], uint16(r.FragmentNo))
	} else {
		uuidLE, _ := FizzleUUID(r.ObjectID)
		copy(bytes[8:], uuidLE)
		uuidLE, _ = FizzleUUID(r.InterfaceID)
		copy(bytes[24:], uuidLE)
		uuidLE, _ = FizzleUUID(r.ActivityID)
		copy(bytes[40:], uuidLE)
		binary.LittleEndian.PutUint32(bytes[56:60], uint32(r.ServerBootTime))
		binary.LittleEndian.PutUint32(bytes[60:64], uint32(r.InterfaceVersion))
		binary.LittleEndian.PutUint32(bytes[64:68], uint32(r.SequenceNum))
		binary.LittleEndian.PutUint16(bytes[68:70], uint16(r.OpNum))
		binary.LittleEndian.PutUint16(bytes[70:72], uint16(r.InterfaceHint))
		binary.LittleEndian.PutUint16(bytes[72:74], uint16(r.ActivityHint))
		binary.LittleEndian.PutUint16(bytes[74:76], uint16(r.BodyLen))
		binary.LittleEndian.PutUint16(bytes[76:78], uint16(r.FragmentNo))
	}
	bytes[78] = r.AuthProto
	bytes[79] = r.SerialLow

	return nil
}

func decodeRPC(data []byte, p gopacket.PacketBuilder) error {
	d := &RPC{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		log.Println("[decodeRPC] DecodeFromBytes error", err)
		return err
	}
	p.AddLayer(d)

	switch d.PacketType {
	case RPCPacketTypePing:
		// no more package data to come? - TODO
		return nil
	case RPCPacketTypeRequest:
		// check interface uuid
		if bytes.Equal(d.InterfaceID, PNIODeviceInterfaceID()) ||
			bytes.Equal(d.InterfaceID, PNIOControllerInterfaceID()) {
			// this is a PNIO request
			switch d.OpNum {
			case RPCPNIOOpNumConnect:
				return p.NextDecoder(LayerTypePNIOConnectReq)
			case RPCPNIOOpNumRelease:
				return p.NextDecoder(LayerTypePNIOReleaseReq)
			case RPCPNIOOpNumRead, RPCPNIOOpNumReadImplicit:
				return p.NextDecoder(LayerTypePNIOReadReq)
			case RPCPNIOOpNumWrite:
				return p.NextDecoder(LayerTypePNIOWriteReq)
			case RPCPNIOOpNumControl:
				return p.NextDecoder(LayerTypePNIOControlReq)
			default:
				return errors.New("unhandled RPC PNIO OpNum " + strconv.Itoa(int(d.OpNum)))
			}
		} else if bytes.Equal(d.InterfaceID, NDREPMapLookupReqInterfaceID()) {
			// this is a epmap request
			switch d.OpNum {
			case RPCEPMapOpNumLookupReq:
				return p.NextDecoder(LayerTypeRPCEPMapLookupReq)
			case RPCEPMapOpNumLookupHandleFree:
				return p.NextDecoder(LayerTypeRPCEPMapLookupFreeReq)
			default:
				return errors.New("unhandled RPC EPMap OpNum " + strconv.Itoa(int(d.OpNum)))
			}
		} else {
			log.Printf("unhandled interface id: % x\n", d.InterfaceID)
		}
	default:
		// TODO
		return errors.New("unhandled RPC packet type " + strconv.Itoa(int(d.PacketType)))
	}

	return nil
}

type NDREPMapLookupReq struct {
	BaseLayer
	InquiryType           uint32
	ObjectReference       uint32
	ObjectUUID            []byte // 16 byte UUID
	InterfaceReference    uint32
	InterfaceUUID         []byte // 16 byte UUID
	InterfaceVersionMajor uint16
	InterfaceVersionMinor uint16
	VersionOption         uint32
	EntryHandleAttribute  uint32
	EntryHandleUUID       []byte // 16 byte UUID
	MaxEntries            uint32
}

func (r NDREPMapLookupReq) LayerType() gopacket.LayerType { return LayerTypeRPCEPMapLookupReq }

func NDREPMapLookupReqInterfaceID() []byte {
	return []byte{0xe1, 0xaf, 0x83, 0x08, 0x5d, 0x1f, 0x11, 0xc9, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa}
}

func NDR32bUUID() []byte {
	return []byte{0x8a, 0x88, 0x5d, 0x04, 0x1c, 0xeb, 0x11, 0xc9, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60}
}

func (r *NDREPMapLookupReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 76 {
		return errors.New("Malformed RPC EPMap lookup request packet. Too short")
	}

	littleEndian := true // TODO get this from packet
	// packet, _ := df.(gopacket.Packet)
	// if RPCLay := packet.Layer(LayerTypeRPC); RPCLay != nil {
	// 	RPC, _ := RPCLay.(*RPC)
	// 	littleEndian = (RPC.Encoding.IntegerRepresentation == IntegerRepresentationLittleEndian)
	// }

	if littleEndian {
		r.InquiryType = binary.LittleEndian.Uint32(data[0:])
		r.ObjectReference = binary.LittleEndian.Uint32(data[4:])
		r.ObjectUUID, _ = FizzleUUID(data[8:24])
		r.InterfaceReference = binary.LittleEndian.Uint32(data[24:])
		r.InterfaceUUID, _ = FizzleUUID(data[28:44])
		r.InterfaceVersionMajor = binary.LittleEndian.Uint16(data[44:])
		r.InterfaceVersionMinor = binary.LittleEndian.Uint16(data[46:])
		r.VersionOption = binary.LittleEndian.Uint32(data[48:])
		r.EntryHandleAttribute = binary.LittleEndian.Uint32(data[52:])
		r.EntryHandleUUID, _ = FizzleUUID(data[56:72])
		r.MaxEntries = binary.LittleEndian.Uint32(data[72:])
	} else {
		r.InquiryType = binary.BigEndian.Uint32(data[0:])
		r.ObjectReference = binary.BigEndian.Uint32(data[4:])
		r.ObjectUUID = make([]byte, 16)
		copy(r.ObjectUUID, data[8:24])
		r.InterfaceReference = binary.BigEndian.Uint32(data[24:])
		r.InterfaceUUID = make([]byte, 16)
		copy(r.InterfaceUUID, data[28:44])
		r.InterfaceVersionMajor = binary.BigEndian.Uint16(data[44:])
		r.InterfaceVersionMinor = binary.BigEndian.Uint16(data[46:])
		r.VersionOption = binary.BigEndian.Uint32(data[48:])
		r.EntryHandleAttribute = binary.BigEndian.Uint32(data[52:])
		r.EntryHandleUUID = make([]byte, 16)
		copy(r.EntryHandleUUID, data[56:])
		r.MaxEntries = binary.BigEndian.Uint32(data[72:])
	}

	r.Contents = data[:76]

	return nil
}

func decodeRPCEPMapLookupReq(data []byte, p gopacket.PacketBuilder) error {
	d := &NDREPMapLookupReq{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		log.Println("[decodeRPCEPMapLookupReq] DecodeFromBytes error", err)
		return err
	}
	p.AddLayer(d)

	return nil
}

type NDREPMapLookupResEntryFloorProtocol uint8

const (
	NDREPMapLookupResEntryFloorProtocolUDP               NDREPMapLookupResEntryFloorProtocol = 0x08
	NDREPMapLookupResEntryFloorProtocolIP                NDREPMapLookupResEntryFloorProtocol = 0x09
	NDREPMapLookupResEntryFloorProtocolRPCConnectionless NDREPMapLookupResEntryFloorProtocol = 0x0a
	NDREPMapLookupResEntryFloorProtocolUUID              NDREPMapLookupResEntryFloorProtocol = 0x0d
)

type NDREPMapLookupResEntryFloor interface {
	Protocol() NDREPMapLookupResEntryFloorProtocol
	SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error)
}

type NDREPMapLookupResEntryFloorBase struct {
	LHSLength uint16
	// Protocol  NDREPMapLookupResEntryFloorProtocol
	RHSLength uint16
}

type NDREPMapLookupResEntryFloorRPCProtocol struct {
	NDREPMapLookupResEntryFloorBase
	VersionMinor uint16
}

func (f NDREPMapLookupResEntryFloorRPCProtocol) Protocol() NDREPMapLookupResEntryFloorProtocol {
	return NDREPMapLookupResEntryFloorProtocolRPCConnectionless
}

func (f *NDREPMapLookupResEntryFloorRPCProtocol) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	bytes, err := b.AppendBytes(7)
	if err != nil {
		return 0, err
	}

	if opts.FixLengths {
		f.LHSLength = 1
		f.RHSLength = 2
	}

	// TODO also handle big endian ?! get info from other packet
	binary.LittleEndian.PutUint16(bytes[0:2], f.LHSLength)
	bytes[2] = uint8(f.Protocol())
	binary.LittleEndian.PutUint16(bytes[3:5], f.RHSLength)
	binary.LittleEndian.PutUint16(bytes[5:7], f.VersionMinor)

	return len(bytes), nil
}

type NDREPMapLookupResEntryFloorUUID struct {
	NDREPMapLookupResEntryFloorBase
	UUID         []byte
	Version      uint16
	VersionMinor uint16
}

func (f NDREPMapLookupResEntryFloorUUID) Protocol() NDREPMapLookupResEntryFloorProtocol {
	return NDREPMapLookupResEntryFloorProtocolUUID
}

func (f *NDREPMapLookupResEntryFloorUUID) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	bytes, err := b.AppendBytes(25)
	if err != nil {
		return 0, err
	}

	if opts.FixLengths {
		f.LHSLength = 19
		f.RHSLength = 2
	}

	// TODO also handle big endian ?! get info from other packet
	binary.LittleEndian.PutUint16(bytes[0:2], f.LHSLength)
	bytes[2] = uint8(f.Protocol())
	uuidLE, _ := FizzleUUID(f.UUID)
	copy(bytes[3:19], uuidLE)
	binary.LittleEndian.PutUint16(bytes[19:21], f.Version)
	binary.LittleEndian.PutUint16(bytes[21:23], f.RHSLength)
	binary.LittleEndian.PutUint16(bytes[23:25], f.VersionMinor)

	return len(bytes), nil
}

type NDREPMapLookupResEntryFloorUDP struct {
	NDREPMapLookupResEntryFloorBase
	UDPPort uint16
}

func (f NDREPMapLookupResEntryFloorUDP) Protocol() NDREPMapLookupResEntryFloorProtocol {
	return NDREPMapLookupResEntryFloorProtocolUDP
}

func (f *NDREPMapLookupResEntryFloorUDP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	bytes, err := b.AppendBytes(7)
	if err != nil {
		return 0, err
	}

	if opts.FixLengths {
		f.LHSLength = 1
		f.RHSLength = 2
	}

	// TODO also handle big endian ?! get info from other packet
	binary.LittleEndian.PutUint16(bytes[0:2], f.LHSLength)
	bytes[2] = uint8(f.Protocol())
	binary.LittleEndian.PutUint16(bytes[3:5], f.RHSLength)
	binary.BigEndian.PutUint16(bytes[5:7], f.UDPPort) // big endian?!

	return len(bytes), nil
}

type NDREPMapLookupResEntryFloorIP struct {
	NDREPMapLookupResEntryFloorBase
	IP []byte // 4 byte IP
}

func NewNDREPMapLookupResEntryFloorIP(ipv4 []byte) *NDREPMapLookupResEntryFloorIP {
	f := &NDREPMapLookupResEntryFloorIP{IP: make([]byte, 4)}
	copy(f.IP, ipv4)
	return f
}

func (f NDREPMapLookupResEntryFloorIP) Protocol() NDREPMapLookupResEntryFloorProtocol {
	return NDREPMapLookupResEntryFloorProtocolIP
}

func (f *NDREPMapLookupResEntryFloorIP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	bytes, err := b.AppendBytes(9)
	if err != nil {
		return 0, err
	}

	if opts.FixLengths {
		f.LHSLength = 1
		f.RHSLength = 4
	}

	// TODO also handle big endian ?! get info from other packet
	binary.LittleEndian.PutUint16(bytes[0:2], f.LHSLength)
	bytes[2] = uint8(f.Protocol())
	binary.LittleEndian.PutUint16(bytes[3:5], f.RHSLength)
	copy(bytes[5:9], f.IP)

	return len(bytes), nil
}

type NDREPMapLookupResEntry struct {
	ObjectUUID       []byte // 16 byte UUID
	TowerReference   uint32
	AnnotationOffset uint32
	AnnotationLength uint32
	Annotation       []byte
	// Padding
	TowerLength            uint32
	TowerOctetStringLength uint32
	Floors                 []NDREPMapLookupResEntryFloor
	// Padding
}

func (r *NDREPMapLookupResEntry) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.AppendBytes(28 + 64)
	if err != nil {
		return err
	}

	if opts.FixLengths {
		r.AnnotationOffset = 0
		r.AnnotationLength = uint32(len(r.Annotation))
	}

	// TODO also handle big endian ?! get info from other packet
	objectUUIDLE, _ := FizzleUUID(r.ObjectUUID)
	copy(bytes[0:16], objectUUIDLE)
	binary.LittleEndian.PutUint32(bytes[16:20], r.TowerReference)
	binary.LittleEndian.PutUint32(bytes[20:24], r.AnnotationOffset)
	binary.LittleEndian.PutUint32(bytes[24:28], r.AnnotationLength)
	copy(bytes[28:], r.Annotation)

	if len(r.Floors) > 0 {
		bytes, err := b.AppendBytes(10)
		if err != nil {
			return err
		}

		lenFloors := 2 // for number of floors
		for _, floor := range r.Floors {
			l, err := floor.SerializeTo(b, opts)
			if err != nil {
				return err
			}
			lenFloors = lenFloors + l
		}

		binary.LittleEndian.PutUint32(bytes[0:4], uint32(lenFloors))
		binary.LittleEndian.PutUint32(bytes[4:8], uint32(lenFloors))
		binary.LittleEndian.PutUint16(bytes[8:10], uint16(len(r.Floors)))

		if lenFloors%2 != 0 {
			// pad to even number of bytes?! - TODO
			_, err := b.AppendBytes(1)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

type NDREPMapLookupRes struct {
	BaseLayer
	EntryHandleAttribute uint32
	EntryHandleUUID      []byte // 16 Byte UUID
	NumberOfEntries      uint32
	MaxEntries           uint32
	EntriesOffset        uint32
	EntriesCount         uint32
	Entries              []NDREPMapLookupResEntry
	Status               uint32
}

func (r NDREPMapLookupRes) LayerType() gopacket.LayerType { return LayerTypeRPCEPMapLookupRes }

func (r *NDREPMapLookupRes) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.AppendBytes(36)
	if err != nil {
		return err
	}

	if opts.FixLengths {
		r.NumberOfEntries = uint32(len(r.Entries))
		r.MaxEntries = uint32(len(r.Entries)) // TODO check this (!)
		r.EntriesOffset = 0
		r.EntriesCount = uint32(len(r.Entries))
	}

	// TODO also handle big endian ?! get info from other packet
	binary.LittleEndian.PutUint32(bytes[0:4], r.EntryHandleAttribute)
	entryHandleUUIDLE, _ := FizzleUUID(r.EntryHandleUUID)
	copy(bytes[4:20], entryHandleUUIDLE)
	binary.LittleEndian.PutUint32(bytes[20:24], r.NumberOfEntries)

	// lenPacket := 36

	binary.LittleEndian.PutUint32(bytes[24:28], r.MaxEntries)
	binary.LittleEndian.PutUint32(bytes[28:32], r.EntriesOffset)
	binary.LittleEndian.PutUint32(bytes[32:36], r.EntriesCount)

	// encode entries
	for _, entry := range r.Entries {
		err := entry.SerializeTo(b, opts)
		if err != nil {
			return err
		}
	}

	// encode status
	bytes, err = b.AppendBytes(4)
	if err != nil {
		return err
	}

	binary.LittleEndian.PutUint32(bytes[0:4], r.Status)

	return nil
}

type NDREPMapLookupFreeReq struct {
	BaseLayer
	EntryHandleAttribute uint32
	EntryHandleUUID      []byte // 16 byte UUID
}

func (r NDREPMapLookupFreeReq) LayerType() gopacket.LayerType { return LayerTypeRPCEPMapLookupFreeReq }

func (r *NDREPMapLookupFreeReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 20 {
		return errors.New("Malformed RPC EPMap lookup free request packet. Too short")
	}

	littleEndian := true // TODO get this from packet
	if littleEndian {
		r.EntryHandleAttribute = binary.LittleEndian.Uint32(data[52:])
		r.EntryHandleUUID, _ = FizzleUUID(data[56:72])
	} else {
		r.EntryHandleAttribute = binary.BigEndian.Uint32(data[0:])
		r.EntryHandleUUID = make([]byte, 16)
		copy(r.EntryHandleUUID, data[4:])
	}

	r.Contents = data[:20]

	return nil
}

func decodeRPCEPMapLookupFreeReq(data []byte, p gopacket.PacketBuilder) error {
	d := &NDREPMapLookupFreeReq{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		log.Println("[decodeRPCEPMapLookupFreeReq] DecodeFromBytes error", err)
		return err
	}
	p.AddLayer(d)

	return nil
}
