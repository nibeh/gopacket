package layers

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/google/gopacket"
)

type DCERPCPacketType byte

const (
	DCERPCPacketTypeRequest          DCERPCPacketType = 0
	DCERPCPacketTypePing             DCERPCPacketType = 1
	DCERPCPacketTypeResponse         DCERPCPacketType = 2
	DCERPCPacketTypeFault            DCERPCPacketType = 3
	DCERPCPacketTypeWorking          DCERPCPacketType = 4
	DCERPCPacketTypeNoCall           DCERPCPacketType = 5
	DCERPCPacketTypeReject           DCERPCPacketType = 6
	DCERPCPacketTypeAck              DCERPCPacketType = 7
	DCERPCPacketTypeClCancel         DCERPCPacketType = 8
	DCERPCPacketTypeFack             DCERPCPacketType = 9
	DCERPCPacketTypeCancelAck        DCERPCPacketType = 10
	DCERPCPacketTypeBind             DCERPCPacketType = 11
	DCERPCPacketTypeBindAck          DCERPCPacketType = 12
	DCERPCPacketTypeBindNak          DCERPCPacketType = 13
	DCERPCPacketTypeAlterContext     DCERPCPacketType = 14
	DCERPCPacketTypeAlterContextResp DCERPCPacketType = 15
	DCERPCPacketTypeShutdown         DCERPCPacketType = 17
	DCERPCPacketTypeCoCancel         DCERPCPacketType = 18
	DCERPCPacketTypeOrphaned         DCERPCPacketType = 19
)

type DCERPCOpNumType uint16

const (
	DCERPCOpNumConnect      DCERPCOpNumType = 0x0000
	DCERPCOpNumRelease      DCERPCOpNumType = 0x0001
	DCERPCOpNumRead         DCERPCOpNumType = 0x0002
	DCERPCOpNumWrite        DCERPCOpNumType = 0x0003
	DCERPCOpNumControl      DCERPCOpNumType = 0x0004
	DCERPCOpNumReadImplicit DCERPCOpNumType = 0x0005
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

type DCERPCFormats struct {
	IntegerRepresentation       IntegerRepresentationType
	CharacterRepresentation     CharacterRepresentationType
	FloatingPointRepresentation FloatingPointRepresentationType
}

func getEncoding(data []byte) (DCERPCFormats, error) {
	var format DCERPCFormats

	if len(data) < 3 {
		return format, errors.New("encodings data too short. Need 3 Bytes")
	}

	format.IntegerRepresentation = IntegerRepresentationType(data[0] >> 4)
	format.CharacterRepresentation = CharacterRepresentationType(data[0] & 0x0f)
	format.FloatingPointRepresentation = FloatingPointRepresentationType(data[1])

	return format, nil
}

func (e DCERPCFormats) ToBytes(data []byte) {
	data[0] = uint8(e.CharacterRepresentation) | (uint8(e.IntegerRepresentation) << 4)
	data[1] = uint8(e.FloatingPointRepresentation)
}

// LLDPCapabilities Types
const (
	DCERPCFlags1LastFragment uint8 = 1 << 1
	DCERPCFlags1Fragment     uint8 = 1 << 2
	DCERPCFlags1NoFack       uint8 = 1 << 3
	DCERPCFlags1Maybe        uint8 = 1 << 4
	DCERPCFlags1Idempotent   uint8 = 1 << 5
	DCERPCFlags1Broadcast    uint8 = 1 << 6
)

type DCERPCFlags1 struct {
	LastFragment bool
	Fragment     bool
	NoFack       bool
	Maybe        bool
	Idempotent   bool
	Broadcast    bool
}

func getFlags1(d uint8) (f DCERPCFlags1) {
	f.LastFragment = (d&DCERPCFlags1LastFragment > 0)
	f.Fragment = (d&DCERPCFlags1Fragment > 0)
	f.NoFack = (d&DCERPCFlags1NoFack > 0)
	f.Maybe = (d&DCERPCFlags1Maybe > 0)
	f.Idempotent = (d&DCERPCFlags1Idempotent > 0)
	f.Broadcast = (d&DCERPCFlags1Broadcast > 0)
	return
}

func (f DCERPCFlags1) ToUint8() uint8 {
	var r uint8
	if f.LastFragment {
		r = r | DCERPCFlags1LastFragment
	}
	if f.Fragment {
		r = r | DCERPCFlags1Fragment
	}
	if f.NoFack {
		r = r | DCERPCFlags1NoFack
	}
	if f.Maybe {
		r = r | DCERPCFlags1Maybe
	}
	if f.Idempotent {
		r = r | DCERPCFlags1Idempotent
	}
	if f.Broadcast {
		r = r | DCERPCFlags1Broadcast
	}
	return r
}

func RandomUUID() []byte {
	res := make([]byte, 16)
	rand.Read(res)
	return res
}

type DCERPC struct {
	BaseLayer
	Version          uint8
	PacketType       DCERPCPacketType
	Flags1           DCERPCFlags1
	Flags2           uint8
	Encoding         DCERPCFormats
	SerialHigh       uint8
	ObjectID         []byte // 16 Byte
	InterfaceID      []byte // 16 Byte
	ActivityID       []byte // 16 Byte
	ServerBootTime   uint32
	InterfaceVersion uint32
	SequenceNum      uint32
	OpNum            DCERPCOpNumType
	InterfaceHint    uint16
	ActivityHint     uint16
	BodyLen          uint16
	FragmentNo       uint16
	AuthProto        uint8
	SerialLow        uint8
}

func (r DCERPC) LayerType() gopacket.LayerType { return LayerTypeDCERPC }

// little endian to big endian fizzle (shuffle)
func fizzleUUID(uuidLE []byte) ([]byte, error) {
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

func (r *DCERPC) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 80 {
		return errors.New("Profinet DCE/RPC packet too small")
	}

	r.Version = uint8(data[0])
	r.PacketType = DCERPCPacketType(data[1])
	r.Flags1 = getFlags1(data[2])
	r.Flags2 = uint8(data[3])
	r.Encoding, _ = getEncoding(data[4:6]) // after one byte of pad
	r.SerialHigh = uint8(data[7])
	if r.Encoding.IntegerRepresentation == IntegerRepresentationLittleEndian {
		// log.Println("\tLittle-Endian Encoding")
		r.ObjectID, _ = fizzleUUID(data[8:24])
		r.InterfaceID, _ = fizzleUUID(data[24:40])
		r.ActivityID, _ = fizzleUUID(data[40:56])
		r.ServerBootTime = binary.LittleEndian.Uint32(data[56:60])
		r.InterfaceVersion = binary.LittleEndian.Uint32(data[60:64])
		r.SequenceNum = binary.LittleEndian.Uint32(data[64:68])
		r.OpNum = DCERPCOpNumType(binary.LittleEndian.Uint16(data[68:70]))
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
		r.OpNum = DCERPCOpNumType(binary.BigEndian.Uint16(data[68:70]))
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

func (r *DCERPC) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
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
	bytes[78] = r.AuthProto
	bytes[79] = r.SerialLow

	return nil
}

func decodeDCERPC(data []byte, p gopacket.PacketBuilder) error {
	// assertion, if data is too small
	if len(data) < 80 {
		return errors.New("Malformed DCERPC Packet")
	}

	d := &DCERPC{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(d)

	switch d.PacketType {
	case DCERPCPacketTypePing:
		// no more package data to come? - TODO
		return nil
	// case DCERPCPacketTypeRequest:
	default:
		// check interface uuid
		if bytes.Equal(d.InterfaceID, PNIODCERPCDeviceInterfaceID()) ||
			bytes.Equal(d.InterfaceID, PNIODCERPCControllerInterfaceID()) {
			return p.NextDecoder(LayerTypeProfinetIO)
		}
	}

	return nil
}
