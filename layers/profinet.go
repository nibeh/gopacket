package layers

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"strconv"

	"github.com/google/gopacket"
)

type PNFrameID uint16

const (
	PNFrameIDTimeSynchronization PNFrameID = 0x0000
	PNFrameIDRTClass3            PNFrameID = 0x0100
	PNFrameIDRTClass2            PNFrameID = 0x8000
	PNFrameIDRTClass1            PNFrameID = 0xc000
	PNFrameIDAcyclicHigh         PNFrameID = 0xfc00
	PNFrameIDReserved            PNFrameID = 0xfd00
	PNFrameIDAcyclicLow          PNFrameID = 0xfe00
	PNFrameIDHello               PNFrameID = 0xfefc
	PNFrameIDDCPGetOrSet         PNFrameID = 0xfefd
	PNFrameIDDCPIdentifyRequest  PNFrameID = 0xfefe
	PNFrameIDDCPIdentifyResponse PNFrameID = 0xfeff
)

func PNDCPMulticastMAC() []byte {
	return []byte{0x01, 0x0e, 0xcf, 0x00, 0x00, 0x00}
}

type PNDCPServiceID uint8

const (
	PNDCPServiceIDGet      PNDCPServiceID = 0x03
	PNDCPServiceIDSet      PNDCPServiceID = 0x04
	PNDCPServiceIDIdentify PNDCPServiceID = 0x05
	PNDCPServiceIDHello    PNDCPServiceID = 0x06
)

type PNDCPServiceType uint8

const (
	PNDCPServiceTypeRequest     PNDCPServiceType = 0
	PNDCPServiceTypeSuccess     PNDCPServiceType = 1
	PNDCPServiceTypeUnsupported PNDCPServiceType = 5
)

type PNDCPOption uint8

const (
	PNDCPOptionIP               PNDCPOption = 0x01
	PNDCPOptionDevice           PNDCPOption = 0x02
	PNDCPOptionDHPC             PNDCPOption = 0x03
	PNDCPOptionReserved         PNDCPOption = 0x04
	PNDCPOptionControl          PNDCPOption = 0x05
	PNDCPOptionDeviceInitiative PNDCPOption = 0x06
	PNDCPOptionManufX80         PNDCPOption = 0x80
	PNDCPOptionManufX81         PNDCPOption = 0x81
	PNDCPOptionManufX82         PNDCPOption = 0x82
	PNDCPOptionManufX83         PNDCPOption = 0x83
	PNDCPOptionManufX84         PNDCPOption = 0x84
	PNDCPOptionManufX85         PNDCPOption = 0x85
	PNDCPOptionManufX86         PNDCPOption = 0x86
	PNDCPOptionAllselector      PNDCPOption = 0xff
)

type PNDCPSuboption uint8

const (
	PNDCPSuboptionAllselector PNDCPSuboption = 0xff
)

type PNDCPSuboptionIP PNDCPSuboption

const (
	PNDCPSuboptionIPMAC PNDCPSuboptionIP = 0x01
	PNDCPSuboptionIPIP  PNDCPSuboptionIP = 0x02
)

type PNDCPSuboptionDevice PNDCPSuboption

const (
	PNDCPSuboptionDeviceManufacturer  PNDCPSuboptionDevice = 0x01
	PNDCPSuboptionDeviceNameOfStation PNDCPSuboptionDevice = 0x02
	PNDCPSuboptionDeviceID            PNDCPSuboptionDevice = 0x03
	PNDCPSuboptionDeviceRole          PNDCPSuboptionDevice = 0x04
	PNDCPSuboptionDeviceOptions       PNDCPSuboptionDevice = 0x05
	PNDCPSuboptionDeviceAliasName     PNDCPSuboptionDevice = 0x06
	PNDCPSuboptionDeviceInstance      PNDCPSuboptionDevice = 0x07
)

type PNDCPSuboptionControl PNDCPSuboption

const (
	PNDCPSuboptionControlStartTransaction PNDCPSuboptionControl = 0x01
	PNDCPSuboptionControlEndTransaction   PNDCPSuboptionControl = 0x02
	PNDCPSuboptionControlSignal           PNDCPSuboptionControl = 0x03
	PNDCPSuboptionControlResponse         PNDCPSuboptionControl = 0x04
	PNDCPSuboptionControlFactoryReset     PNDCPSuboptionControl = 0x05
)

const (
	PNDCPOptionDeviceRoleIODevice      uint8 = 0x01
	PNDCPOptionDeviceRoleIOController  uint8 = 0x02
	PNDCPOptionDeviceRoleIOMultidevice uint8 = 0x04
	PNDCPOptionDeviceRoleIOSupervisor  uint8 = 0x08
)

type PNDCPBlockError uint8

const (
	PNDCPBlockErrorOK                   PNDCPBlockError = 0x00
	PNDCPBlockErrorOptionUnsupported    PNDCPBlockError = 0x01
	PNDCPBlockErrorSuboptionUnsupported PNDCPBlockError = 0x02
	PNDCPBlockErrorSuboptionNotSet      PNDCPBlockError = 0x03
	PNDCPBlockErrorResourceError        PNDCPBlockError = 0x04
	PNDCPBlockErrorSetImpossible        PNDCPBlockError = 0x05
	PNDCPBlockErrorInOperation          PNDCPBlockError = 0x06
)

type Profinet struct {
	BaseLayer
	FrameID PNFrameID
}

func (p Profinet) LayerType() gopacket.LayerType { return LayerTypeProfinet }

func (p *Profinet) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 2 {
		return errors.New("Profinet packet too small")
	}

	p.FrameID = PNFrameID(binary.BigEndian.Uint16(data[0:2]))
	p.Payload = data[2:]

	return nil
}

func (p *Profinet) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {

	bytes, err := b.PrependBytes(2)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, uint16(p.FrameID))

	// TODO added VLAN
	bytes2, err := b.PrependBytes(4)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes2[2:4], uint16(EthernetTypeProfinet))

	// log.Printf("% x\n", b.Bytes())
	return nil
}

func decodeProfinet(data []byte, p gopacket.PacketBuilder) error {
	// assertion, if data is too small
	if len(data) < 2 {
		return errors.New("Malformed Profinet Packet")
	}

	d := &Profinet{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(d)

	if d.FrameID >= PNFrameIDTimeSynchronization && d.FrameID < PNFrameIDRTClass3 {
		// fmt.Println("This is a Profinet Time Synchronization packet")
	} else if d.FrameID >= PNFrameIDRTClass3 && d.FrameID < PNFrameIDRTClass2 {
		// fmt.Println("This is a Profinet RT Class 3 packet")
		return p.NextDecoder(LayerTypeProfinetRT)
	} else if d.FrameID >= PNFrameIDRTClass2 && d.FrameID < PNFrameIDRTClass1 {
		// fmt.Println("This is a Profinet RT Class 2 packet")
		return p.NextDecoder(LayerTypeProfinetRT)
	} else if d.FrameID >= PNFrameIDRTClass1 && d.FrameID < PNFrameIDAcyclicHigh {
		// fmt.Println("This is a Profinet RT Class 1 packet")
		return p.NextDecoder(LayerTypeProfinetRT)
	} else if d.FrameID >= PNFrameIDAcyclicHigh && d.FrameID < PNFrameIDReserved {
		// fmt.Println("This is a Profinet Acyclic High packet")
	} else if d.FrameID >= PNFrameIDReserved && d.FrameID < PNFrameIDAcyclicLow {
		// fmt.Println("This is a Profinet Reserved packet")
	} else if d.FrameID >= PNFrameIDAcyclicLow && d.FrameID < PNFrameIDDCPGetOrSet {
		// fmt.Println("This is a Profinet Acyclic Low packet")
	} else if d.FrameID >= PNFrameIDDCPGetOrSet && d.FrameID <= PNFrameIDDCPIdentifyResponse {
		// fmt.Println("This is a Profinet DCP packet")
		return p.NextDecoder(LayerTypeProfinetDCP)
	}

	return nil
}

type ProfinetDCP struct {
	BaseLayer
	ServiceID     PNDCPServiceID
	ServiceType   PNDCPServiceType
	Xid           uint32
	ResponseDelay uint16
	BlockLength   uint16
	Blocks        []ProfinetDCPBlock
}

type ProfinetDCPBlock struct {
	Option    PNDCPOption
	Suboption uint8
	Length    uint16
	Data      []byte
}

func (p ProfinetDCP) LayerType() gopacket.LayerType { return LayerTypeProfinetDCP }

func (p *ProfinetDCP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {

	var blocksLen int
	for _, block := range p.Blocks {
		blockLen := len(block.Data)
		blockLen = blockLen + blockLen%2 // static params + byte array length + padding

		if opts.FixLengths {
			block.Length = uint16(blockLen)
		}

		blocksLen = blocksLen + 4 + blockLen
		// fmt.Printf("%d\t%d\n", blockLen, blocksLen)
	}
	if opts.FixLengths {
		p.BlockLength = uint16(blocksLen)
	}

	// fmt.Println("final: ", blocksLen)

	// TODO added VLAN to DCP
	// bytes, err := b.PrependBytes(14 + blocksLen)

	bytes, err := b.PrependBytes(10 + blocksLen)
	if err != nil {
		return err
	}
	bytes[0] = uint8(p.ServiceID)
	bytes[1] = uint8(p.ServiceType)
	binary.BigEndian.PutUint32(bytes[2:], p.Xid)
	binary.BigEndian.PutUint16(bytes[6:], p.ResponseDelay)
	binary.BigEndian.PutUint16(bytes[8:], p.BlockLength)

	blocksLen = 10
	for _, block := range p.Blocks {
		blockLen := len(block.Data)
		blockLen = blockLen + blockLen%2 // static params + byte array length + padding

		bytes[blocksLen] = uint8(block.Option)
		bytes[blocksLen+1] = block.Suboption
		binary.BigEndian.PutUint16(bytes[blocksLen+2:], uint16(blockLen))
		copy(bytes[blocksLen+4:], block.Data)

		blocksLen = blocksLen + 4 + blockLen
	}

	return nil
}

func (d *ProfinetDCP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	d.ServiceID = PNDCPServiceID(data[0])
	d.ServiceType = PNDCPServiceType(data[1])
	d.Xid = binary.BigEndian.Uint32(data[2:6])
	d.ResponseDelay = binary.BigEndian.Uint16(data[6:8])
	d.BlockLength = binary.BigEndian.Uint16(data[8:10])

	len := int(d.BlockLength)
	for len >= 4 {
		dcpBlock := &ProfinetDCPBlock{}
		decodedLen, err := dcpBlock.DecodeFromBytes(data[(10+int(d.BlockLength)-len):], df)
		if err != nil {
			return err
		}

		d.Blocks = append(d.Blocks, *dcpBlock)
		len = len - decodedLen
	}

	return nil
}

func (b *ProfinetDCPBlock) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) (int, error) {
	if len(data) < 4 {
		return 0, errors.New("Profinet DCP block too small")
	}

	b.Option = PNDCPOption(uint8(data[0]))
	b.Suboption = uint8(data[1])
	b.Length = binary.BigEndian.Uint16(data[2:4])
	if b.Length > 0 {
		if len(data[4:]) < int(b.Length) {
			df.SetTruncated()
			// TODO still return error here, even if packet is truncated?
			return 4, errors.New("Profinet DCP block data too small")
		}

		b.Data = data[4 : b.Length+4]
	}

	// including padding here
	lenDecoded := int(b.Length) + 4 + int(b.Length)%2

	return lenDecoded, nil
}

func decodeProfinetDCP(data []byte, p gopacket.PacketBuilder) error {
	// assertion, if data is too small
	if len(data) < 10 {
		return errors.New("Malformed Profinet DCP Packet")
	}

	d := &ProfinetDCP{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(d)

	return nil
}

type ProfinetRT struct {
	BaseLayer
	Data           []byte // 40 - 1500 Byte
	CycleCounter   uint16
	DataStatus     uint8
	TransferStatus uint8
}

func (p ProfinetRT) LayerType() gopacket.LayerType { return LayerTypeProfinetRT }

func (d *ProfinetRT) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	numBytes := int(Max(int64(40), int64(len(d.Data)))) + 4
	bytes, err := b.PrependBytes(numBytes)
	if err != nil {
		log.Println("cannot Prepend numBytes:", numBytes)
		return err
	}

	copy(bytes[0:numBytes-4], d.Data)
	binary.BigEndian.PutUint16(bytes[numBytes-4:numBytes-2], uint16(d.CycleCounter))
	bytes[numBytes-2] = d.DataStatus
	bytes[numBytes-1] = d.TransferStatus

	return nil
}

func (d *ProfinetRT) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	offset := len(data) - 4
	d.Data = make([]byte, offset)
	copy(d.Data, data[0:offset])
	d.CycleCounter = binary.BigEndian.Uint16(data[offset : offset+2])
	d.DataStatus = data[offset+2]
	d.TransferStatus = data[offset+3]

	return nil
}

func decodeProfinetRT(data []byte, p gopacket.PacketBuilder) error {
	// assertion, if data is too small
	if len(data) < 44 {
		return errors.New("Malformed Profinet DCP Packet")
	}

	d := &ProfinetRT{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(d)

	return nil
}

type ProfinetDCERPC struct {
	BaseLayer
	Version          uint8
	PacketType       uint8
	Flags1           uint8
	Flags2           uint8
	Encoding         uint16 // after one byte of pad
	SerialHigh       uint8
	ObjectID         []byte // 16 Byte
	InterfaceID      []byte // 16 Byte
	ActivityID       []byte // 16 Byte
	ServerBootTime   uint32
	InterfaceVersion uint32
	SequenceNum      uint32
	OpNum            uint16
	InterfaceHint    uint16
	ActivityHint     uint16
	BodyLen          uint16
	FragmentNo       uint16
	AuthProto        uint8
	SerialLow        uint8
}

func (r ProfinetDCERPC) LayerType() gopacket.LayerType { return LayerTypeProfinetDCERPC }

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

func (r *ProfinetDCERPC) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 80 {
		return errors.New("Profinet DCE/RPC packet too small")
	}

	r.Version = uint8(data[0])
	r.PacketType = uint8(data[1])
	r.Flags1 = uint8(data[2])
	r.Flags2 = uint8(data[3])
	r.Encoding = binary.BigEndian.Uint16(data[4:6]) // after one byte of pad
	r.SerialHigh = uint8(data[7])
	r.ObjectID, _ = fizzleUUID(data[8:24])
	r.InterfaceID, _ = fizzleUUID(data[24:40])
	r.ActivityID, _ = fizzleUUID(data[40:56])
	r.ServerBootTime = binary.LittleEndian.Uint32(data[56:60])
	r.InterfaceVersion = binary.LittleEndian.Uint32(data[60:64])
	r.SequenceNum = binary.LittleEndian.Uint32(data[64:68])
	r.OpNum = binary.LittleEndian.Uint16(data[68:70])
	r.InterfaceHint = binary.LittleEndian.Uint16(data[70:72])
	r.ActivityHint = binary.LittleEndian.Uint16(data[72:74])
	r.BodyLen = binary.LittleEndian.Uint16(data[74:76])
	r.FragmentNo = binary.LittleEndian.Uint16(data[76:78])
	r.AuthProto = uint8(data[78])
	r.SerialLow = uint8(data[79])

	// log.Printf("OpNum: %x\n", r.OpNum)

	r.Contents = data[:80]
	r.Payload = data[80:]

	return nil
}

func (r *ProfinetDCERPC) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	if opts.FixLengths {
		r.BodyLen = uint16(len(b.Bytes()))
	}

	bytes, err := b.PrependBytes(80)
	if err != nil {
		return err
	}

	bytes[0] = r.Version
	bytes[1] = r.PacketType
	bytes[2] = r.Flags1
	bytes[3] = r.Flags2
	binary.BigEndian.PutUint16(bytes[4:6], uint16(r.Encoding))
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

func decodeProfinetDCERPC(data []byte, p gopacket.PacketBuilder) error {
	// assertion, if data is too small
	if len(data) < 80 {
		return errors.New("Malformed RPC Packet")
	}

	d := &ProfinetDCERPC{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(d)

	return p.NextDecoder(LayerTypeProfinetIO)
}

type ProfinetIO struct {
	BaseLayer
	ArgsMaximum                uint32 // or status
	ArgsLength                 uint32
	ArrayMaximumCount          uint32
	ArrayOffset                uint32
	ArrayActualCount           uint32
	ARBlockReqs                []ProfinetIOARBlockReq
	IOCRBlockReqs              []ProfinetIOIOCRBlockReq
	ExpectedSubmoduleBlockReqs []ProfinetIOExpectedSubmoduleBlockReq
	AlarmCRBlockReqs           []ProfinetIOAlarmCRBlockReq
	IODWriteReqHeader          *ProfinetIOIODWriteReqHeader
	ARBlockRess                []ProfinetIOARBlockRes
	IOCRBlockRess              []ProfinetIOIOCRBlockRes
	AlarmCRBlockRess           []ProfinetIOAlarmCRBlockRes
	ModuleDiffBlock            *ProfinetIOModuleDiffBlock
	IODWriteResHeader          *ProfinetIOIODWriteResHeader
	IODControlReq              *ProfinetIOIODControlReq // used for both req and res
}

func (p ProfinetIO) LayerType() gopacket.LayerType { return LayerTypeProfinetIO }

type ProfinetIOBlockHeaderType uint16

const (
	ProfinetIOBlockHeaderTypeIODWriteReqHeader         ProfinetIOBlockHeaderType = 0x0008
	ProfinetIOBlockHeaderTypeARBlockReq                ProfinetIOBlockHeaderType = 0x0101
	ProfinetIOBlockHeaderTypeIOCRBlockReq              ProfinetIOBlockHeaderType = 0x0102
	ProfinetIOBlockHeaderTypeAlarmCRBlockReq           ProfinetIOBlockHeaderType = 0x0103
	ProfinetIOBlockHeaderTypeExpectedSubmoduleBlockReq ProfinetIOBlockHeaderType = 0x0104
	ProfinetIOBlockHeaderTypeIODControlReq             ProfinetIOBlockHeaderType = 0x0110
	ProfinetIOBlockHeaderTypeReleaseReq                ProfinetIOBlockHeaderType = 0x0114
	ProfinetIOBlockHeaderTypeIODWriteResHeader         ProfinetIOBlockHeaderType = 0x8008
	ProfinetIOBlockHeaderTypeARBlockRes                ProfinetIOBlockHeaderType = 0x8101
	ProfinetIOBlockHeaderTypeIOCRBlockRes              ProfinetIOBlockHeaderType = 0x8102
	ProfinetIOBlockHeaderTypeAlarmCRBlockRes           ProfinetIOBlockHeaderType = 0x8103
	ProfinetIOBlockHeaderTypeModuleDiffBlock           ProfinetIOBlockHeaderType = 0x8104
)

type ProfinetIOBlockHeader struct {
	Type        ProfinetIOBlockHeaderType
	Length      uint16
	VersionHigh uint8
	VersionLow  uint8
}

func (h *ProfinetIOBlockHeader) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// TODO check length

	h.Type = ProfinetIOBlockHeaderType(binary.BigEndian.Uint16(data[0:2]))
	h.Length = binary.BigEndian.Uint16(data[2:4])
	h.VersionHigh = uint8(data[4])
	h.VersionLow = uint8(data[5])

	return nil
}

func (h *ProfinetIOBlockHeader) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	bytes, err := b.PrependBytes(6)
	if err != nil {
		return 6, err
	}

	// TODO IMPORTANT header length (only content below header) is set outside
	if opts.FixLengths {
		// previous content length, +2 byte for version
		h.Length = h.Length + uint16(2)
	}

	binary.BigEndian.PutUint16(bytes[0:2], uint16(h.Type))
	binary.BigEndian.PutUint16(bytes[2:4], h.Length)
	bytes[4] = h.VersionHigh
	bytes[5] = h.VersionLow

	return 6, nil
}

type ProfinetIOARBlockReq struct {
	BlockHeader                      ProfinetIOBlockHeader
	ARType                           uint16
	ARUUID                           []byte // 16 byte
	SessionKey                       uint16
	CMInitiatorMac                   net.HardwareAddr // 6 byte
	CMInitiatorObjectUUID            []byte           // 16 byte
	Properties                       uint32
	CMInitiatorActivityTimeoutFactor uint16
	CMInitiatorUDPRTPort             uint16
	CMInitiatorStationNameLength     uint16
	CMInitiatorStationName           string
}

func (p *ProfinetIOARBlockReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// length without header
	if len(data) < 50 {
		return errors.New("Malformed ProfinetIOARBlockReq")
	}

	p.ARType = binary.BigEndian.Uint16(data[0:2])
	p.ARUUID = make([]byte, 16)
	copy(p.ARUUID, data[2:18])
	p.SessionKey = binary.BigEndian.Uint16(data[18:20])
	p.CMInitiatorMac = make([]byte, 6)
	copy(p.CMInitiatorMac, data[20:26])
	p.CMInitiatorObjectUUID = make([]byte, 16)
	copy(p.CMInitiatorObjectUUID, data[26:42])
	p.Properties = binary.BigEndian.Uint32(data[42:46])
	p.CMInitiatorActivityTimeoutFactor = binary.BigEndian.Uint16(data[46:48])
	p.CMInitiatorUDPRTPort = binary.BigEndian.Uint16(data[48:50])
	p.CMInitiatorStationNameLength = binary.BigEndian.Uint16(data[50:52])
	p.CMInitiatorStationName = string(data[50 : 50+p.CMInitiatorStationNameLength])

	return nil
}

type ProfinetIOIODControlReq struct {
	BlockHeader            ProfinetIOBlockHeader
	ARUUID                 []byte
	SessionKey             uint16
	ControlCommand         uint16
	ControlBlockProperties uint16
}

func (p *ProfinetIOIODControlReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// length without header
	if len(data) < 26 {
		return errors.New("Malformed ProfinetIOIODControlReq")
	}

	// 2 bytes reserved
	p.ARUUID = make([]byte, 16)
	copy(p.ARUUID, data[2:18])
	p.SessionKey = binary.BigEndian.Uint16(data[18:20])
	// 2 bytes reserved
	p.ControlCommand = binary.BigEndian.Uint16(data[22:24])
	p.ControlBlockProperties = binary.BigEndian.Uint16(data[24:26])

	return nil
}

func (r *ProfinetIOIODControlReq) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	lenPacket := 26
	bytes, err := b.PrependBytes(lenPacket)
	if err != nil {
		return lenPacket, err
	}

	// 2 bytes reserved
	copy(bytes[2:18], r.ARUUID)
	binary.BigEndian.PutUint16(bytes[18:20], r.SessionKey)
	// 2 bytes reserved
	binary.BigEndian.PutUint16(bytes[22:24], r.ControlCommand)
	binary.BigEndian.PutUint16(bytes[24:26], r.ControlBlockProperties)

	if opts.FixLengths {
		r.BlockHeader.Length = uint16(lenPacket)
	}

	lenBlock, err := r.BlockHeader.SerializeTo(b, opts)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + lenBlock

	return lenPacket, nil
}

type ProfinetIOIODWriteReqHeader struct {
	BlockHeader      ProfinetIOBlockHeader
	SeqNumber        uint16
	ARUUID           []byte
	API              uint32
	SlotNumber       uint16
	SubSlotNumber    uint16
	Index            uint16
	RecordDataLength uint32
	ParameterData    []byte
}

func Max(x, y int64) int64 {
	if x < y {
		return y
	}
	return x
}

func Min(x, y int64) int64 {
	if x < y {
		return x
	}
	return y
}

func (p *ProfinetIOIODWriteReqHeader) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// length WITH header
	if len(data) < 56 {
		return errors.New("Malformed ProfinetIOIODWriteReqHeader")
	}

	// redecode block header, because length is needed here TODO
	blockHeader := &ProfinetIOBlockHeader{}
	err := blockHeader.DecodeFromBytes(data[0:], df)
	if err != nil {
		return err
	}
	p.BlockHeader = *blockHeader

	p.SeqNumber = binary.BigEndian.Uint16(data[6:8])
	p.ARUUID = make([]byte, 16)
	copy(p.ARUUID, data[8:24])
	p.API = binary.BigEndian.Uint32(data[24:28])
	p.SlotNumber = binary.BigEndian.Uint16(data[28:30])
	p.SubSlotNumber = binary.BigEndian.Uint16(data[30:32])
	// 2 byte padding
	p.Index = binary.BigEndian.Uint16(data[34:36])
	p.RecordDataLength = binary.BigEndian.Uint32(data[36:40])
	arrayLen := Min(int64(p.RecordDataLength), int64(128))
	p.ParameterData = make([]byte, arrayLen)
	// log.Printf("record data has length %d and starts after %d byte", arrayLen, p.BlockHeader.Length)
	dataOffset := int(p.BlockHeader.Length) + 4
	copy(p.ParameterData, data[dataOffset:dataOffset+int(arrayLen)])

	// fmt.Println("ProfinetIO - IODWriteReqHeader")
	// fmt.Printf("\tBlockHeader.Type: %x\n", p.BlockHeader.Type)
	// fmt.Printf("\tBlockHeader.VersionHigh: %x\n", p.BlockHeader.VersionHigh)
	// fmt.Printf("\tBlockHeader.VersionLow: %x\n", p.BlockHeader.VersionLow)
	// fmt.Println("\tSeqNumber: ", p.SeqNumber)
	// fmt.Printf("\tARUUID: %x\n", p.ARUUID)
	// fmt.Println("\tAPI: ", p.API)
	// fmt.Println("\tSlotNumber: ", p.SlotNumber)
	// fmt.Println("\tSubSlotNumber: ", p.SubSlotNumber)
	// fmt.Println("\tIndex: ", p.Index)
	// fmt.Println("\tRecordDataLength: ", p.RecordDataLength)
	// fmt.Printf("\tData: % x\n", p.ParameterData)

	return nil
}

type ProfinetIOIODWriteResHeader struct {
	BlockHeader      ProfinetIOBlockHeader
	SeqNumber        uint16
	ARUUID           []byte
	API              uint32
	SlotNumber       uint16
	SubSlotNumber    uint16
	Index            uint16
	RecordDataLength uint32
	AdditionalValue1 uint16
	AdditionalValue2 uint16
	Status           uint32
}

func (r *ProfinetIOIODWriteResHeader) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	lenPacket := 58
	bytes, err := b.PrependBytes(lenPacket)
	if err != nil {
		return lenPacket, err
	}
	binary.BigEndian.PutUint16(bytes[0:2], r.SeqNumber)
	copy(bytes[2:18], r.ARUUID)
	binary.BigEndian.PutUint32(bytes[18:22], r.API)
	binary.BigEndian.PutUint16(bytes[22:24], r.SlotNumber)
	binary.BigEndian.PutUint16(bytes[24:26], r.SubSlotNumber)
	// 2 byte padding
	binary.BigEndian.PutUint16(bytes[28:30], r.Index)
	binary.BigEndian.PutUint32(bytes[30:34], r.RecordDataLength)
	binary.BigEndian.PutUint16(bytes[34:36], r.AdditionalValue1)
	binary.BigEndian.PutUint16(bytes[36:38], r.AdditionalValue2)
	binary.BigEndian.PutUint32(bytes[38:42], r.Status)
	// padding afterwards

	if opts.FixLengths {
		r.BlockHeader.Length = uint16(lenPacket)
	}

	lenBlock, err := r.BlockHeader.SerializeTo(b, opts)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + lenBlock

	return lenPacket, nil
}

type ProfinetIOIOCRBlockReq struct {
	BlockHeader           ProfinetIOBlockHeader
	IOCRType              uint16
	IOCRReference         uint16
	LT                    uint16
	Properties            uint32
	DataLength            uint16
	FrameID               uint16
	SendClockFactor       uint16
	ReductionRatio        uint16
	Phase                 uint16
	Sequence              uint16
	FrameSendOffset       uint32
	WatchDogFactor        uint16
	DataHoldFactor        uint16
	IOCRTagHeader         uint16
	IOCRMulticastMACAdd   net.HardwareAddr // 6 byte
	NumberOfAPIs          uint16
	API                   uint32
	NumberOfIODataObjects uint16
	DataObjects           []byte // TODO better type
	NumberOfIOCS          uint16
	IOCSs                 []byte // TODO better type
}

func (p *ProfinetIOIOCRBlockReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// length without header
	if len(data) < 48 {
		return errors.New("Malformed ProfinetIOARBlockReq")
	}

	// TODO decode header
	// BlockHeader
	p.IOCRType = binary.BigEndian.Uint16(data[0:2])
	p.IOCRReference = binary.BigEndian.Uint16(data[2:4])
	p.LT = binary.BigEndian.Uint16(data[4:6])
	p.Properties = binary.BigEndian.Uint32(data[6:10])
	p.DataLength = binary.BigEndian.Uint16(data[10:12])
	p.FrameID = binary.BigEndian.Uint16(data[12:14])
	p.SendClockFactor = binary.BigEndian.Uint16(data[14:16])
	p.ReductionRatio = binary.BigEndian.Uint16(data[16:18])
	p.Phase = binary.BigEndian.Uint16(data[18:20])
	p.Sequence = binary.BigEndian.Uint16(data[20:22])
	p.FrameSendOffset = binary.BigEndian.Uint32(data[22:26])
	p.WatchDogFactor = binary.BigEndian.Uint16(data[26:28])
	p.DataHoldFactor = binary.BigEndian.Uint16(data[28:30])
	p.IOCRTagHeader = binary.BigEndian.Uint16(data[30:32])
	p.IOCRMulticastMACAdd = make([]byte, 6)
	copy(p.IOCRMulticastMACAdd, data[32:38]) // 6 byte
	p.NumberOfAPIs = binary.BigEndian.Uint16(data[38:40])
	p.API = binary.BigEndian.Uint32(data[40:44])
	p.NumberOfIODataObjects = binary.BigEndian.Uint16(data[44:46])
	// TODO decode completely
	// DataObjects           []byte // TODO better type
	// NumberOfIOCS          uint16
	// IOCSs                 []byte

	return nil
}

type ProfinetIOExpectedSubmoduleBlockReq struct {
	BlockHeader  ProfinetIOBlockHeader
	NumberOfAPIs uint16
	APIs         []ProfinetIOSubmoduleAPI
}

func (p *ProfinetIOExpectedSubmoduleBlockReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// length without header
	if len(data) < 2 {
		return errors.New("Malformed ProfinetIOExpectedSubmoduleBlockReq")
	}

	lenPacket := 2
	p.NumberOfAPIs = binary.BigEndian.Uint16(data[0:2])

	// log.Printf("NumberOfAPIs: %x\n", p.NumberOfAPIs)

	for iAPI := 0; (iAPI < int(p.NumberOfAPIs)) && (len(data[lenPacket:]) > 14); iAPI++ {
		api := &ProfinetIOSubmoduleAPI{}
		lenAPI, err := api.DecodeFromBytes(data[lenPacket:], df)
		if err != nil {
			log.Println("cannot decode API block")
			break
		}
		p.APIs = append(p.APIs, *api)
		lenPacket = lenPacket + lenAPI
	}

	return nil
}

type ProfinetIOSubmoduleAPI struct {
	No                uint32
	SlotNumber        uint16
	ModuleIdentNumber uint32
	ModuleProperties  uint16
	SubModulesLength  uint16
	Submodules        []ProfinetIOSubmodule
}

func (p *ProfinetIOSubmoduleAPI) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) (int, error) {
	// length without header
	if len(data) < 14 {
		return 0, errors.New("Malformed ProfinetIOSubmoduleAPI")
	}

	lenPacket := 14

	p.No = binary.BigEndian.Uint32(data[0:4])
	p.SlotNumber = binary.BigEndian.Uint16(data[4:6])
	p.ModuleIdentNumber = binary.BigEndian.Uint32(data[6:10])
	p.ModuleProperties = binary.BigEndian.Uint16(data[10:12])
	p.SubModulesLength = binary.BigEndian.Uint16(data[12:14])

	// log.Printf("\tNo: %x\n", p.No)
	// log.Printf("\tSlotNumber: %x\n", p.SlotNumber)
	// log.Printf("\tModuleIdentNumber: %x\n", p.ModuleIdentNumber)
	// log.Printf("\tModuleProperties: %x\n", p.ModuleProperties)
	// log.Printf("\tSubModulesLength: %x\n", p.SubModulesLength)

	for iSubmodule := 0; (iSubmodule < int(p.SubModulesLength)) && (len(data[lenPacket:]) > 14); iSubmodule++ {
		api := &ProfinetIOSubmodule{}
		lenSubmodule, err := api.DecodeFromBytes(data[lenPacket:], df)
		if err != nil {
			log.Println("cannot decode API block")
			break
		}
		lenPacket = lenPacket + lenSubmodule
	}

	return lenPacket, nil
}

type ProfinetIOSubmodule struct {
	SubslotNumber        uint16
	SubmoduleIdentNumber uint32
	SubmoduleProperties  uint16
	DataDescription      ProfinetIODataDescription
}

func (p *ProfinetIOSubmodule) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) (int, error) {
	// length without header
	if len(data) < 14 {
		return 0, errors.New("Malformed ProfinetIOSubmodule")
	}

	p.SubslotNumber = binary.BigEndian.Uint16(data[0:2])
	p.SubmoduleIdentNumber = binary.BigEndian.Uint32(data[2:6])
	p.SubmoduleProperties = binary.BigEndian.Uint16(data[6:8])
	p.DataDescription.Type = binary.BigEndian.Uint16(data[10:12])
	p.DataDescription.SubmoduleDataLength = binary.BigEndian.Uint16(data[10:12])
	p.DataDescription.LengthIOCS = data[12]
	p.DataDescription.LengthIOPS = data[13]

	// log.Printf("\t\tSubslotNumber: %x\n", p.SubslotNumber)
	// log.Printf("\t\tSubmoduleIdentNumber: %x\n", p.SubmoduleIdentNumber)

	return 14, nil
}

type ProfinetIODataDescription struct {
	Type                uint16
	SubmoduleDataLength uint16
	LengthIOCS          uint8
	LengthIOPS          uint8
}

type ProfinetIOAlarmCRBlockReq struct {
	BlockHeader          ProfinetIOBlockHeader
	AlarmCRType          uint16
	LT                   uint16
	Properties           uint32
	RTATimeoutFactor     uint16
	RTARetries           uint16
	LocalAlarmReference  uint16
	MaxAlarmDataLength   uint16
	AlarmCRTagHeaderHigh uint16
	AlarmCRTagHeaderLow  uint16
}

func (p *ProfinetIOAlarmCRBlockReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// length without header
	if len(data) < 20 {
		return errors.New("Malformed ProfinetIOAlarmCRBlockReq")
	}

	p.AlarmCRType = binary.LittleEndian.Uint16(data[0:2])
	p.LT = binary.LittleEndian.Uint16(data[2:4])
	p.Properties = binary.LittleEndian.Uint32(data[4:8])
	p.RTATimeoutFactor = binary.LittleEndian.Uint16(data[8:10])
	p.RTARetries = binary.LittleEndian.Uint16(data[10:12])
	p.LocalAlarmReference = binary.LittleEndian.Uint16(data[12:14])
	p.MaxAlarmDataLength = binary.LittleEndian.Uint16(data[14:16])
	p.AlarmCRTagHeaderHigh = binary.LittleEndian.Uint16(data[16:18])
	p.AlarmCRTagHeaderLow = binary.LittleEndian.Uint16(data[18:20])

	return nil
}

type ProfinetIOART struct {
	ARUUID        []byte
	InputFrameID  uint16
	OutputFrameID uint16

	MAC      []byte
	AlarmRef uint16
	ARType   uint16 // device only
}

type ProfinetIOARBlockRes struct {
	BlockHeader          ProfinetIOBlockHeader
	ARType               uint16
	ARUUID               []byte // 16 byte
	SessionKey           uint16
	CMResponderMacAdd    net.HardwareAddr // 6 byte
	CMResponderUDPRTPort uint16
	// Params               []ProfinetIOART
	DataHack []byte
}

func (r *ProfinetIOARBlockRes) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	lenPacket := 28 + len(r.DataHack)
	bytes, err := b.PrependBytes(lenPacket)
	if err != nil {
		return lenPacket, err
	}
	binary.BigEndian.PutUint16(bytes[0:2], r.ARType)
	copy(bytes[2:18], r.ARUUID)
	binary.BigEndian.PutUint16(bytes[18:20], r.SessionKey)
	copy(bytes[20:26], r.CMResponderMacAdd)
	binary.BigEndian.PutUint16(bytes[26:28], r.CMResponderUDPRTPort)
	copy(bytes[28:], r.DataHack)

	if opts.FixLengths {
		r.BlockHeader.Length = uint16(lenPacket)
	}
	lenBlock, err := r.BlockHeader.SerializeTo(b, opts)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + lenBlock

	return lenPacket, nil
}

type ProfinetIOIOCRBlockRes struct {
	BlockHeader   ProfinetIOBlockHeader
	IOCRType      uint16
	IOCRReference uint16
	FrameID       uint16
}

func (r *ProfinetIOIOCRBlockRes) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	lenPacket := 6
	bytes, err := b.PrependBytes(lenPacket)
	if err != nil {
		return lenPacket, err
	}
	binary.BigEndian.PutUint16(bytes[0:2], r.IOCRType)
	binary.BigEndian.PutUint16(bytes[2:4], r.IOCRReference)
	binary.BigEndian.PutUint16(bytes[4:6], r.FrameID)

	if opts.FixLengths {
		r.BlockHeader.Length = uint16(lenPacket)
	}
	lenBlock, err := r.BlockHeader.SerializeTo(b, opts)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + lenBlock

	return lenPacket, nil
}

type ProfinetIOAlarmCRBlockRes struct {
	BlockHeader         ProfinetIOBlockHeader
	AlarmCRType         uint16
	LocalAlarmReference uint16
	MaxAlarmDataLength  uint16
}

func (r *ProfinetIOAlarmCRBlockRes) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	lenPacket := 6
	bytes, err := b.PrependBytes(lenPacket)
	if err != nil {
		return lenPacket, err
	}
	binary.BigEndian.PutUint16(bytes[0:2], r.AlarmCRType)
	binary.BigEndian.PutUint16(bytes[2:4], r.LocalAlarmReference)
	binary.BigEndian.PutUint16(bytes[4:6], r.MaxAlarmDataLength)

	if opts.FixLengths {
		r.BlockHeader.Length = uint16(lenPacket)
	}
	lenBlock, err := r.BlockHeader.SerializeTo(b, opts)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + lenBlock

	return lenPacket, nil
}

type ProfinetIOModuleDiffBlock struct {
	BlockHeader  ProfinetIOBlockHeader
	NumberOfAPIs uint16
	APIs         []ProfinetIOIOCAPI
}

func (r *ProfinetIOModuleDiffBlock) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	lenPacket := 0
	for _, t := range r.APIs {
		lenBlock, err := t.SerializeTo(b, opts)
		if err != nil {
			return 0, err
		}
		lenPacket = lenPacket + lenBlock
	}

	bytes, err := b.PrependBytes(2)
	if err != nil {
		return lenPacket, err
	}
	if opts.FixLengths {
		r.NumberOfAPIs = uint16(len(r.APIs))
	}
	binary.BigEndian.PutUint16(bytes[0:2], r.NumberOfAPIs)

	if opts.FixLengths {
		// + 2 for NumberOfAPIs
		r.BlockHeader.Length = uint16(lenPacket + 2)
	}
	lenBlock, err := r.BlockHeader.SerializeTo(b, opts)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + lenBlock

	return lenPacket, nil
}

type ProfinetIOIOCAPI struct {
	API             uint32
	NumberOfModules uint16
	// TODO some fields are missing here :/
}

func (t *ProfinetIOIOCAPI) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	bytes, err := b.PrependBytes(6)
	if err != nil {
		return 6, err
	}

	// IMPORTANT header length is set outside
	// TODO
	if opts.FixLengths {
		// TODO how to get length here?
	}

	binary.BigEndian.PutUint32(bytes[0:4], t.API)
	binary.BigEndian.PutUint16(bytes[4:6], t.NumberOfModules)

	return 6, nil
}

func (r *ProfinetIO) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	lenPacket := 0

	if r.ModuleDiffBlock != nil {
		lenBlock, err := r.ModuleDiffBlock.SerializeTo(b, opts)
		if err != nil {
			return err
		}
		lenPacket = lenPacket + lenBlock
	}

	for _, t := range r.AlarmCRBlockRess {
		lenBlock, err := t.SerializeTo(b, opts)
		if err != nil {
			return err
		}
		lenPacket = lenPacket + lenBlock
	}

	for _, t := range r.IOCRBlockRess {
		lenBlock, err := t.SerializeTo(b, opts)
		if err != nil {
			return err
		}
		lenPacket = lenPacket + lenBlock
	}

	for _, t := range r.ARBlockRess {
		lenBlock, err := t.SerializeTo(b, opts)
		if err != nil {
			return err
		}
		lenPacket = lenPacket + lenBlock
	}

	if r.IODWriteResHeader != nil {
		lenBlock, err := r.IODWriteResHeader.SerializeTo(b, opts)
		if err != nil {
			return err
		}
		lenPacket = lenPacket + lenBlock
	}

	if r.IODControlReq != nil {
		lenBlock, err := r.IODControlReq.SerializeTo(b, opts)
		if err != nil {
			return err
		}
		lenPacket = lenPacket + lenBlock
	}

	if opts.FixLengths {
		r.ArgsLength = uint32(lenPacket)
		r.ArrayOffset = 0
		r.ArrayActualCount = uint32(lenPacket)
	}

	bytes, err := b.PrependBytes(20)
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint32(bytes[0:4], r.ArgsMaximum)
	binary.BigEndian.PutUint32(bytes[4:8], r.ArgsLength)
	binary.BigEndian.PutUint32(bytes[8:12], r.ArrayMaximumCount)
	binary.BigEndian.PutUint32(bytes[12:16], r.ArrayOffset)
	binary.BigEndian.PutUint32(bytes[16:20], r.ArrayActualCount)

	// testing
	r.Contents = bytes

	return nil
}

func (p *ProfinetIO) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// assertion, if data is too small
	if len(data) < 20 {
		return errors.New("Malformed Profinet IO Packet")
	}

	p.ArgsMaximum = binary.LittleEndian.Uint32(data[0:4])
	p.ArgsLength = binary.LittleEndian.Uint32(data[4:8])
	p.ArrayMaximumCount = binary.LittleEndian.Uint32(data[8:12])
	p.ArrayOffset = binary.LittleEndian.Uint32(data[12:16])
	p.ArrayActualCount = binary.LittleEndian.Uint32(data[16:20])

	// decode blocks
	numBytes := int(p.ArrayActualCount)
	for numBytes > 0 {
		offset := 20 + (int(p.ArrayActualCount) - numBytes)

		blockHeader := &ProfinetIOBlockHeader{}
		err := blockHeader.DecodeFromBytes(data[offset:], df)
		if err != nil {
			return err
		}

		// log.Printf("BlockHeader.Type: %x\n", blockHeader.Type)

		switch blockHeader.Type {
		case ProfinetIOBlockHeaderTypeARBlockReq:
			b := &ProfinetIOARBlockReq{}
			err := b.DecodeFromBytes(data[offset+6:], df)
			if err != nil {
				return err
			}
			b.BlockHeader = *blockHeader
			p.ARBlockReqs = append(p.ARBlockReqs, *b)
		case ProfinetIOBlockHeaderTypeIOCRBlockReq:
			b := &ProfinetIOIOCRBlockReq{}
			err := b.DecodeFromBytes(data[offset+6:], df)
			if err != nil {
				return err
			}
			b.BlockHeader = *blockHeader
			p.IOCRBlockReqs = append(p.IOCRBlockReqs, *b)
		case ProfinetIOBlockHeaderTypeAlarmCRBlockReq:
			b := &ProfinetIOAlarmCRBlockReq{}
			err := b.DecodeFromBytes(data[offset+6:], df)
			if err != nil {
				return err
			}
			b.BlockHeader = *blockHeader
			p.AlarmCRBlockReqs = append(p.AlarmCRBlockReqs, *b)
		case ProfinetIOBlockHeaderTypeExpectedSubmoduleBlockReq:
			b := &ProfinetIOExpectedSubmoduleBlockReq{}
			err := b.DecodeFromBytes(data[offset+6:], df)
			if err != nil {
				return err
			}
			b.BlockHeader = *blockHeader
			p.ExpectedSubmoduleBlockReqs = append(p.ExpectedSubmoduleBlockReqs, *b)
		case ProfinetIOBlockHeaderTypeIODControlReq, ProfinetIOBlockHeaderTypeReleaseReq:
			b := &ProfinetIOIODControlReq{}
			err := b.DecodeFromBytes(data[offset+6:], df)
			if err != nil {
				return err
			}
			b.BlockHeader = *blockHeader
			p.IODControlReq = b
		case ProfinetIOBlockHeaderTypeIODWriteReqHeader:
			b := &ProfinetIOIODWriteReqHeader{}
			err := b.DecodeFromBytes(data[offset:], df)
			if err != nil {
				return err
			}
			b.BlockHeader = *blockHeader
			p.IODWriteReqHeader = b

			// no more data following this block
			numBytes = 0
		default:
			log.Printf("unknown header %x", blockHeader.Type)
			return errors.New("unknown block header type: 0x" + strconv.FormatInt(int64(blockHeader.Type), 16))
		}

		// remaining number of bytes
		numBytes = numBytes - int(blockHeader.Length) - 4
	}

	return nil
}

func decodeProfinetIO(data []byte, p gopacket.PacketBuilder) error {
	d := &ProfinetIO{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(d)

	return nil
}
