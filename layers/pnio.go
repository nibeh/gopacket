package layers

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"strconv"

	"github.com/google/gopacket"
)

func PNIODCERPCDeviceInterfaceID() []byte {
	// TODO big or little endian
	return []byte{0xde, 0xa0, 0x00, 0x01, 0x6c, 0x97, 0x11, 0xd1, 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d}
}

func PNIODCERPCControllerInterfaceID() []byte {
	// TODO big or little endian
	return []byte{0xde, 0xa0, 0x00, 0x02, 0x6c, 0x97, 0x11, 0xd1, 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d}
}

func PNIODCERPCObjectID(nodeNumber, deviceID, vendorID uint16) []byte {
	// TODO big or little endian
	// DEA00000-6C97-11D1-8271-XXXXYYYYZZZZ (X: Node Number, Y: DeviceID, Z: VendorID)
	objectID := []byte{0xde, 0xa0, 0x00, 0x00, 0x6c, 0x97, 0x11, 0xd1, 0x82, 0x71, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint16(objectID[10:], nodeNumber)
	binary.BigEndian.PutUint16(objectID[12:], deviceID)
	binary.BigEndian.PutUint16(objectID[14:], vendorID)

	return objectID
}

type ProfinetIO struct {
	BaseLayer
	ArgsMaximum       uint32 // or status
	ArgsLength        uint32
	ArrayMaximumCount uint32
	ArrayOffset       uint32
	ArrayActualCount  uint32

	// requests - TODO missing: PrmServerBlock, MCRBlockReq, ARRPCBlockReq (+ others)
	ARBlockReq                 *PNIOARBlockReq
	IOCRBlockReqs              []PNIOIOCRBlockReq
	ExpectedSubmoduleBlockReqs []PNIOExpectedSubmoduleBlockReq
	AlarmCRBlockReqs           []PNIOAlarmCRBlockReq
	IODWriteReqs               []PNIOIODWriteReq
	IODReadReq                 *PNIOIODReadReq
	IODControlReq              *PNIOIODControlReq
	// IOXBlockReq                *PNIOIOXBlockReq

	// responses
	ARBlockRes       *PNIOARBlockRes
	IOCRBlockRess    []PNIOIOCRBlockRes
	ModuleDiffBlock  *PNIOModuleDiffBlock
	AlarmCRBlockRess []PNIOAlarmCRBlockRes
	ARServerRes      *PNIOARRPCServerBlockRes
	IODWriteRess     []PNIOIODWriteResHeader
	// IODControlRes
}

func (p ProfinetIO) LayerType() gopacket.LayerType { return LayerTypeProfinetIO }

type PNIOBlockHeaderType uint16

const (
	PNIOBlockHeaderAlarmNotificationHigh PNIOBlockHeaderType = 0x0001
	PNIOBlockHeaderAlarmNotificationLow  PNIOBlockHeaderType = 0x0002

	PNIOBlockHeaderIODWriteReqHeader PNIOBlockHeaderType = 0x0008
	PNIOBlockHeaderIODReadReqHeader  PNIOBlockHeaderType = 0x0009

	PNIOBlockHeaderDiagnosisData PNIOBlockHeaderType = 0x0010

	PNIOBlockHeaderExpectedIdentificationData PNIOBlockHeaderType = 0x0012
	PNIOBlockHeaderRealIdentificationData     PNIOBlockHeaderType = 0x0013
	PNIOBlockHeaderSubstituteValue            PNIOBlockHeaderType = 0x0014
	PNIOBlockHeaderRecordInputDataObject      PNIOBlockHeaderType = 0x0015
	PNIOBlockHeaderRecordOutputDataObject     PNIOBlockHeaderType = 0x0016

	PNIOBlockHeaderARData      PNIOBlockHeaderType = 0x0018
	PNIOBlockHeaderLogBookData PNIOBlockHeaderType = 0x0019
	PNIOBlockHeaderAPIData     PNIOBlockHeaderType = 0x001A
	PNIOBlockHeaderSRLData     PNIOBlockHeaderType = 0x001B

	PNIOBlockHeaderIM0  PNIOBlockHeaderType = 0x0020
	PNIOBlockHeaderIM1  PNIOBlockHeaderType = 0x0021
	PNIOBlockHeaderIM2  PNIOBlockHeaderType = 0x0022
	PNIOBlockHeaderIM3  PNIOBlockHeaderType = 0x0023
	PNIOBlockHeaderIM4  PNIOBlockHeaderType = 0x0024
	PNIOBlockHeaderIM5  PNIOBlockHeaderType = 0x0025
	PNIOBlockHeaderIM6  PNIOBlockHeaderType = 0x0026
	PNIOBlockHeaderIM7  PNIOBlockHeaderType = 0x0027
	PNIOBlockHeaderIM8  PNIOBlockHeaderType = 0x0028
	PNIOBlockHeaderIM9  PNIOBlockHeaderType = 0x0029
	PNIOBlockHeaderIM10 PNIOBlockHeaderType = 0x002a
	PNIOBlockHeaderIM11 PNIOBlockHeaderType = 0x002b
	PNIOBlockHeaderIM12 PNIOBlockHeaderType = 0x002c
	PNIOBlockHeaderIM13 PNIOBlockHeaderType = 0x002d
	PNIOBlockHeaderIM14 PNIOBlockHeaderType = 0x002e
	PNIOBlockHeaderIM15 PNIOBlockHeaderType = 0x002f

	PNIOBlockHeaderIM0FilterDataSubmodule PNIOBlockHeaderType = 0x0030
	PNIOBlockHeaderIM0FilterDataModule    PNIOBlockHeaderType = 0x0031
	PNIOBlockHeaderIM0FilterDataDevice    PNIOBlockHeaderType = 0x0032

	PNIOBlockHeaderARBlockReq             PNIOBlockHeaderType = 0x0101
	PNIOBlockHeaderIOCRBlockReq           PNIOBlockHeaderType = 0x0102
	PNIOBlockHeaderAlarmCRBlockReq        PNIOBlockHeaderType = 0x0103
	PNIOBlockHeaderExpectedSubmoduleBlock PNIOBlockHeaderType = 0x0104
	PNIOBlockHeaderPRMServerReq           PNIOBlockHeaderType = 0x0105
	PNIOBlockHeaderMCRReq                 PNIOBlockHeaderType = 0x0106
	PNIOBlockHeaderRPCServerReq           PNIOBlockHeaderType = 0x0107
	PNIOBlockHeaderARVendorBlockReq       PNIOBlockHeaderType = 0x0108
	PNIOBlockHeaderIRInfoBlockReq         PNIOBlockHeaderType = 0x0109
	PNIOBlockHeaderSRInfoBlockReq         PNIOBlockHeaderType = 0x010A
	PNIOBlockHeaderARFSUBlockReq          PNIOBlockHeaderType = 0x010B
	PNIOBlockHeaderRSInfoBlockReq         PNIOBlockHeaderType = 0x010C

	PNIOBlockHeaderPRMEndReq            PNIOBlockHeaderType = 0x0110 // IODControl
	PNIOBlockHeaderPRMPlugAlarmReq      PNIOBlockHeaderType = 0x0111
	PNIOBlockHeaderAppRdyReq            PNIOBlockHeaderType = 0x0112
	PNIOBlockHeaderAppRdyPlugAlarmReq   PNIOBlockHeaderType = 0x0113
	PNIOBlockHeaderReleaseBlockReq      PNIOBlockHeaderType = 0x0114
	PNIOBlockHeaderXControlRdyCompReq   PNIOBlockHeaderType = 0x0116
	PNIOBlockHeaderXControlRdyRTC3Req   PNIOBlockHeaderType = 0x0117
	PNIOBlockHeaderPRMBeginReq          PNIOBlockHeaderType = 0x0118
	PNIOBlockHeaderSubmodulePRMBeginReq PNIOBlockHeaderType = 0x0119

	PNIOBlockHeaderPDInterfaceAdjust PNIOBlockHeaderType = 0x0250

	PNIOBlockHeaderAlarmAckHigh PNIOBlockHeaderType = 0x8001
	PNIOBlockHeaderAlarmAckLow  PNIOBlockHeaderType = 0x8002

	PNIOBlockHeaderIODWriteRes PNIOBlockHeaderType = 0x8008
	PNIOBlockHeaderIODReadRes  PNIOBlockHeaderType = 0x8009

	PNIOBlockHeaderARBlockRes        PNIOBlockHeaderType = 0x8101
	PNIOBlockHeaderIOCRBlockRes      PNIOBlockHeaderType = 0x8102
	PNIOBlockHeaderAlarmCRBlockRes   PNIOBlockHeaderType = 0x8103
	PNIOBlockHeaderModuleDiffBlock   PNIOBlockHeaderType = 0x8104
	PNIOBlockHeaderPRMServerBlockRes PNIOBlockHeaderType = 0x8105
	PNIOBlockHeaderARServerBlock     PNIOBlockHeaderType = 0x8106
	PNIOBlockHeaderARRPCBlockRes     PNIOBlockHeaderType = 0x8107
	PNIOBlockHeaderARVendorBlockRes  PNIOBlockHeaderType = 0x8108

	PNIOBlockHeaderPRMEndRes           PNIOBlockHeaderType = 0x8110
	PNIOBlockHeaderPRMEndPlugAlarmRes  PNIOBlockHeaderType = 0x8110
	PNIOBlockHeaderAppRdyRes           PNIOBlockHeaderType = 0x8110
	PNIOBlockHeaderAppRedyPlugAlarmRes PNIOBlockHeaderType = 0x8110
	PNIOBlockHeaderReleaseBlockRes     PNIOBlockHeaderType = 0x8110
)

type PNIOBlockHeader struct {
	Type        PNIOBlockHeaderType
	Length      uint16
	VersionHigh uint8
	VersionLow  uint8
}

func NewPNIOBlockHeader(t PNIOBlockHeaderType) PNIOBlockHeader {
	return PNIOBlockHeader{Type: t, VersionHigh: 0x01, VersionLow: 0x00}
}

func (h *PNIOBlockHeader) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 6 {
		return errors.New("PNIOBlockHeader too small")
	}

	h.Type = PNIOBlockHeaderType(binary.BigEndian.Uint16(data[0:2]))
	h.Length = binary.BigEndian.Uint16(data[2:4])
	h.VersionHigh = uint8(data[4])
	h.VersionLow = uint8(data[5])

	return nil
}

func (h *PNIOBlockHeader) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
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

type PNIOARBlockReq struct {
	BlockHeader                      PNIOBlockHeader
	ARType                           uint16
	ARUUID                           []byte // 16 byte
	SessionKey                       uint16
	CMInitiatorMac                   net.HardwareAddr // 6 byte
	CMInitiatorObjectUUID            []byte           // 16 byte
	ARProperties                     uint32
	CMInitiatorActivityTimeoutFactor uint16
	CMInitiatorUDPRTPort             uint16
	CMInitiatorStationNameLength     uint16
	CMInitiatorStationName           string
}

func (p *PNIOARBlockReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// length without header
	if len(data) < 50 {
		return errors.New("Malformed PNIOARBlockReq")
	}

	p.ARType = binary.BigEndian.Uint16(data[0:2])
	p.ARUUID = make([]byte, 16)
	copy(p.ARUUID, data[2:18])
	p.SessionKey = binary.BigEndian.Uint16(data[18:20])
	p.CMInitiatorMac = make([]byte, 6)
	copy(p.CMInitiatorMac, data[20:26])
	p.CMInitiatorObjectUUID = make([]byte, 16)
	copy(p.CMInitiatorObjectUUID, data[26:42])
	p.ARProperties = binary.BigEndian.Uint32(data[42:46])
	p.CMInitiatorActivityTimeoutFactor = binary.BigEndian.Uint16(data[46:48])
	p.CMInitiatorUDPRTPort = binary.BigEndian.Uint16(data[48:50])
	p.CMInitiatorStationNameLength = binary.BigEndian.Uint16(data[50:52])
	p.CMInitiatorStationName = string(data[50 : 50+p.CMInitiatorStationNameLength])

	return nil
}

type PNIOIODControlCmd uint16

const (
	PNIOIODControlCmdPrmEnd          PNIOIODControlCmd = 1 << 0
	PNIOIODControlCmdAppRdy          PNIOIODControlCmd = 1 << 1
	PNIOIODControlCmdRelease         PNIOIODControlCmd = 1 << 2
	PNIOIODControlCmdDone            PNIOIODControlCmd = 1 << 3
	PNIOIODControlCmdRdyForCompanion PNIOIODControlCmd = 1 << 4
	PNIOIODControlCmdRdyForRTC3      PNIOIODControlCmd = 1 << 5
	PNIOIODControlCmdPrmBegin        PNIOIODControlCmd = 1 << 6
)

// used as request and response
type PNIOIODControlReq struct {
	BlockHeader            PNIOBlockHeader
	ARUUID                 []byte
	SessionKey             uint16
	ControlCommand         PNIOIODControlCmd
	ControlBlockProperties uint16
}

func NewPNIOIODControlResFromReq(req *PNIOIODControlReq) (res PNIOIODControlReq) {
	res.BlockHeader = NewPNIOBlockHeader(PNIOBlockHeaderPRMEndRes)
	res.ARUUID = make([]byte, 16)
	copy(res.ARUUID, req.ARUUID)
	res.SessionKey = req.SessionKey
	// res.ControlCommand =         cmd
	// res.ControlBlockProperties = 0x0000

	return res
}

func (p *PNIOIODControlReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// length without header
	if len(data) < 26 {
		return errors.New("Malformed PNIOIODControlReq")
	}

	// 2 bytes reserved
	p.ARUUID = make([]byte, 16)
	copy(p.ARUUID, data[2:18])
	p.SessionKey = binary.BigEndian.Uint16(data[18:20])
	// 2 bytes reserved
	p.ControlCommand = PNIOIODControlCmd(binary.BigEndian.Uint16(data[22:24]))
	p.ControlBlockProperties = binary.BigEndian.Uint16(data[24:26])

	return nil
}

func (r *PNIOIODControlReq) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	lenPacket := 26
	bytes, err := b.PrependBytes(lenPacket)
	if err != nil {
		return lenPacket, err
	}

	// 2 bytes reserved
	copy(bytes[2:18], r.ARUUID)
	binary.BigEndian.PutUint16(bytes[18:20], r.SessionKey)
	// 2 bytes reserved
	binary.BigEndian.PutUint16(bytes[22:24], uint16(r.ControlCommand))
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

// type PNIOIOXBlockReq struct {
// 	Header PNIOBlockHeader
// 	// 2 Byte Padding
// 	ARUUID []byte
// 	SessionKey uint16
// 	// 2 Byte Padding

// }

type MultipleInterfaceModeNameOfDeviceValue bool

const (
	LLDPPortIDContainNameOfPort                 MultipleInterfaceModeNameOfDeviceValue = false
	LLDPPortIDContainNameOfPortAndNameOfStation MultipleInterfaceModeNameOfDeviceValue = true
)

type PNIOPDInterfaceAdjust struct {
	Header                            PNIOBlockHeader
	MultipleInterfaceModeNameOfDevice MultipleInterfaceModeNameOfDeviceValue
}

func (p *PNIOPDInterfaceAdjust) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// length WITH header
	if len(data) < 12 {
		return errors.New("PNIOPDInterfaceAdjust too small")
	}

	// redecode block header, because length is needed here TODO
	header := &PNIOBlockHeader{}
	err := header.DecodeFromBytes(data, df)
	if err != nil {
		return err
	}

	if header.Type != PNIOBlockHeaderPDInterfaceAdjust {
		return errors.New("BlockHeaderType mismatch")
	}
	if header.Length != 8 {
		return errors.New("BlockHeaderLength mismatch")
	}
	if header.VersionHigh != 1 {
		return errors.New("BlockHeaderVersion mismatch")
	}

	// 2 byte padding
	p.Header = *header
	p.MultipleInterfaceModeNameOfDevice = MultipleInterfaceModeNameOfDeviceValue(data[11]&0x01 > 0)

	return nil
}

type PNIOIODReadWriteReqHeader struct {
	BlockHeader      PNIOBlockHeader
	SeqNumber        uint16
	ARUUID           []byte
	API              uint32
	SlotNumber       uint16
	SubSlotNumber    uint16
	Index            PNIOIODReadWriteReqHeaderIndex
	RecordDataLength uint32
}

type PNIOIODReadWriteReqHeaderIndex uint16

const (
	PNIOIODReadWriteReqPDInterfaceAdjust PNIOIODReadWriteReqHeaderIndex = 0x8071
	PNIOIODWriteMultipleWrite            PNIOIODReadWriteReqHeaderIndex = 0xe040
)

type PNIOIODReadReq struct {
	Header PNIOIODReadWriteReqHeader
	// ReccordDataReadQuery TODO
}

func (p *PNIOIODReadReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) (int, error) {
	// length WITH header
	if len(data) < 64 {
		return 0, errors.New("PNIOIODReadReq too small")
	}

	// redecode block header, because length is needed here TODO
	blockHeader := &PNIOBlockHeader{}
	err := blockHeader.DecodeFromBytes(data[0:], df)
	if err != nil {
		return 0, err
	}
	p.Header.BlockHeader = *blockHeader

	p.Header.SeqNumber = binary.BigEndian.Uint16(data[6:8])
	p.Header.ARUUID = make([]byte, 16)
	copy(p.Header.ARUUID, data[8:24])
	p.Header.API = binary.BigEndian.Uint32(data[24:28])
	p.Header.SlotNumber = binary.BigEndian.Uint16(data[28:30])
	p.Header.SubSlotNumber = binary.BigEndian.Uint16(data[30:32])
	// 2 byte padding
	p.Header.Index = PNIOIODReadWriteReqHeaderIndex(binary.BigEndian.Uint16(data[34:36]))
	p.Header.RecordDataLength = binary.BigEndian.Uint32(data[36:40])
	// 24 byte padding

	// TODO recorddatareadqueries

	return 64, nil
}

type PNIOIODWriteReq struct {
	Header     PNIOIODReadWriteReqHeader
	RecordData []byte
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

func (p *PNIOIODWriteReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) (int, error) {
	// length WITH header
	if len(data) < 64 {
		return 0, errors.New("PNIOIODWriteReq too small")
	}

	// redecode block header, because length is needed here TODO
	blockHeader := &PNIOBlockHeader{}
	err := blockHeader.DecodeFromBytes(data[0:], df)
	if err != nil {
		return 0, err
	}
	p.Header.BlockHeader = *blockHeader

	p.Header.SeqNumber = binary.BigEndian.Uint16(data[6:8])
	p.Header.ARUUID = make([]byte, 16)
	copy(p.Header.ARUUID, data[8:24])
	p.Header.API = binary.BigEndian.Uint32(data[24:28])
	p.Header.SlotNumber = binary.BigEndian.Uint16(data[28:30])
	p.Header.SubSlotNumber = binary.BigEndian.Uint16(data[30:32])
	// 2 byte padding
	p.Header.Index = PNIOIODReadWriteReqHeaderIndex(binary.BigEndian.Uint16(data[34:36]))
	p.Header.RecordDataLength = binary.BigEndian.Uint32(data[36:40])
	// 24 byte padding

	numBytesDecoded := int(p.Header.BlockHeader.Length) + 4
	if p.Header.Index != PNIOIODWriteMultipleWrite {
		// clip maximum record data length
		arrayLen := Min(int64(p.Header.RecordDataLength), int64(128))
		// log.Printf("record data has length %d and starts after %d byte", arrayLen, p.BlockHeader.Length)
		p.RecordData = make([]byte, arrayLen)
		copy(p.RecordData, data[numBytesDecoded:numBytesDecoded+int(arrayLen)])
		numBytesDecoded = numBytesDecoded + int(arrayLen)
	}

	return numBytesDecoded, nil
}

type PNIOIODWriteResHeader struct {
	BlockHeader      PNIOBlockHeader
	SeqNumber        uint16
	ARUUID           []byte
	API              uint32
	SlotNumber       uint16
	SubSlotNumber    uint16
	Index            PNIOIODReadWriteReqHeaderIndex
	RecordDataLength uint32
	AdditionalValue1 uint16
	AdditionalValue2 uint16
	Status           uint32
}

func NewPNIOIODWriteResFromReq(req *PNIOIODReadWriteReqHeader) (res PNIOIODWriteResHeader) {
	res.BlockHeader = NewPNIOBlockHeader(PNIOBlockHeaderIODWriteRes)
	res.SeqNumber = req.SeqNumber
	res.ARUUID = make([]byte, 16)
	copy(res.ARUUID, req.ARUUID) // TODO get from handler
	res.API = req.API
	res.SlotNumber = req.SlotNumber
	res.SubSlotNumber = req.SubSlotNumber
	res.Index = req.Index
	res.RecordDataLength = req.RecordDataLength
	res.AdditionalValue1 = 0
	res.AdditionalValue2 = 0
	res.Status = 0 // 0 = success

	return res
}

func (r *PNIOIODWriteResHeader) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
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
	binary.BigEndian.PutUint16(bytes[28:30], uint16(r.Index))
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

type PNIOIOCRBlockReq struct {
	BlockHeader           PNIOBlockHeader
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

func (p *PNIOIOCRBlockReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// length without header
	if len(data) < 48 {
		return errors.New("Malformed PNIOARBlockReq")
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

type PNIOExpectedSubmoduleBlockReq struct {
	BlockHeader  PNIOBlockHeader
	NumberOfAPIs uint16
	APIs         []ProfinetIOSubmoduleAPI
}

func (p *PNIOExpectedSubmoduleBlockReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// length without header
	if len(data) < 2 {
		return errors.New("Malformed PNIOExpectedSubmoduleBlockReq")
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

type PNIOAlarmCRBlockReq struct {
	BlockHeader          PNIOBlockHeader
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

func (p *PNIOAlarmCRBlockReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// length without header
	if len(data) < 20 {
		return errors.New("Malformed PNIOAlarmCRBlockReq")
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

type PNIOARBlockRes struct {
	BlockHeader          PNIOBlockHeader
	ARType               uint16
	ARUUID               []byte // 16 byte
	SessionKey           uint16
	CMResponderMacAdd    net.HardwareAddr // 6 byte
	CMResponderUDPRTPort uint16
	// Params               []ProfinetIOART
	DataHack []byte
}

func (r *PNIOARBlockRes) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
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

type PNIOIOCRBlockRes struct {
	BlockHeader   PNIOBlockHeader
	IOCRType      uint16
	IOCRReference uint16
	FrameID       uint16
}

func (r *PNIOIOCRBlockRes) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
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

type PNIOAlarmCRBlockRes struct {
	BlockHeader         PNIOBlockHeader
	AlarmCRType         uint16
	LocalAlarmReference uint16
	MaxAlarmDataLength  uint16
}

func (r *PNIOAlarmCRBlockRes) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
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

type PNIOModuleDiffBlock struct {
	BlockHeader  PNIOBlockHeader
	NumberOfAPIs uint16
	APIs         []ProfinetIOIOCAPI
}

func (r *PNIOModuleDiffBlock) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	lenPacket := 0
	for _, t := range r.APIs {
		lenBlock, err := t.SerializeTo(b, opts)
		if err != nil {
			return 0, err
		}
		lenPacket = lenPacket + lenBlock
	}

	lenPacket = lenPacket + 2
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
		r.BlockHeader.Length = uint16(lenPacket)
	}
	lenBlock, err := r.BlockHeader.SerializeTo(b, opts)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + lenBlock

	return lenPacket, nil
}

type PNIOARRPCServerBlockRes struct {
	BlockHeader            PNIOBlockHeader
	CMInitiatorStationName string
}

func (r *PNIOARRPCServerBlockRes) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	lenPacket := 2 + len(r.CMInitiatorStationName)
	bytes, err := b.PrependBytes(lenPacket)
	if err != nil {
		return lenPacket, err
	}

	binary.BigEndian.PutUint16(bytes[0:], uint16(len(r.CMInitiatorStationName)))
	copy(bytes[2:], r.CMInitiatorStationName)

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

	if r.ARServerRes != nil {
		lenBlock, err := r.ARServerRes.SerializeTo(b, opts)
		if err != nil {
			return err
		}
		lenPacket = lenPacket + lenBlock
	}

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

	for i := len(r.IOCRBlockRess) - 1; i >= 0; i-- {
		lenBlock, err := r.IOCRBlockRess[i].SerializeTo(b, opts)
		if err != nil {
			return err
		}
		lenPacket = lenPacket + lenBlock
	}

	if r.ARBlockRes != nil {
		lenBlock, err := r.ARBlockRes.SerializeTo(b, opts)
		if err != nil {
			return err
		}
		lenPacket = lenPacket + lenBlock
	}

	for i := len(r.IODWriteRess) - 1; i >= 0; i-- {
		lenBlock, err := r.IODWriteRess[i].SerializeTo(b, opts)
		if err != nil {
			return err
		}
		lenPacket = lenPacket + lenBlock
	}
	if len(r.IODWriteRess) > 1 {
		block := &PNIOIODWriteResHeader{
			BlockHeader:   NewPNIOBlockHeader(PNIOBlockHeaderIODWriteRes),
			SeqNumber:     0,
			ARUUID:        make([]byte, 40),
			API:           0xffffffff,
			SlotNumber:    0xffff,
			SubSlotNumber: 0xffff,
			Index:         PNIOIODWriteMultipleWrite,
		}
		copy(block.ARUUID, r.IODWriteRess[0].ARUUID)

		lenBlock, err := block.SerializeTo(b, opts)
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
		return errors.New("Malformed PN-IO Packet")
	}

	// check for little or big endian - TODO get this previous layer
	if data[0] == 0 {
		p.ArgsMaximum = binary.BigEndian.Uint32(data[0:4])
		p.ArgsLength = binary.BigEndian.Uint32(data[4:8])
		p.ArrayMaximumCount = binary.BigEndian.Uint32(data[8:12])
		p.ArrayOffset = binary.BigEndian.Uint32(data[12:16])
		p.ArrayActualCount = binary.BigEndian.Uint32(data[16:20])
	} else {
		p.ArgsMaximum = binary.LittleEndian.Uint32(data[0:4])
		p.ArgsLength = binary.LittleEndian.Uint32(data[4:8])
		p.ArrayMaximumCount = binary.LittleEndian.Uint32(data[8:12])
		p.ArrayOffset = binary.LittleEndian.Uint32(data[12:16])
		p.ArrayActualCount = binary.LittleEndian.Uint32(data[16:20])
	}

	// decode blocks
	numBytes := int(p.ArrayActualCount)
	for numBytes > 0 {
		offset := 20 + (int(p.ArrayActualCount) - numBytes)

		blockHeader := &PNIOBlockHeader{}
		err := blockHeader.DecodeFromBytes(data[offset:], df)
		if err != nil {
			log.Println("PN-IO Block Header decode error:", err)
			return err
		}

		var numBytesDecoded int
		switch blockHeader.Type {
		case PNIOBlockHeaderARBlockReq:
			b := &PNIOARBlockReq{}
			err = b.DecodeFromBytes(data[offset+6:], df)
			p.ARBlockReq = b
		case PNIOBlockHeaderIOCRBlockReq:
			b := &PNIOIOCRBlockReq{}
			err = b.DecodeFromBytes(data[offset+6:], df)
			p.IOCRBlockReqs = append(p.IOCRBlockReqs, *b)
		case PNIOBlockHeaderAlarmCRBlockReq:
			b := &PNIOAlarmCRBlockReq{}
			err = b.DecodeFromBytes(data[offset+6:], df)
			p.AlarmCRBlockReqs = append(p.AlarmCRBlockReqs, *b)
		case PNIOBlockHeaderExpectedSubmoduleBlock:
			b := &PNIOExpectedSubmoduleBlockReq{}
			err = b.DecodeFromBytes(data[offset+6:], df)
			p.ExpectedSubmoduleBlockReqs = append(p.ExpectedSubmoduleBlockReqs, *b)
		case PNIOBlockHeaderPRMEndReq, PNIOBlockHeaderReleaseBlockReq:
			b := &PNIOIODControlReq{}
			err = b.DecodeFromBytes(data[offset+6:], df)
			p.IODControlReq = b
		case PNIOBlockHeaderIODWriteReqHeader:
			b := &PNIOIODWriteReq{}
			numBytesDecoded, err = b.DecodeFromBytes(data[offset:], df)
			if b.Header.Index != PNIOIODWriteMultipleWrite {
				p.IODWriteReqs = append(p.IODWriteReqs, *b)
			}
		case PNIOBlockHeaderIODReadReqHeader:
			b := &PNIOIODReadReq{}
			numBytesDecoded, err = b.DecodeFromBytes(data[offset:], df)
			p.IODReadReq = b
		default:
			log.Printf("unknown header 0x%x", blockHeader.Type)
			return errors.New("unknown block header type: 0x" + strconv.FormatInt(int64(blockHeader.Type), 16))
		}
		if err != nil {
			log.Println("PN-IO Block Decode error:", err)
			return err
		}

		// TODO quick and dirty hack? ;)
		if numBytesDecoded == 0 {
			numBytesDecoded = int(blockHeader.Length) + 4
		}

		// remaining number of bytes
		numBytes = numBytes - numBytesDecoded
	}

	return nil
}

func decodeProfinetIO(data []byte, p gopacket.PacketBuilder) error {
	d := &ProfinetIO{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		log.Println("PN-IO decoding error:", err)
		return err
	}
	p.AddLayer(d)

	return nil
}
