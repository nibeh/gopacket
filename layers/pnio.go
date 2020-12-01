package layers

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/nibeh/gopacket"
)

func FillWithBlank(d []byte) {
	for i := 0; i < len(d); i++ {
		d[i] = ' '
	}
}

func FillWithBlankString(d []byte, s string) {
	FillWithBlank(d)
	copy(d, s)
}

func PNIODeviceInterfaceID() []byte {
	return []byte{0xde, 0xa0, 0x00, 0x01, 0x6c, 0x97, 0x11, 0xd1, 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d}
}

func PNIOControllerInterfaceID() []byte {
	return []byte{0xde, 0xa0, 0x00, 0x02, 0x6c, 0x97, 0x11, 0xd1, 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d}
}

// PNIOObjectID returns corresponding Object ID (always big endian) in format:
// DEA00000-6C97-11D1-8271-XXXXYYYYZZZZ (X: Node Number, Y: DeviceID, Z: VendorID)
func PNIOObjectID(nodeNumber, deviceID, vendorID uint16) []byte {
	objectID := []byte{0xde, 0xa0, 0x00, 0x00, 0x6c, 0x97, 0x11, 0xd1, 0x82, 0x71, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint16(objectID[10:], nodeNumber)
	binary.BigEndian.PutUint16(objectID[12:], deviceID)
	binary.BigEndian.PutUint16(objectID[14:], vendorID)

	return objectID
}

type PNIOReq struct {
	BaseLayer

	ArgsMaximum       uint32
	ArgsLength        uint32
	ArrayMaximumCount uint32
	ArrayOffset       uint32
	ArrayActualCount  uint32
}

func (p *PNIOReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) (int, error) {
	// assertion, if data is too small
	if len(data) < 20 {
		return 0, errors.New("PNIOReq too short")
	}

	// check for little or big endian - TODO get this previous layer
	littleEndian := data[4] != 0
	if littleEndian {
		p.ArgsMaximum = binary.LittleEndian.Uint32(data[0:4])
		p.ArgsLength = binary.LittleEndian.Uint32(data[4:8])
		p.ArrayMaximumCount = binary.LittleEndian.Uint32(data[8:12])
		p.ArrayOffset = binary.LittleEndian.Uint32(data[12:16])
		p.ArrayActualCount = binary.LittleEndian.Uint32(data[16:20])
	} else {
		p.ArgsMaximum = binary.BigEndian.Uint32(data[0:4])
		p.ArgsLength = binary.BigEndian.Uint32(data[4:8])
		p.ArrayMaximumCount = binary.BigEndian.Uint32(data[8:12])
		p.ArrayOffset = binary.BigEndian.Uint32(data[12:16])
		p.ArrayActualCount = binary.BigEndian.Uint32(data[16:20])
	}

	return 20, nil
}

func (r *PNIOReq) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(20)
	if err != nil {
		return err
	}

	littleEndian := false
	if littleEndian {
		binary.LittleEndian.PutUint32(bytes[0:4], r.ArgsMaximum)
		binary.LittleEndian.PutUint32(bytes[4:8], r.ArgsLength)
		binary.LittleEndian.PutUint32(bytes[8:12], r.ArrayMaximumCount)
		binary.LittleEndian.PutUint32(bytes[12:16], r.ArrayOffset)
		binary.LittleEndian.PutUint32(bytes[16:20], r.ArrayActualCount)
	} else {
		binary.BigEndian.PutUint32(bytes[0:4], r.ArgsMaximum)
		binary.BigEndian.PutUint32(bytes[4:8], r.ArgsLength)
		binary.BigEndian.PutUint32(bytes[8:12], r.ArrayMaximumCount)
		binary.BigEndian.PutUint32(bytes[12:16], r.ArrayOffset)
		binary.BigEndian.PutUint32(bytes[16:20], r.ArrayActualCount)
	}

	return nil
}

type PNIOIODConnectReq struct {
	PNIOReq
	ARBlockReq                 *PNIOARBlockReq
	IOCRBlockReqs              []PNIOIOCRBlockReq
	AlarmCRBlockReqs           []PNIOAlarmCRBlockReq
	ExpectedSubmoduleBlockReqs []PNIOExpectedSubmoduleBlockReq
	// TODO missing: []PNIOPrmServerBlock
	// TODO missing: []PNIOMCRBlockReq
	// TODO missing: []PNIOARRPCBlockReq
}

func (p PNIOIODConnectReq) LayerType() gopacket.LayerType { return LayerTypePNIOConnectReq }

func (p *PNIOIODConnectReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	offsetStart, err := p.PNIOReq.DecodeFromBytes(data, df)
	if err != nil {
		log.Println("[decodePNIOConnectReq] PNIOReq.DecodeFromBytes error:", err)
		return err
	}

	// decode blocks
	for numBytesDecoded := 0; numBytesDecoded < int(p.PNIOReq.ArrayActualCount); {
		offset := offsetStart + numBytesDecoded

		blockHeader := &PNIOBlockHeader{}
		err := blockHeader.DecodeFromBytes(data[offset:], df)
		if err != nil {
			log.Println("PNIOBlockHeader.DecodeFromBytes error:", err)
			return err
		}

		switch blockHeader.Type {
		case PNIOBlockHeaderARBlockReq:
			b := &PNIOARBlockReq{}
			err = b.DecodeFromBytes(data[offset:], df)
			p.ARBlockReq = b
		case PNIOBlockHeaderIOCRBlockReq:
			b := &PNIOIOCRBlockReq{}
			err = b.DecodeFromBytes(data[offset:], df)
			p.IOCRBlockReqs = append(p.IOCRBlockReqs, *b)
		case PNIOBlockHeaderAlarmCRBlockReq:
			b := &PNIOAlarmCRBlockReq{}
			err = b.DecodeFromBytes(data[offset:], df)
			p.AlarmCRBlockReqs = append(p.AlarmCRBlockReqs, *b)
		case PNIOBlockHeaderExpectedSubmoduleBlock:
			b := &PNIOExpectedSubmoduleBlockReq{}
			err = b.DecodeFromBytes(data[offset:], df)
			p.ExpectedSubmoduleBlockReqs = append(p.ExpectedSubmoduleBlockReqs, *b)
		default:
			err = errors.New("unhandled block header type: 0x" + strconv.FormatInt(int64(blockHeader.Type), 16))
		}
		if err != nil {
			log.Println("PNIO block DecodeFromBytes error:", err)
			return err
		}

		// blockHeader.Length, + 4 is for block Header without Version
		numBytesDecoded = numBytesDecoded + (int(blockHeader.Length) + 4)
	}

	return nil
}

type PNIOIODWriteReq struct {
	Header     PNIOIODReadWriteReqHeader
	RecordData []byte
}

func (p *PNIOIODWriteReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) (int, error) {
	// length WITH header
	if len(data) < 64 {
		return 0, errors.New("PNIOIODWriteReq too small")
	}

	// decode block header
	err := p.Header.BlockHeader.DecodeFromBytes(data[0:], df)
	if err != nil {
		return 0, err
	}

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
	if p.Header.Index != PNIOIODReadWriteReqWriteMultiple {
		// clip maximum record data length
		arrayLen := Min(int64(p.Header.RecordDataLength), int64(128))
		// log.Printf("record data has length %d and starts after %d byte", arrayLen, p.BlockHeader.Length)
		p.RecordData = make([]byte, arrayLen)
		copy(p.RecordData, data[numBytesDecoded:numBytesDecoded+int(arrayLen)])
		numBytesDecoded = numBytesDecoded + int(arrayLen)
	}

	return numBytesDecoded, nil
}

type PNIOIODWriteMultipleReq struct {
	PNIOReq
	Records []PNIOIODWriteReq
}

func (p PNIOIODWriteMultipleReq) LayerType() gopacket.LayerType { return LayerTypePNIOWriteReq }

func (p *PNIOIODWriteMultipleReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	offsetStart, err := p.PNIOReq.DecodeFromBytes(data, df)
	if err != nil {
		log.Println("[decodePNIOConnectReq] PNIOReq.DecodeFromBytes error:", err)
		return err
	}

	// decode blocks
	for numBytesDecoded := 0; numBytesDecoded < int(p.PNIOReq.ArrayActualCount); {
		offset := offsetStart + numBytesDecoded

		blockHeader := &PNIOBlockHeader{}
		err := blockHeader.DecodeFromBytes(data[offset:], df)
		if err != nil {
			log.Println("PNIOBlockHeader.DecodeFromBytes error:", err)
			return err
		}

		numBytesRecord := int(blockHeader.Length) + 4
		switch blockHeader.Type {
		case PNIOBlockHeaderIODWriteReqHeader:
			b := PNIOIODWriteReq{}
			numBytesRecord, err = b.DecodeFromBytes(data[offset:], df)
			if b.Header.Index != PNIOIODReadWriteReqWriteMultiple {
				p.Records = append(p.Records, b)
			}
		default:
			err = errors.New("unhandled block header type: 0x" + strconv.FormatInt(int64(blockHeader.Type), 16))
		}
		if err != nil {
			log.Println("PNIO block DecodeFromBytes error:", err)
			return err
		}

		numBytesDecoded = numBytesDecoded + numBytesRecord
	}

	return nil
}

type PNIORecordDataReadQuery struct {
	BlockHeader PNIOBlockHeader
	Data        []byte
}

type PNIOIODReadReq struct {
	PNIOReq
	IODReadReqHeader PNIOIODReadWriteReqHeader
	*PNIORecordDataReadQuery
}

func (p PNIOIODReadReq) LayerType() gopacket.LayerType { return LayerTypePNIOReadReq }

type PNIOControlBlockConnectPlug struct {
	BlockHeader            PNIOBlockHeader
	ARUUID                 []byte
	SessionKey             uint16
	ControlCommand         PNIOIODControlCmd
	ControlBlockProperties uint16
}

func (p *PNIOControlBlockConnectPlug) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 32 {
		return errors.New("PNIOControlBlockConnectPlug too short")
	}

	// decode block header
	err := p.BlockHeader.DecodeFromBytes(data[0:], df)
	if err != nil {
		return err
	}

	// 2 bytes reserved
	p.ARUUID = make([]byte, 16)
	copy(p.ARUUID, data[8:24])
	p.SessionKey = binary.BigEndian.Uint16(data[24:26])
	// 2 bytes reserved
	p.ControlCommand = PNIOIODControlCmd(binary.BigEndian.Uint16(data[28:30]))
	p.ControlBlockProperties = binary.BigEndian.Uint16(data[30:32])

	return nil
}

func (r *PNIOControlBlockConnectPlug) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	lenPacket := 26
	bytes, err := b.PrependBytes(lenPacket)
	if err != nil {
		return 0, err
	}

	// 2 byte padding
	copy(bytes[2:18], r.ARUUID)
	binary.BigEndian.PutUint16(bytes[18:20], r.SessionKey)
	// 2 byte padding
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

// used as request and response
type PNIOIODControlReq struct {
	PNIOReq
	PNIOControlBlockConnectPlug
}

func (p PNIOIODControlReq) LayerType() gopacket.LayerType { return LayerTypePNIOControlReq }

func (p *PNIOIODControlReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	offset, err := p.PNIOReq.DecodeFromBytes(data, df)
	if err != nil {
		log.Println("[PNIOIODControlReq.DecodeFromBytes] PNIOReq.DecodeFromBytes error:", err)
		return err
	}

	return p.PNIOControlBlockConnectPlug.DecodeFromBytes(data[offset:], df)
}

func (r *PNIOIODControlReq) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	lenPacket, err := r.PNIOControlBlockConnectPlug.SerializeTo(b, opts)
	if err != nil {
		return err
	}

	if opts.FixLengths {
		r.ArgsLength = uint32(lenPacket)
		r.ArrayOffset = 0
		r.ArrayActualCount = uint32(lenPacket)
	}

	// serialize res header
	return r.PNIOReq.SerializeTo(b, opts)
}

type PNIOIODReleaseReq struct {
	PNIOReq
	ReleaseBlock PNIOReleaseBlock
}

func (p PNIOIODReleaseReq) LayerType() gopacket.LayerType { return LayerTypePNIOReleaseReq }

type PNIORes struct {
	BaseLayer
	Status            uint32
	ArgsLength        uint32
	ArrayMaximumCount uint32
	ArrayOffset       uint32
	ArrayActualCount  uint32
}

func (r *PNIORes) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.PrependBytes(20)
	if err != nil {
		return err
	}

	littleEndian := false
	if littleEndian {
		binary.LittleEndian.PutUint32(bytes[0:4], r.Status)
		binary.LittleEndian.PutUint32(bytes[4:8], r.ArgsLength)
		binary.LittleEndian.PutUint32(bytes[8:12], r.ArrayMaximumCount)
		binary.LittleEndian.PutUint32(bytes[12:16], r.ArrayOffset)
		binary.LittleEndian.PutUint32(bytes[16:20], r.ArrayActualCount)
	} else {
		binary.BigEndian.PutUint32(bytes[0:4], r.Status)
		binary.BigEndian.PutUint32(bytes[4:8], r.ArgsLength)
		binary.BigEndian.PutUint32(bytes[8:12], r.ArrayMaximumCount)
		binary.BigEndian.PutUint32(bytes[12:16], r.ArrayOffset)
		binary.BigEndian.PutUint32(bytes[16:20], r.ArrayActualCount)
	}

	return nil
}

type PNIOIODConnectRes struct {
	PNIORes

	ARBlockRes      *PNIOARBlockRes
	IOCRBlockRes    []PNIOIOCRBlockRes
	AlarmCRBlockRes []PNIOAlarmCRBlockRes
	ModuleDiffBlock []PNIOModuleDiffBlock
	ARRPCBlockRes   []PNIOARRPCBlockRes
}

func (p PNIOIODConnectRes) LayerType() gopacket.LayerType { return LayerTypePNIOConnectRes }

func NewPNIOIODConnectResFromReq(req *PNIOIODConnectReq) (res PNIOIODConnectRes) {
	res.ArrayMaximumCount = req.ArrayMaximumCount

	return res
}

func (r *PNIOIODConnectRes) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	lenPacket := 0

	for _, f := range r.ARRPCBlockRes {
		lenBlock, err := f.SerializeTo(b, opts)
		if err != nil {
			return err
		}
		lenPacket = lenPacket + lenBlock
	}

	for _, f := range r.ModuleDiffBlock {
		lenBlock, err := f.SerializeTo(b, opts)
		if err != nil {
			return err
		}
		lenPacket = lenPacket + lenBlock
	}

	for _, f := range r.AlarmCRBlockRes {
		lenBlock, err := f.SerializeTo(b, opts)
		if err != nil {
			return err
		}
		lenPacket = lenPacket + lenBlock
	}

	for _, f := range r.IOCRBlockRes {
		lenBlock, err := f.SerializeTo(b, opts)
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

	if opts.FixLengths {
		r.ArgsLength = uint32(lenPacket)
		r.ArrayOffset = 0
		r.ArrayActualCount = uint32(lenPacket)
	}

	// serialize res header
	return r.PNIORes.SerializeTo(b, opts)
}

// IODWriteRes IODWriteMultipleRes
type PNIOIODWriteRes struct {
	PNIORes
	Records []PNIOIODWriteResHeader
}

func (p PNIOIODWriteRes) LayerType() gopacket.LayerType { return LayerTypePNIOWriteRes }

func NewPNIOIODWriteResFromReq(req *PNIOIODWriteMultipleReq) (res PNIOIODWriteRes) {
	res.ArrayMaximumCount = req.ArrayMaximumCount

	return res
}

func (r *PNIOIODWriteRes) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	lenPacket := 0

	for i := len(r.Records) - 1; i >= 0; i-- {
		lenBlock, err := r.Records[i].SerializeTo(b, opts)
		if err != nil {
			return err
		}
		lenPacket = lenPacket + lenBlock
	}
	if len(r.Records) > 1 {
		block := &PNIOIODWriteResHeader{
			BlockHeader:   NewPNIOBlockHeader(PNIOBlockHeaderIODWriteRes),
			SeqNumber:     0,
			ARUUID:        make([]byte, 40),
			API:           0xffffffff,
			SlotNumber:    0xffff,
			SubSlotNumber: 0xffff,
			Index:         PNIOIODReadWriteReqWriteMultiple,
		}
		copy(block.ARUUID, r.Records[0].ARUUID)

		lenBlock, err := block.SerializeTo(b, opts)
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

	// serialize res header
	return r.PNIORes.SerializeTo(b, opts)
}

type PNIOIODReleaseRes struct {
	PNIORes
	ReleaseBlock PNIOReleaseBlock
}

func (p PNIOIODReleaseRes) LayerType() gopacket.LayerType { return LayerTypePNIOReleaseRes }

func NewPNIOIODReleaseResFromReq(req *PNIOIODReleaseReq) (res PNIOIODReleaseRes) {
	res.ArrayMaximumCount = req.ArrayMaximumCount

	res.ReleaseBlock = *NewPNIOReleaseBlockFromReq(req.ReleaseBlock)

	return res
}

func (r *PNIOIODReleaseRes) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	lenPacket, err := r.ReleaseBlock.SerializeTo(b, opts)
	if err != nil {
		return err
	}

	if opts.FixLengths {
		r.ArgsLength = uint32(lenPacket)
		r.ArrayOffset = 0
		r.ArrayActualCount = uint32(lenPacket)
	}

	// serialize res header
	return r.PNIORes.SerializeTo(b, opts)
}

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
	PNIOBlockHeaderPRMEndPlugAlarmRes  PNIOBlockHeaderType = 0x8111
	PNIOBlockHeaderAppRdyRes           PNIOBlockHeaderType = 0x8112
	PNIOBlockHeaderAppRedyPlugAlarmRes PNIOBlockHeaderType = 0x8113
	PNIOBlockHeaderReleaseBlockRes     PNIOBlockHeaderType = 0x8114
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
		return 0, err
	}

	// important: header length (only content below header) is set outside
	if opts.FixLengths {
		// content length, + 2 byte for version
		h.Length = h.Length + uint16(2)
	}

	binary.BigEndian.PutUint16(bytes[0:2], uint16(h.Type))
	binary.BigEndian.PutUint16(bytes[2:4], h.Length)
	bytes[4] = h.VersionHigh
	bytes[5] = h.VersionLow

	return len(bytes), nil
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
	if len(data) < 58 {
		return errors.New("PNIOARBlockReq too short")
	}

	// decode block header
	err := p.BlockHeader.DecodeFromBytes(data[0:], df)
	if err != nil {
		return err
	}

	// TODO parse and check AR Properties (Startup mode Advanced/Legacy)

	p.ARType = binary.BigEndian.Uint16(data[6:8])
	p.ARUUID = make([]byte, 16)
	copy(p.ARUUID, data[8:24])
	p.SessionKey = binary.BigEndian.Uint16(data[24:26])
	p.CMInitiatorMac = make([]byte, 6)
	copy(p.CMInitiatorMac, data[26:32])
	p.CMInitiatorObjectUUID = make([]byte, 16)
	copy(p.CMInitiatorObjectUUID, data[32:48])
	p.ARProperties = binary.BigEndian.Uint32(data[48:52])
	p.CMInitiatorActivityTimeoutFactor = binary.BigEndian.Uint16(data[52:54])
	p.CMInitiatorUDPRTPort = binary.BigEndian.Uint16(data[54:56])
	p.CMInitiatorStationNameLength = binary.BigEndian.Uint16(data[56:58])
	p.CMInitiatorStationName = string(data[58 : 58+p.CMInitiatorStationNameLength])

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

type PNIOIODRecordDataRead interface {
	SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error)
}

type PNIOIM0Data struct {
	BlockHeader                       PNIOBlockHeader
	VendorID                          uint16
	OrderID                           []byte // 20 byte
	IMSerialNumber                    []byte // 16 byte
	IMHardwareRevision                uint16
	IMSWRevisionPrefix                uint8
	IMSWRevisionFunctionalEnhancement uint8
	IMSWRevisionBugFix                uint8
	IMSWRevisionInternalChange        uint8
	IMRevisionCounter                 uint16
	IMProfileID                       uint16
	IMProfileSpecificType             uint16
	IMVersionMajor                    uint8
	IMVersionMinor                    uint8
	IMSupported                       uint16
}

func NewPNIOIM0Data() *PNIOIM0Data {
	return &PNIOIM0Data{
		BlockHeader: NewPNIOBlockHeader(PNIOBlockHeaderIM0), OrderID: make([]byte, 20), IMSerialNumber: make([]byte, 16),
		IMRevisionCounter: 0, IMProfileID: 0, IMProfileSpecificType: 0, IMVersionMajor: 1, IMVersionMinor: 1}
}

func (d *PNIOIM0Data) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	lenPacket := 54
	bytes, err := b.PrependBytes(lenPacket)
	if err != nil {
		return 0, err
	}

	binary.BigEndian.PutUint16(bytes[0:2], d.VendorID)
	copy(bytes[2:22], d.OrderID)
	copy(bytes[22:38], d.IMSerialNumber)
	binary.BigEndian.PutUint16(bytes[38:40], d.IMHardwareRevision)
	bytes[40] = d.IMSWRevisionPrefix
	bytes[41] = d.IMSWRevisionFunctionalEnhancement
	bytes[42] = d.IMSWRevisionBugFix
	bytes[43] = d.IMSWRevisionInternalChange
	binary.BigEndian.PutUint16(bytes[44:46], d.IMRevisionCounter)
	binary.BigEndian.PutUint16(bytes[46:48], d.IMProfileID)
	binary.BigEndian.PutUint16(bytes[48:50], d.IMProfileSpecificType)
	bytes[50] = d.IMVersionMajor
	bytes[51] = d.IMVersionMinor
	binary.BigEndian.PutUint16(bytes[52:54], d.IMSupported)

	// encode block header
	if opts.FixLengths {
		d.BlockHeader.Length = uint16(lenPacket)
	}

	lenBlock, err := d.BlockHeader.SerializeTo(b, opts)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + lenBlock

	return lenPacket, nil
}

type PNIOIM1Data struct {
	BlockHeader PNIOBlockHeader
	TagFunction []byte // 32 byte (filled with blank)
	TagLocation []byte // 22 byte (filled with blank)
}

func NewPNIOIM1Data() *PNIOIM1Data {
	rec := &PNIOIM1Data{BlockHeader: NewPNIOBlockHeader(PNIOBlockHeaderIM1), TagFunction: make([]byte, 32), TagLocation: make([]byte, 22)}
	FillWithBlank(rec.TagFunction)
	FillWithBlank(rec.TagLocation)
	return rec
}

func NewPNIOIM1DataFromData(tagFunction, tagLocation string) *PNIOIM1Data {
	rec := NewPNIOIM1Data()
	FillWithBlankString(rec.TagFunction, tagFunction)
	FillWithBlankString(rec.TagLocation, tagLocation)
	return rec
}

func (d *PNIOIM1Data) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	lenPacket := 54
	bytes, err := b.PrependBytes(lenPacket)
	if err != nil {
		return 0, err
	}

	copy(bytes[0:32], d.TagFunction)
	copy(bytes[32:54], d.TagLocation)

	// encode block header
	if opts.FixLengths {
		d.BlockHeader.Length = uint16(lenPacket)
	}

	lenBlock, err := d.BlockHeader.SerializeTo(b, opts)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + lenBlock

	return lenPacket, nil
}

type PNIOIM234Data struct {
	BlockHeader PNIOBlockHeader
	Data        []byte
}

func NewPNIOIM2Data() *PNIOIM234Data {
	return &PNIOIM234Data{BlockHeader: NewPNIOBlockHeader(PNIOBlockHeaderIM2), Data: make([]byte, 16)}
}

func NewPNIOIM2DataFromData(date time.Time) *PNIOIM234Data {
	rec := NewPNIOIM2Data()
	s := date.Format(time.RFC3339)
	copy(rec.Data, s)
	return rec
}

func NewPNIOIM3Data() *PNIOIM234Data {
	return &PNIOIM234Data{BlockHeader: NewPNIOBlockHeader(PNIOBlockHeaderIM3), Data: make([]byte, 54)}
}

func NewPNIOIM3DataFromData(descriptor string) *PNIOIM234Data {
	rec := NewPNIOIM3Data()
	copy(rec.Data, descriptor)
	return rec
}

func NewPNIOIM4Data() *PNIOIM234Data {
	return &PNIOIM234Data{BlockHeader: NewPNIOBlockHeader(PNIOBlockHeaderIM4), Data: make([]byte, 54)}
}

func NewPNIOIM4DataFromData(signature string) *PNIOIM234Data {
	rec := NewPNIOIM3Data()
	copy(rec.Data, signature)
	return rec
}

func (d *PNIOIM234Data) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	lenPacket := 54
	bytes, err := b.PrependBytes(lenPacket)
	if err != nil {
		return 0, err
	}

	copy(bytes, d.Data)

	// encode block header
	if opts.FixLengths {
		d.BlockHeader.Length = uint16(lenPacket)
	}

	lenBlock, err := d.BlockHeader.SerializeTo(b, opts)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + lenBlock

	return lenPacket, nil
}

type PNIODiagnosisData struct {
	BlockHeader      PNIOBlockHeader
	API              uint32
	ChannelDiagnosis PNIOChannelDiagnosis
}

func NewPNIODiagnosisData() *PNIODiagnosisData {
	res := &PNIODiagnosisData{BlockHeader: NewPNIOBlockHeader(PNIOBlockHeaderDiagnosisData)}
	res.BlockHeader.VersionLow = 1 // include API in response
	return res
}

func (d *PNIODiagnosisData) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	lenPacket, err := d.ChannelDiagnosis.SerializeTo(b, opts)
	if err != nil {
		return 0, err
	}

	bytes, err := b.PrependBytes(4)
	if err != nil {
		return 0, err
	}
	binary.BigEndian.PutUint32(bytes[0:4], d.API)
	lenPacket = lenPacket + len(bytes)

	// encode block header
	if opts.FixLengths {
		d.BlockHeader.Length = uint16(lenPacket)
	}

	lenBlock, err := d.BlockHeader.SerializeTo(b, opts)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + lenBlock

	return lenPacket, nil
}

type PNIOChannelDiagnosis struct {
	SlotNumber              uint16
	SubslotNumber           uint16
	ChannelNumber           uint16
	ChannelProperties       uint16 // TODO to flags
	UserStructureIdentifier uint16
	ChannelDiagnosisData    []PNIOChannelDiagnosisData
}

func (d *PNIOChannelDiagnosis) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	// first encode all APIs
	lenPacket := 0
	for i := len(d.ChannelDiagnosisData) - 1; i >= 0; i-- {
		lenBlock, err := d.ChannelDiagnosisData[i].SerializeTo(b, opts)
		if err != nil {
			return lenPacket, err
		}
		lenPacket = lenPacket + lenBlock
	}

	bytes, err := b.PrependBytes(10)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + len(bytes)
	binary.BigEndian.PutUint16(bytes[0:2], d.SlotNumber)
	binary.BigEndian.PutUint16(bytes[2:4], d.SubslotNumber)
	binary.BigEndian.PutUint16(bytes[4:6], d.ChannelNumber)
	binary.BigEndian.PutUint16(bytes[6:8], d.ChannelProperties)
	binary.BigEndian.PutUint16(bytes[8:10], d.UserStructureIdentifier)

	return lenPacket, nil
}

type PNIOChannelDiagnosisData struct {
	ChannelNumber     uint16
	ChannelProperties PNIOChannelProperties
	ChannelErrorType  uint16
}

func (d *PNIOChannelDiagnosisData) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	bytes, err := b.PrependBytes(6)
	if err != nil {
		return 0, err
	}
	binary.BigEndian.PutUint16(bytes[0:2], d.ChannelNumber)
	binary.BigEndian.PutUint16(bytes[2:4], d.ChannelProperties.toUint16())
	binary.BigEndian.PutUint16(bytes[4:6], d.ChannelErrorType)

	return len(bytes), nil
}

type PNIOChannelProperties struct {
	Direction    uint8 // Bit 13 - 15	=> TODO other type
	Specifier    uint8 // Bit 11 - 12	=> TODO other type
	Maintenance  uint8 // Bit 9 - 10	=> TODO other type
	Accumulative bool  // Bit 8
	Type         uint8 // Bit 0 - 7
}

func (p PNIOChannelProperties) toUint16() uint16 {
	var r uint16

	r = r | ((uint16(p.Direction) << 13) & 0xe000)
	r = r | ((uint16(p.Specifier) << 11) & 0x1800)
	r = r | ((uint16(p.Maintenance) << 9) & 0x0600)
	if p.Accumulative {
		r = r | 0x0100
	}
	r = r | uint16(p.Type)

	return r
}

// TODO combine this with another block?
type PNIORealIdentificationData struct {
	BlockHeader  PNIOBlockHeader
	NumberOfAPIs uint16
	APIs         []PNIOAPI
}

func NewPNIORealIdentificationData() *PNIORealIdentificationData {
	return &PNIORealIdentificationData{BlockHeader: NewPNIOBlockHeader(PNIOBlockHeaderRealIdentificationData)}
}

func (d *PNIORealIdentificationData) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	// first encode all APIs
	lenPacket := 0
	for i := len(d.APIs) - 1; i >= 0; i-- {
		lenBlock, err := d.APIs[i].SerializeTo(b, opts)
		if err != nil {
			return lenPacket, err
		}
		lenPacket = lenPacket + lenBlock
	}

	// set version low to 1 for multiple APIs
	// if len(d.APIs) > 1 {
	d.BlockHeader.VersionLow = 1 // TODO check
	// }

	// add number of APIs
	bytes, err := b.PrependBytes(2)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + len(bytes)
	binary.BigEndian.PutUint16(bytes[0:2], uint16(len(d.APIs)))

	// encode block header
	if opts.FixLengths {
		d.BlockHeader.Length = uint16(lenPacket)
	}

	lenBlock, err := d.BlockHeader.SerializeTo(b, opts)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + lenBlock

	return lenPacket, nil
}

type PNIOIM0FilterData struct {
	IM0FilterDataBlocks []PNIOIM0FilterDataBlock
}

func (d *PNIOIM0FilterData) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	// encode all IM0FilterDataBlocks
	lenPacket := 0
	for i := len(d.IM0FilterDataBlocks) - 1; i >= 0; i-- {
		lenBlock, err := (&d.IM0FilterDataBlocks[i]).SerializeTo(b, opts)
		if err != nil {
			return lenPacket, err
		}
		lenPacket = lenPacket + lenBlock
	}

	return lenPacket, nil
}

type PNIOIM0FilterDataBlock struct {
	BlockHeader  PNIOBlockHeader
	NumberOfAPIs uint16
	APIs         []PNIOAPI
}

func NewPNIOIM0FilterDataBlock(t PNIOBlockHeaderType) *PNIOIM0FilterDataBlock {
	// check t
	if t >= PNIOBlockHeaderIM0FilterDataSubmodule && t <= PNIOBlockHeaderIM0FilterDataDevice {
		return &PNIOIM0FilterDataBlock{BlockHeader: NewPNIOBlockHeader(t)}
	}
	return nil
}

func (d *PNIOIM0FilterDataBlock) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	// first encode all APIs
	lenPacket := 0
	for i := len(d.APIs) - 1; i >= 0; i-- {
		lenBlock, err := d.APIs[i].SerializeTo(b, opts)
		if err != nil {
			return lenPacket, err
		}
		lenPacket = lenPacket + lenBlock
	}

	// add number of APIs
	bytes, err := b.PrependBytes(2)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + len(bytes)
	binary.BigEndian.PutUint16(bytes[0:2], uint16(len(d.APIs)))

	// encode block header
	if opts.FixLengths {
		d.BlockHeader.Length = uint16(lenPacket)
	}

	lenBlock, err := d.BlockHeader.SerializeTo(b, opts)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + lenBlock

	return lenPacket, nil
}

type PNIOAPI struct {
	API             uint32
	NumberOfModules uint16
	Modules         []PNIOAPIModule
}

func (d *PNIOAPI) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	// first encode all Modules
	lenPacket := 0
	for i := len(d.Modules) - 1; i >= 0; i-- {
		lenBlock, err := d.Modules[i].SerializeTo(b, opts)
		if err != nil {
			return lenPacket, err
		}
		lenPacket = lenPacket + lenBlock
	}

	// add number of Modules and API
	bytes, err := b.PrependBytes(6)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + len(bytes)
	binary.BigEndian.PutUint32(bytes[0:4], d.API)
	binary.BigEndian.PutUint16(bytes[4:6], uint16(len(d.Modules)))

	return lenPacket, nil
}

type PNIOAPIModule struct {
	SlotNumber         uint16
	ModuleIdentNumber  uint32
	NumberOfSubmodules uint32
	Submodules         []PNIOAPISubmodule
}

func (d *PNIOAPIModule) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	// first encode all Submodules
	lenPacket := 0
	for i := len(d.Submodules) - 1; i >= 0; i-- {
		lenBlock, err := d.Submodules[i].SerializeTo(b, opts)
		if err != nil {
			return lenPacket, err
		}
		lenPacket = lenPacket + lenBlock
	}

	// add number of Submodules, ModuleIdentNumber and Slotnumber
	bytes, err := b.PrependBytes(8)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + len(bytes)
	binary.BigEndian.PutUint16(bytes[0:2], d.SlotNumber)
	binary.BigEndian.PutUint32(bytes[2:6], d.ModuleIdentNumber)
	binary.BigEndian.PutUint16(bytes[6:8], uint16(len(d.Submodules)))

	return lenPacket, nil
}

type PNIOAPISubmodule struct {
	SubslotNumber        uint16
	SubmoduleIdentNumber uint32
}

func (d *PNIOAPISubmodule) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	// add number of Submodules, ModuleIdentNumber and Slotnumber
	bytes, err := b.PrependBytes(6)
	if err != nil {
		return 0, err
	}
	lenPacket := len(bytes)
	binary.BigEndian.PutUint16(bytes[0:2], d.SubslotNumber)
	binary.BigEndian.PutUint32(bytes[2:6], d.SubmoduleIdentNumber)

	return lenPacket, nil
}

type PNIOIODReadRes struct {
	PNIORes
	IODReadResHeader PNIOIODReadWriteReqHeader // TODO switch to PNIOIODReadWriteResHeader
	RecordDataRead   PNIOIODRecordDataRead
}

func (p PNIOIODReadRes) LayerType() gopacket.LayerType { return LayerTypePNIOReadRes }

func NewPNIOIODReadResFromReq(req *PNIOIODReadReq) (res PNIOIODReadRes) {
	res.ArrayMaximumCount = req.ArrayMaximumCount

	res.IODReadResHeader.BlockHeader = NewPNIOBlockHeader(PNIOBlockHeaderIODReadRes)
	res.IODReadResHeader.SeqNumber = req.IODReadReqHeader.SeqNumber // not standardized
	res.IODReadResHeader.ARUUID = make([]byte, 16)
	copy(res.IODReadResHeader.ARUUID, req.IODReadReqHeader.ARUUID)
	res.IODReadResHeader.API = req.IODReadReqHeader.API
	res.IODReadResHeader.SlotNumber = req.IODReadReqHeader.SlotNumber
	res.IODReadResHeader.SubSlotNumber = req.IODReadReqHeader.SubSlotNumber
	res.IODReadResHeader.Index = req.IODReadReqHeader.Index

	return res
}

func (r *PNIOIODReadRes) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	lenPacket := 0
	if r.RecordDataRead != nil {
		lenBlock, err := r.RecordDataRead.SerializeTo(b, opts)
		if err != nil {
			return err
		}
		lenPacket = lenBlock
	}
	if opts.FixLengths {
		r.IODReadResHeader.RecordDataLength = uint32(lenPacket)
	}

	// encode read response header
	lenBlock, err := r.IODReadResHeader.SerializeTo(b, opts)
	if err != nil {
		return err
	}
	lenPacket = lenPacket + lenBlock

	if opts.FixLengths {
		r.ArgsLength = uint32(lenPacket)
		r.ArrayOffset = 0
		r.ArrayActualCount = uint32(lenPacket)
	}

	// serialize res header
	return r.PNIORes.SerializeTo(b, opts)
}

type PNIOIODControlRes struct {
	PNIORes
	PNIOControlBlockConnectPlug
}

func (p PNIOIODControlRes) LayerType() gopacket.LayerType { return LayerTypePNIOControlRes }

func NewPNIOIODControlResFromReq(req *PNIOIODControlReq) (res PNIOIODControlRes) {
	res.BlockHeader = NewPNIOBlockHeader(PNIOBlockHeaderPRMEndRes)
	res.ArrayMaximumCount = req.ArrayMaximumCount
	res.ARUUID = make([]byte, 16)
	copy(res.ARUUID, req.ARUUID)
	res.SessionKey = req.SessionKey
	// res.ControlCommand =         cmd
	// res.ControlBlockProperties = 0x0000

	return res
}

func (r *PNIOIODControlRes) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	lenPacket := 26
	bytes, err := b.PrependBytes(lenPacket)
	if err != nil {
		return err
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
		return err
	}
	lenPacket = lenPacket + lenBlock

	if opts.FixLengths {
		r.ArgsLength = uint32(lenPacket)
		r.ArrayOffset = 0
		r.ArrayActualCount = uint32(lenPacket)
	}

	// serialize res header
	return r.PNIORes.SerializeTo(b, opts)
}

type PNIOReleaseBlock struct {
	BlockHeader PNIOBlockHeader
	// 2 byte padding
	ARUUID     []byte // 16 byte
	SessionKey uint16
	// 2 byte padding
	ControlCommand         uint16
	ControlBlockProperties uint16
}

func NewPNIOReleaseBlockFromReq(req PNIOReleaseBlock) *PNIOReleaseBlock {
	res := &PNIOReleaseBlock{
		BlockHeader: NewPNIOBlockHeader(PNIOBlockHeaderReleaseBlockRes),
		ARUUID:      make([]byte, 16),
		SessionKey:  req.SessionKey,
	}
	copy(res.ARUUID, req.ARUUID)
	return res
}

func (p *PNIOReleaseBlock) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 32 {
		return errors.New("PNIOReleaseBlock too short")
	}

	// decode block header
	err := p.BlockHeader.DecodeFromBytes(data[0:], df)
	if err != nil {
		return err
	}

	// 2 byte padding
	p.ARUUID = make([]byte, 16)
	copy(p.ARUUID, data[8:24])
	p.SessionKey = binary.BigEndian.Uint16(data[24:26])
	// 2 byte padding
	p.ControlCommand = binary.BigEndian.Uint16(data[28:30])
	p.ControlBlockProperties = binary.BigEndian.Uint16(data[30:32])
	// TODO parse and check ControlBlockProperties Properties

	return nil
}

func (d *PNIOReleaseBlock) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	lenPacket := 26
	bytes, err := b.PrependBytes(lenPacket)
	if err != nil {
		return 0, err
	}

	copy(bytes[2:18], d.ARUUID)
	binary.BigEndian.PutUint16(bytes[18:20], d.SessionKey)
	binary.BigEndian.PutUint16(bytes[22:24], d.ControlCommand)
	binary.BigEndian.PutUint16(bytes[24:26], d.ControlBlockProperties)

	// encode block header
	if opts.FixLengths {
		d.BlockHeader.Length = uint16(lenPacket)
	}

	lenBlock, err := d.BlockHeader.SerializeTo(b, opts)
	if err != nil {
		return lenPacket, err
	}
	lenPacket = lenPacket + lenBlock

	return lenPacket, nil
}

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
	err := p.Header.DecodeFromBytes(data, df)
	if err != nil {
		return err
	}

	// assertions
	if p.Header.Type != PNIOBlockHeaderPDInterfaceAdjust {
		return errors.New("BlockHeaderType mismatch")
	}
	if p.Header.Length != 8 {
		return errors.New("BlockHeaderLength mismatch")
	}
	if p.Header.VersionHigh != 1 {
		return errors.New("BlockHeaderVersion mismatch")
	}

	// 2 byte padding
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

func (p *PNIOIODReadWriteReqHeader) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) (int, error) {
	if len(data) < 64 {
		return 0, errors.New("PNIOIODReadWriteReqHeader too small")
	}

	// redecode block header, because length is needed here TODO
	err := p.BlockHeader.DecodeFromBytes(data[0:], df)
	if err != nil {
		return 0, err
	}

	p.SeqNumber = binary.BigEndian.Uint16(data[6:8])
	p.ARUUID = make([]byte, 16)
	copy(p.ARUUID, data[8:24])
	p.API = binary.BigEndian.Uint32(data[24:28])
	p.SlotNumber = binary.BigEndian.Uint16(data[28:30])
	p.SubSlotNumber = binary.BigEndian.Uint16(data[30:32])
	// 2 byte padding
	p.Index = PNIOIODReadWriteReqHeaderIndex(binary.BigEndian.Uint16(data[34:36]))
	p.RecordDataLength = binary.BigEndian.Uint32(data[36:40])
	// 24 byte padding

	// TODO recorddatareadqueries

	return 64, nil
}

func (r *PNIOIODReadWriteReqHeader) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	lenPacket := 58
	bytes, err := b.PrependBytes(lenPacket)
	if err != nil {
		return 0, err
	}

	// 2 bytes reserved
	binary.BigEndian.PutUint16(bytes[0:2], r.SeqNumber)
	copy(bytes[2:18], r.ARUUID)
	binary.BigEndian.PutUint32(bytes[18:22], r.API)
	binary.BigEndian.PutUint16(bytes[22:24], r.SlotNumber)
	binary.BigEndian.PutUint16(bytes[24:26], r.SubSlotNumber)
	// 2 byte padding
	binary.BigEndian.PutUint16(bytes[28:30], uint16(r.Index))
	binary.BigEndian.PutUint32(bytes[30:36], r.RecordDataLength)
	// TODO more elements ?!

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

type PNIOIODReadWriteReqHeaderIndex uint16

const (
	PNIOIODReadWriteReqExpectedIdentificationDataSubslot PNIOIODReadWriteReqHeaderIndex = 0x8000
	PNIOIODReadWriteReqRealIdentificationDataSubslot     PNIOIODReadWriteReqHeaderIndex = 0x8001

	PNIOIODReadWriteReqPDInterfaceAdjust PNIOIODReadWriteReqHeaderIndex = 0x8071

	PNIOIODReadWriteReqIndexIM0 PNIOIODReadWriteReqHeaderIndex = 0xaff0
	PNIOIODReadWriteReqIndexIM1 PNIOIODReadWriteReqHeaderIndex = 0xaff1
	PNIOIODReadWriteReqIndexIM2 PNIOIODReadWriteReqHeaderIndex = 0xaff2
	PNIOIODReadWriteReqIndexIM3 PNIOIODReadWriteReqHeaderIndex = 0xaff3
	PNIOIODReadWriteReqIndexIM4 PNIOIODReadWriteReqHeaderIndex = 0xaff4

	PNIOIODReadWriteReqExpectedIdentificationDataSlot PNIOIODReadWriteReqHeaderIndex = 0xc000
	PNIOIODReadWriteReqRealIdentificationDataSlot     PNIOIODReadWriteReqHeaderIndex = 0xc001

	PNIOIODReadWriteReqExpectedIdentificationDataAR PNIOIODReadWriteReqHeaderIndex = 0xe000
	PNIOIODReadWriteReqRealIdentificationDataAR     PNIOIODReadWriteReqHeaderIndex = 0xe001
	PNIOIODReadWriteReqModuleDiffBlockAR            PNIOIODReadWriteReqHeaderIndex = 0xe002

	PNIOIODReadWriteReqWriteMultiple PNIOIODReadWriteReqHeaderIndex = 0xe040

	PNIOIODReadWriteReqRealIdentificationDataAPI PNIOIODReadWriteReqHeaderIndex = 0xf000
	PNIOIODReadWriteReqDiagnosisAPI              PNIOIODReadWriteReqHeaderIndex = 0xf00c
	PNIOIODReadWriteReqDiagnosisARDataAPI        PNIOIODReadWriteReqHeaderIndex = 0xf020

	PNIOIODReadWriteReqIM0FilterData PNIOIODReadWriteReqHeaderIndex = 0xf840
)

func (p *PNIOIODReadReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) (int, error) {
	offset, err := p.PNIOReq.DecodeFromBytes(data, df)
	if err != nil {
		log.Println("[PNIOIODReadReq.DecodeFromBytes] PNIOReq.DecodeFromBytes error:", err)
		return offset, err
	}

	return p.IODReadReqHeader.DecodeFromBytes(data[offset:], df)
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

func NewPNIOIODWriteResHeaderFromReqHeader(req *PNIOIODReadWriteReqHeader) (res PNIOIODWriteResHeader) {
	res.BlockHeader = NewPNIOBlockHeader(PNIOBlockHeaderIODWriteRes)
	res.SeqNumber = req.SeqNumber
	res.ARUUID = make([]byte, 16)
	copy(res.ARUUID, req.ARUUID)
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

type PNIOIODataObj struct {
	SlotNumber    uint16
	SubslotNumber uint16
	FrameOffset   uint16
}

func (p *PNIOIODataObj) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) (int, error) {
	// length without header
	if len(data) < 6 {
		return 0, errors.New("PNIOIODataObj too small")
	}

	p.SlotNumber = binary.BigEndian.Uint16(data[0:2])
	p.SubslotNumber = binary.BigEndian.Uint16(data[2:4])
	p.FrameOffset = binary.BigEndian.Uint16(data[4:6])

	return 6, nil
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
	DataObjects           []PNIOIODataObj
	NumberOfIOCS          uint16
	IOCSs                 []byte // TODO better type
}

func (p *PNIOIOCRBlockReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 52 {
		return errors.New("PNIOIOCRBlockReq too short")
	}

	// decode block header
	err := p.BlockHeader.DecodeFromBytes(data[0:], df)
	if err != nil {
		return err
	}

	// TODO decode header
	// BlockHeader
	p.IOCRType = binary.BigEndian.Uint16(data[6:8])
	p.IOCRReference = binary.BigEndian.Uint16(data[8:10])
	p.LT = binary.BigEndian.Uint16(data[10:12])
	p.Properties = binary.BigEndian.Uint32(data[12:16])
	p.DataLength = binary.BigEndian.Uint16(data[16:18])
	p.FrameID = binary.BigEndian.Uint16(data[18:20])
	p.SendClockFactor = binary.BigEndian.Uint16(data[20:22])
	p.ReductionRatio = binary.BigEndian.Uint16(data[22:24])
	p.Phase = binary.BigEndian.Uint16(data[24:26])
	p.Sequence = binary.BigEndian.Uint16(data[26:28])
	p.FrameSendOffset = binary.BigEndian.Uint32(data[28:32])
	p.WatchDogFactor = binary.BigEndian.Uint16(data[32:34])
	p.DataHoldFactor = binary.BigEndian.Uint16(data[34:36])
	p.IOCRTagHeader = binary.BigEndian.Uint16(data[36:38])
	p.IOCRMulticastMACAdd = make([]byte, 6)
	copy(p.IOCRMulticastMACAdd, data[38:44]) // 6 byte
	p.NumberOfAPIs = binary.BigEndian.Uint16(data[44:46])
	p.API = binary.BigEndian.Uint32(data[46:50])
	p.NumberOfIODataObjects = binary.BigEndian.Uint16(data[50:52])

	offset := 52
	for i := 0; i < int(p.NumberOfIODataObjects); i++ {
		dobj := &PNIOIODataObj{}
		numBytesDecoded, err := dobj.DecodeFromBytes(data[offset:], df)
		if err != nil {
			return err
		}
		offset = offset + numBytesDecoded
		p.DataObjects = append(p.DataObjects, *dobj)
	}
	// TODO decode completely

	// NumberOfIOCS          uint16
	// IOCSs                 []byte

	return nil
}

type PNIOExpectedSubmoduleBlockReq struct {
	BlockHeader  PNIOBlockHeader
	NumberOfAPIs uint16
	APIs         []PNIOSubmoduleAPI
}

func (p *PNIOExpectedSubmoduleBlockReq) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// length without header
	if len(data) < 8 {
		return errors.New("PNIOExpectedSubmoduleBlockReq too short")
	}

	// decode block header
	err := p.BlockHeader.DecodeFromBytes(data[0:], df)
	if err != nil {
		return err
	}

	lenPacket := 8
	p.NumberOfAPIs = binary.BigEndian.Uint16(data[6:8])

	// log.Printf("NumberOfAPIs: %x\n", p.NumberOfAPIs)

	for iAPI := 0; (iAPI < int(p.NumberOfAPIs)) && (len(data[lenPacket:]) > 14); iAPI++ {
		api := &PNIOSubmoduleAPI{}
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

type PNIOSubmoduleAPI struct {
	No                uint32
	SlotNumber        uint16
	ModuleIdentNumber uint32
	ModuleProperties  uint16
	SubModulesLength  uint16
	Submodules        []PNIOSubmodule
}

func (p *PNIOSubmoduleAPI) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) (int, error) {
	// length without header
	if len(data) < 14 {
		return 0, errors.New("Malformed PNIOSubmoduleAPI")
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
		api := &PNIOSubmodule{}
		lenSubmodule, err := api.DecodeFromBytes(data[lenPacket:], df)
		if err != nil {
			log.Println("cannot decode API block")
			break
		}
		lenPacket = lenPacket + lenSubmodule
	}

	return lenPacket, nil
}

type PNIOSubmodule struct {
	SubslotNumber        uint16
	SubmoduleIdentNumber uint32
	SubmoduleProperties  uint16
	DataDescription      PNIODataDescription
}

func (p *PNIOSubmodule) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) (int, error) {
	// length without header
	if len(data) < 14 {
		return 0, errors.New("Malformed PNIOSubmodule")
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

type PNIODataDescription struct {
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
	if len(data) < 26 {
		return errors.New("PNIOAlarmCRBlockReq too short")
	}

	// decode block header
	err := p.BlockHeader.DecodeFromBytes(data[0:], df)
	if err != nil {
		return err
	}

	p.AlarmCRType = binary.LittleEndian.Uint16(data[6:8])
	p.LT = binary.LittleEndian.Uint16(data[8:10])
	p.Properties = binary.LittleEndian.Uint32(data[10:14])
	p.RTATimeoutFactor = binary.LittleEndian.Uint16(data[14:16])
	p.RTARetries = binary.LittleEndian.Uint16(data[16:18])
	p.LocalAlarmReference = binary.LittleEndian.Uint16(data[18:20])
	p.MaxAlarmDataLength = binary.LittleEndian.Uint16(data[20:22])
	p.AlarmCRTagHeaderHigh = binary.LittleEndian.Uint16(data[22:24])
	p.AlarmCRTagHeaderLow = binary.LittleEndian.Uint16(data[24:26])

	return nil
}

type PNIOART struct {
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
}

func (r *PNIOARBlockRes) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
	lenPacket := 28
	bytes, err := b.PrependBytes(lenPacket)
	if err != nil {
		return lenPacket, err
	}
	binary.BigEndian.PutUint16(bytes[0:2], r.ARType)
	copy(bytes[2:18], r.ARUUID)
	binary.BigEndian.PutUint16(bytes[18:20], r.SessionKey)
	copy(bytes[20:26], r.CMResponderMacAdd)
	binary.BigEndian.PutUint16(bytes[26:28], r.CMResponderUDPRTPort)

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
	APIs         []PNIOIOCAPI
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

type PNIOARRPCBlockRes struct {
	BlockHeader            PNIOBlockHeader
	CMInitiatorStationName string
}

func (r *PNIOARRPCBlockRes) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
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

type PNIOIOCAPI struct {
	API             uint32
	NumberOfModules uint16
	// TODO some fields are missing here :/
}

func (t *PNIOIOCAPI) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) (int, error) {
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

func decodePNIOConnectReq(data []byte, p gopacket.PacketBuilder) error {
	d := &PNIOIODConnectReq{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		log.Println("[decodePNIOConnectReq] DecodeFromBytes error:", err)
		return err
	}
	p.AddLayer(d)

	return nil
}

func decodePNIOReleaseReq(data []byte, p gopacket.PacketBuilder) error {
	d := &PNIOIODReleaseReq{}
	_, err := d.DecodeFromBytes(data, p)
	if err != nil {
		log.Println("[decodePNIOReleaseReq] DecodeFromBytes error:", err)
		return err
	}
	p.AddLayer(d)

	return nil
}

func decodePNIOReadReq(data []byte, p gopacket.PacketBuilder) error {
	d := &PNIOIODReadReq{}
	_, err := d.DecodeFromBytes(data, p)
	if err != nil {
		log.Println("[decodePNIOReadReq] DecodeFromBytes error:", err)
		return err
	}
	p.AddLayer(d)

	return nil
}

func decodePNIOWriteReq(data []byte, p gopacket.PacketBuilder) error {
	d := &PNIOIODWriteMultipleReq{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		log.Println("[decodePNIOWriteReq] DecodeFromBytes error:", err)
		return err
	}
	p.AddLayer(d)

	return nil
}

func decodePNIOControlReq(data []byte, p gopacket.PacketBuilder) error {
	d := &PNIOIODControlReq{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		log.Println("[decodePNIOControlReq] DecodeFromBytes error:", err)
		return err
	}
	p.AddLayer(d)

	return nil
}
