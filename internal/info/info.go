package info

import (
    "bytes"
    "encoding/binary"
)

type AllocInfoRaw struct {
	Size       	uint64
	TimestampNs uint64
	StackId    	uint32
	_ 			[4]byte
}

type AllocInfo struct {
	Size       	uint64
	TimestampNs uint64
	StackId    	uint32
	Address 	uint64
}

type CombinedAllocInfoRaw struct {
	Bits [8]byte
}

type CombinedAllocInfo struct {
	StackId      	uint32
	TotalSize      	uint64
	NumberOfAllocs 	uint32
}

func UnmarshalBinaryAllocInfo(data []byte) (*AllocInfoRaw, error) {
	var allocInfoRaw AllocInfoRaw
    reader := bytes.NewReader(data)
    if err := binary.Read(reader, binary.LittleEndian, &allocInfoRaw); err != nil {
        return nil, err
    }
    return &allocInfoRaw, nil
}

func GetAllocInfo(address uint64, raw AllocInfoRaw) AllocInfo {
	return AllocInfo{
		Size:        raw.Size,
		TimestampNs: raw.TimestampNs,
		StackId:     raw.StackId,
		Address:     address,
	}
}

func GetCombinedAllocInfo(stackId uint32, raw CombinedAllocInfoRaw) (*CombinedAllocInfo, error) {
    total := uint64(raw.Bits[0]) |
        uint64(raw.Bits[1])<<8 |
        uint64(raw.Bits[2])<<16 |
        uint64(raw.Bits[3])<<24 |
        uint64(raw.Bits[4])<<32

    number := uint32(raw.Bits[5]) |
        uint32(raw.Bits[6])<<8 |
        uint32(raw.Bits[7])<<16

    return &CombinedAllocInfo{
		StackId:        stackId,
        TotalSize:      total,
        NumberOfAllocs: number,
    }, nil
}