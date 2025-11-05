package info

import (
    "bytes"
    "encoding/binary"
)

type AllocInfo struct {
	Size       	uint64
	TimestampNs uint64
	StackId    	int32
	_ 			[4]byte
}

type CombinedAllocInfoRaw struct {
	Bits [8]byte
}

type CombinedAllocInfo struct {
	TotalSize      uint64
	NumberOfAllocs uint32
}

func UnmarshalBinaryAllocInfo(data []byte) (*AllocInfo, error) {
	var allocInfo AllocInfo
    reader := bytes.NewReader(data)
    if err := binary.Read(reader, binary.LittleEndian, &allocInfo); err != nil {
        return nil, err
    }
    return &allocInfo, nil
}


func GetCombinedAllocInfo(raw CombinedAllocInfoRaw) (*CombinedAllocInfo, error) {
    total := uint64(raw.Bits[0]) |
        uint64(raw.Bits[1])<<8 |
        uint64(raw.Bits[2])<<16 |
        uint64(raw.Bits[3])<<24 |
        uint64(raw.Bits[4])<<32

    number := uint32(raw.Bits[5]) |
        uint32(raw.Bits[6])<<8 |
        uint32(raw.Bits[7])<<16

    return &CombinedAllocInfo{
        TotalSize:      total,
        NumberOfAllocs: number,
    }, nil
}