package netflow

import (
	"io"
	"unsafe"
)

type nfv1_record struct {
	srcAddr  ipv4
	dstAddr  ipv4
	nextHop  ipv4
	input    uint16
	output   uint16
	dPkts    uint32
	oOctets  uint32
	first    uint32
	last     uint32
	srcPort  port
	dstPort  port
	pad1     uint16
	prot     protocol
	tos      tos
	flags    flags
	pad2     uint16
	reserved uint32
}

type nfv1_struct struct {
	version   uint16
	count     uint16
	sysUptime uint32
	unixSecs  uint32
	unixNSecs uint32
	data      [24]nfv1_record
}

const nfv1_max_len = unsafe.Sizeof(nfv1_struct{})

func fillV1Buffer(b *nfv1_struct, r io.Reader) error {
	slice := (*[1 << 30]byte)(unsafe.Pointer(b))[:nfv1_max_len:nfv1_max_len]
	_, err := r.Read(slice)
	return err
}
