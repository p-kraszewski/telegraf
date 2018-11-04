package netflow

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

type nfv1_hdr struct {
	version   uint16
	count     uint16
	sysUptime uint32
	unixSecs  uint32
	unixNSecs uint32
	data      [24]nfv1_record
}
