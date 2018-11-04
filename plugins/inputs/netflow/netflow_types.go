package netflow

import (
	"fmt"
	"strings"
)

type port uint16

func (p port) String() string { return fmt.Sprintf("%d", p) }

type protocol byte

const (
	pICMP           protocol = 1
	pIGMP           protocol = 2
	pGGP            protocol = 3
	pIPENCAP        protocol = 4
	pST             protocol = 5
	pTCP            protocol = 6
	pEGP            protocol = 8
	pIGP            protocol = 9
	pPUP            protocol = 12
	pUDP            protocol = 17
	pHMP            protocol = 20
	pXNSIDP         protocol = 22
	pRDP            protocol = 27
	pISOTP4         protocol = 29
	pDCCP           protocol = 33
	pXTP            protocol = 36
	pDDP            protocol = 37
	pIDPRCMTP       protocol = 38
	pIPv6           protocol = 41
	pIPv6Route      protocol = 43
	pIPv6Frag       protocol = 44
	pIDRP           protocol = 45
	pRSVP           protocol = 46
	pGRE            protocol = 47
	pIPSECESP       protocol = 50
	pIPSECAH        protocol = 51
	pSKIP           protocol = 57
	pIPv6ICMP       protocol = 58
	pIPv6NoNxt      protocol = 59
	pIPv6Opts       protocol = 60
	pRSPF           protocol = 73
	pVMTP           protocol = 81
	pEIGRP          protocol = 88
	pOSPFIGP        protocol = 89
	pAX25           protocol = 93
	pIPIP           protocol = 94
	pETHERIP        protocol = 97
	pENCAP          protocol = 98
	pPIM            protocol = 103
	pIPCOMP         protocol = 108
	pVRRP           protocol = 112
	pL2TP           protocol = 115
	pISIS           protocol = 124
	pSCTP           protocol = 132
	pFC             protocol = 133
	pMobilityHeader protocol = 135
	pUDPLite        protocol = 136
	pMPLSinIP       protocol = 137
	pHIP            protocol = 139
	pShim6          protocol = 140
	pWESP           protocol = 141
	pROHC           protocol = 142
)

var protocols = map[protocol]string{
	pICMP:           "ICMP",
	pIGMP:           "IGMP",
	pGGP:            "GGP",
	pIPENCAP:        "IP-ENCAP",
	pST:             "ST",
	pTCP:            "TCP",
	pEGP:            "EGP",
	pIGP:            "IGP",
	pPUP:            "PUP",
	pUDP:            "UDP",
	pHMP:            "HMP",
	pXNSIDP:         "XNS-IDP",
	pRDP:            "RDP",
	pISOTP4:         "ISO-TP4",
	pDCCP:           "DCCP",
	pXTP:            "XTP",
	pDDP:            "DDP",
	pIDPRCMTP:       "IDPR-CMTP",
	pIPv6:           "IPv6",
	pIPv6Route:      "IPv6-Route",
	pIPv6Frag:       "IPv6-Frag",
	pIDRP:           "IDRP",
	pRSVP:           "RSVP",
	pGRE:            "GRE",
	pIPSECESP:       "IPSEC-ESP",
	pIPSECAH:        "IPSEC-AH",
	pSKIP:           "SKIP",
	pIPv6ICMP:       "IPv6-ICMP",
	pIPv6NoNxt:      "IPv6-NoNxt",
	pIPv6Opts:       "IPv6-Opts",
	pRSPF:           "RSPF",
	pVMTP:           "VMTP",
	pEIGRP:          "EIGRP",
	pOSPFIGP:        "OSPFIGP",
	pAX25:           "AX.25",
	pIPIP:           "IPIP",
	pETHERIP:        "ETHERIP",
	pENCAP:          "ENCAP",
	pPIM:            "PIM",
	pIPCOMP:         "IPCOMP",
	pVRRP:           "VRRP",
	pL2TP:           "L2TP",
	pISIS:           "ISIS",
	pSCTP:           "SCTP",
	pFC:             "FC",
	pMobilityHeader: "Mobility-Header",
	pUDPLite:        "UDPLite",
	pMPLSinIP:       "MPLS-in-IP",
	pHIP:            "HIP",
	pShim6:          "Shim6",
	pWESP:           "WESP",
	pROHC:           "ROHC",
}

func (p protocol) String() string {
	if desc, found := protocols[p]; found {
		return desc
	} else {
		return fmt.Sprintf("UNKNOWN_%d", p)
	}
}

type flags byte

const (
	fFIN flags = 1 << iota
	fSYN
	fRST
	fPSH
	fACK
	fURG
	fECE
	fCWR
)

var tflags = []string{"FIN",
	"SYN",
	"RST",
	"PSH",
	"ACK",
	"URG",
	"ECE",
	"CWR",
}

func (f flags) hasFlag(bit flags) bool {
	return f&bit != 0
}

func (f flags) hasBit(bitno byte) bool {
	if bitno <= 7 {
		return f&(1<<bitno) != 0
	} else {
		return false
	}
}

func (f flags) String() string {
	ans := []string{}
	for n := byte(0); n < 8; n++ {
		if f.hasBit(n) {
			ans = append(ans, tflags[n])
		}
	}
	return strings.Join(ans, ",")
}

type ipv4 [4]byte

type tos byte
