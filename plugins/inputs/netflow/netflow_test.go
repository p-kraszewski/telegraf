package netflow

import (
	"fmt"
	"strings"
	"testing"
)

func TestFlagsDecoder(t *testing.T) {
	var testData = []struct {
		f        flags
		expected string
	}{
		{0, ""},
		{fSYN, "SYN"},
		{fACK, "ACK"},
		{fACK | fSYN, "SYN,ACK"},
		{fFIN | fSYN | fRST | fPSH | fACK | fURG | fECE | fCWR, "FIN,SYN,RST,PSH,ACK,URG,ECE,CWR"},
	}

	for _, testPoint := range testData {
		testDescription := "NUL"
		if testPoint.expected != "" {
			testDescription = strings.Replace(testPoint.expected, ",", "", -1)
		}
		t.Run(testDescription, func(subTest *testing.T) {
			got := testPoint.f.String()
			if got != testPoint.expected {
				subTest.Errorf("Mismatch, expected '%s', got '%s'", testPoint.expected, got)
			}
		})
	}
}

func TestProtoDecoder(t *testing.T) {
	var testData = []struct {
		p        protocol
		expected string
	}{
		{0, "UNKNOWN_0"},
		{pICMP, "ICMP"},
		{pUDP, "UDP"},
		{255, "UNKNOWN_255"},
	}

	for _, testPoint := range testData {

		t.Run(fmt.Sprintf("Protocol_%d", testPoint.p), func(subTest *testing.T) {
			got := testPoint.p.String()
			if got != testPoint.expected {
				subTest.Errorf("Mismatch, expected '%s', got '%s'", testPoint.expected, got)
			}
		})
	}
}
