package netflow

import "testing"

func TestFlags(t *testing.T) {
	var f flags = fACK | fSYN
	ft := f.String()
	if ft != "SYN|ACK" {
		t.Error("Mismatch SYNACK")
	}
}
