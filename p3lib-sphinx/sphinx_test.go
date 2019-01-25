package sphinx

import (
	"testing"
)

func TestNewPacket(t *testing.T) {
	p := New()
	if p == nil {
		t.Error("NewPacket_Test: packet not correctly constructed")
	}
}
