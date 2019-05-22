package frt

import (
	kb "github.com/libp2p/go-libp2p-kbucket"
	"testing"
	"time"
)

func TestReqFullRoutingTable(t *testing.T) {
	rt := kb.NewRoutingTable(10, kb.ConvertPeerID("test"), time.Duration(time.Second*1), nil)
	fullRTManager := NewRTProviderRequester(rt)
	err, rtBytes := fullRTManager.GetFullRoutingTable()
	if err != nil {
		t.Fatal(err)
	}

	t.Error(rtBytes)
}
