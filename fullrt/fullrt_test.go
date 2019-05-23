package fullrt

import (
	"encoding/json"
	kb "github.com/libp2p/go-libp2p-kbucket"
	peer "github.com/libp2p/go-libp2p-peer"
	pstore "github.com/libp2p/go-libp2p-peerstore"
	"testing"
	"time"
)

func TestReqFullRoutingTable(t *testing.T) {
	rt := kb.NewRoutingTable(10, kb.ConvertPeerID("test"), time.Duration(time.Second*1), pstore.NewMetrics())

	// setup RT
	id1 := "QmWYob8Wax6xqoHydBGkoYtLjp5JVDXrvA47RtyEVnqVjK"
	_, err := rt.Update(peer.ID(id1))
	if err != nil {
		t.Fatal(err)
	}

	id2 := "QmYHnHTuDbYTEZoBypEDQHP7gb6r2krEQQy9F6dy1YTrbz"
	_, err = rt.Update(peer.ID(id2))
	if err != nil {
		t.Fatal(err)
	}

	id3 := "/non-multihash/ID"
	_, err = rt.Update(peer.ID(id3))
	if err != nil {
		t.Fatal(err)
	}

	fullRTManager := NewRTProvider(rt)
	err, rtBytes := fullRTManager.GetFullRoutingTable()
	if err != nil {
		t.Fatal(err)
	}

	frt := RoutingTableRaw{}
	err = json.Unmarshal(rtBytes, &frt)
	if err != nil {
		t.Fatal(err)
	}

	if frt[0] != id3 {
		t.Error("peerid 3 was not successfully transformed")
	}

	if frt[1] != id2 {
		t.Error("peerid 2 was not successfully transformed")
	}

	if frt[2] != id1 {
		t.Error("peerid 1 was not successfully transformed")
	}

}
