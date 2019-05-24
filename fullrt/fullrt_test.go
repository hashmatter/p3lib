package fullrt

import (
	"encoding/json"
	"fmt"
	kb "github.com/libp2p/go-libp2p-kbucket"
	peer "github.com/libp2p/go-libp2p-peer"
	pstore "github.com/libp2p/go-libp2p-peerstore"
	"testing"
	"time"
)

func TestReqFullRoutingTable(t *testing.T) {
	rt := kb.NewRoutingTable(10, kb.ConvertPeerID("test"),
		time.Duration(time.Second*1), pstore.NewMetrics())

	// setup RT
	id1, _ := peer.IDB58Decode("QmWYob8Wax6xqoHydBGkoYtLjp5JVDXrvA47RtyEVnqVjK")
	fmt.Println(id1)
	_, err := rt.Update(id1)
	if err != nil {
		t.Fatal(err)
	}

	id2, _ := peer.IDB58Decode("QmYHnHTuDbYTEZoBypEDQHP7gb6r2krEQQy9F6dy1YTrbz")
	fmt.Println(id2)
	_, err = rt.Update(id2)
	if err != nil {
		t.Fatal(err)
	}

	id3, _ := peer.IDB58Decode("QmSoLPppuBtQSGwKDZT2M73ULpjvfd3aZ6ha4oFGL1KrGM")
	fmt.Println(id3)
	_, err = rt.Update(id3)
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

	id3Res, _ := peer.IDB58Decode(frt[0])
	if id3Res != id3 {
		t.Error(fmt.Sprintf("peerid 3 was not successfully transformed: %v != %v", id3Res, id3))
	}

	id2Res, _ := peer.IDB58Decode(frt[1])
	if id2Res != id2 {
		t.Error(fmt.Sprintf("peerid 2 was not successfully transformed: %v != %v", id2Res, id2))
	}

	id1Res, _ := peer.IDB58Decode(frt[2])
	if id1Res != id1 {
		t.Error(fmt.Sprintf("peerid 1 was not successfully transformed: %v != %v", id1Res, id1))
	}

}
