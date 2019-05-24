package fullrt

import (
	"encoding/json"
	"errors"
	"fmt"
	kb "github.com/libp2p/go-libp2p-kbucket"
	peer "github.com/libp2p/go-libp2p-peer"
)

type RoutingTableProvider interface {
	// returns local full routing table as a stream of bytes
	GetRoutingTable() (error, []byte)
}

// a RoutingTableRaw is a list of peerIDs (multihash) to be sent over wire once
// encoded as byte stream
type RoutingTableRaw []string

type RTProvider struct {
	routingTable interface{}
}

func NewRTProvider(rt interface{}) *RTProvider {
	return &RTProvider{
		routingTable: rt,
	}
}

func (rtp *RTProvider) GetFullRoutingTable() (error, []byte) {
	rt := rtp.routingTable
	rtr := RoutingTableRaw{}

	// for now p3lib only supports libp2p hosts, but in the future more
	// routing table formats can be added. the translation from a particular
	// implementation to the routing table format expected by the protocol is
	// sone here
	switch r := rt.(type) {

	// translate libp2p routing table to raw registry expected by the protocol.
	case *kb.RoutingTable:
		for _, pid := range r.ListPeers() {
			rtr = append(rtr, peer.IDB58Encode(pid))
		}

	default:
		return errors.New("Routing table type not recognized"), []byte("")
	}

	// encodes the routing table
	var buf []byte
	buf, err := json.Marshal(rtr)
	if err != nil {
		return errors.New(fmt.Sprintf("Err encoding raw routing table, %v", err)), []byte("")
	}

	return nil, buf
}
