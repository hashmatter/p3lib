package frt

import (
	"encoding/json"
	"errors"
	"fmt"
	kb "github.com/libp2p/go-libp2p-kbucket"
	b58 "github.com/mr-tron/base58/base58"
)

type RoutingTableProviderRequester interface {
	// returns local full routing table as a stream of bytes
	GetRoutingTable() (error, []byte)
}

// a RoutingTableRaw is a list of peerIDs (multihash) to be sent over wire once
// encoded as byte stream
type RoutingTableRaw []string

type RTProviderRequester struct {
	routingTable interface{}
}

func NewRTProviderRequester(rt interface{}) *RTProviderRequester {
	return &RTProviderRequester{
		routingTable: rt,
	}
}

func (rtp *RTProviderRequester) GetFullRoutingTable() (error, []byte) {
	rt := rtp.routingTable
	rtr := RoutingTableRaw{}

	// for now p3lib only supports libp2p hosts, but in the future more
	// node implementations can be added. the translation from a particular
	// implementation to the routing table format expected by the protocol is
	// performed here
	switch r := rt.(type) {

	// translate libp2p routing table to raw registry expected by the protocol
	case *kb.RoutingTable:
		for _, pid := range r.ListPeers() {
			rtr = append(rtr, b58.Encode([]byte(pid)))
		}

	default:
		return errors.New("Routing table type not recognized"), []byte("")
	}

	var buf []byte
	buf, err := json.Marshal(rtr)
	if err != nil {
		return errors.New(fmt.Sprintf("Err encoding raw routing table, %v", err)), []byte("")
	}

	return nil, buf
}
