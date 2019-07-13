package sinkhole

import (
	paillier "github.com/Roasbeef/go-go-gadget-paillier"
	"log"
	"math"
	"math/rand"
	"testing"
)

func TestQueryPaillier(t *testing.T) {

	// 16 bytes IDs, where 4 bytes are the suffix space (represented by
	// "1dfe"), the private space is 8 bytes and the tail space is 16-8+4=4 bytes
	// to lookup for `1dfe fd325f31 112a`, the initiator only discloses `1dfe` and
	// uses the CPIR for querying fd325f31 (the private key)

	space_len := 16
	suffix_space_len := 4
	private_space_len := 8

	// bootstrap server
	privKey, _ := paillier.GenerateKey(rand.New(rand.NewSource(1)), 128)
	sinkhole := New(space_len, suffix_space_len, private_space_len, privKey, privKey.PublicKey)

	// add entry to provider
	// 1dfe003ab24b == value1
	kv_suffix_space := "1dfe"
	k := "003ab24b"
	v := "value1"
	err := sinkhole.Add(kv_suffix_space, []byte(k), []byte(v))
	if err != nil {
		t.Error(err)
	}

	// bootstrap client
	cliPrivKey, _ := paillier.GenerateKey(rand.New(rand.NewSource(2)), 128)

	// query
	num_query_fields := math.Pow(2, float64(private_space_len))
	q := make([][]byte, int(num_query_fields))
	q_position := 10

	for i := range q {
		v := []byte{0}
		if i == q_position {
			v = []byte{1}
		}
		el, _, err := paillier.EncryptAndNonce(&cliPrivKey.PublicKey, v)
		if err != nil {
			log.Fatal(err)
		}
		q[i] = el
	}

	res, err := sinkhole.Query(kv_suffix_space, q)
	if err != nil {
		log.Fatal(err)
	}

	t.Error(res)
	t.Error(len(res))
}
