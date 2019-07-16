package sinkhole

import (
	"fmt"
	paillier "github.com/Roasbeef/go-go-gadget-paillier"
	"log"
	"math"
	"math/big"
	"math/rand"
	"reflect"
	"testing"
)

func TestGetIndex(t *testing.T) {
	a := []byte{0}
	a_ex := big.NewInt(0)
	if res := getIndex(a); res.Cmp(a_ex) != 0 {
		t.Error(reflect.TypeOf(res))
		t.Error(reflect.TypeOf(a_ex))
		t.Error(fmt.Sprintf("%v != %v", res, a_ex))
	}

	b := []byte{1, 1}
	b_ex := big.NewInt(257)
	if res := getIndex(b); res.Cmp(b_ex) != 0 {
		t.Error(fmt.Sprintf("%v != %v", res, b_ex))
	}

	// 00000001 00000001 00000011 = 2pow1 + 256 + 3
	c := []byte{1, 1, 3}
	c_ex := big.NewInt(65536 + 256 + 3)
	if res := getIndex(c); res.Cmp(c_ex) != 0 {
		t.Error(fmt.Sprintf("%v != %v", res, c_ex))
	}
}

func TestQueryPaillier(t *testing.T) {

	// 16 bytes IDs, where 4 bytes are the suffix space (represented by
	// "1dfe"), the private space is 8 bytes and the tail space is 16-8+4=4 bytes
	// to lookup for `1dfe fd325f31 112a`, the initiator only discloses `1dfe` and
	// uses the CPIR for querying fd325f31 (the private key)

	space_len := 16
	suffix_space_len := 4
	private_space_len := 2 //4

	// bootstrap server
	privKey, _ := paillier.GenerateKey(rand.New(rand.NewSource(1)), 128)
	sinkhole := New(space_len, suffix_space_len, private_space_len, privKey, privKey.PublicKey)

	// add entry to provider
	// 1dfe003ab24b2213 == value1
	kv_suffix_space := "1dfe"
	k := "1dfe003ab24b22" //16 bytes key
	v := "value1"

	err := sinkhole.Add(kv_suffix_space, []byte(k), []byte(v))
	if err != nil {
		t.Error(err)
	}

	// bootstrap client
	cliPrivKey, _ := paillier.GenerateKey(rand.New(rand.NewSource(2)), 128)

	// query
	// TODO: Refactor!
	num_query_fields := math.Pow(2, float64(8*private_space_len))
	q := make([][]byte, int(num_query_fields))
	q_position := getIndex([]byte(k))

	for i := range q {
		v := []byte{0}
		if int64(i) == q_position.Int64() {
			v = []byte{1}
		}

		el, err := paillier.Encrypt(&cliPrivKey.PublicKey, v)
		if err != nil {
			log.Fatal(err)
		}
		q[i] = el
	}

	array_result, err := sinkhole.Query(kv_suffix_space, q, cliPrivKey.PublicKey)
	if err != nil {
		log.Fatal(err)
	}

	t.Error(array_result)

	// go through result and multiply homomorphically

	// check result
	for i, row := range array_result {
		fmt.Println(i, row)
	}
}
