package sinkhole

import (
	"crypto"
	"encoding/hex"
	//paillier "github.com/Roasbeef/go-go-gadget-paillier"
	"log"
	"math"
	"math/big"
)

type Sinkhole struct {
	space_len         int //bytes
	suffix_space_len  int
	private_space_len int
	buckets           map[string][]bucket
	pk                crypto.PublicKey
	sk                crypto.PrivateKey
}

type bucket struct {
	suffix_space string
	store        [][]byte
}

func New(s_len, ss_len, ps_len int, sk crypto.PrivateKey, pk crypto.PublicKey) Sinkhole {
	buckets := map[string][]bucket{}
	return Sinkhole{s_len, ss_len, ps_len, buckets, pk, sk}
}

func (s *Sinkhole) Query(ss string, q [][]byte) ([][]byte, error) {
	return q, nil
}

func (s *Sinkhole) Add(suffix string, key []byte, value []byte) error {
	b := s.buckets[suffix]

	// if bucket for suffix space of the new key value does not exit yet, create it
	if len(b) == 0 {
		s.buckets[suffix][0] = bucket{
			suffix_space: suffix,
			store:        make([][]byte, int(math.Pow(2, float64(s.private_space_len)))),
		}
		b = s.buckets[suffix]
	}

	// breaks key into [suffix_space:private_space:tail_space]
	// TODO: refactor, add checks for boundaries, etc..
	tail_space := s.space_len - (s.suffix_space_len + s.private_space_len)
	priv_space_key := key[s.suffix_space_len : s.space_len-tail_space]

	index, err := getIndex(string(priv_space_key))
	if err != nil {
		return err
	}

	log.Println(index)

	return nil
}

func (s *Sinkhole) route(sufx string) (bucket, error) {
	return bucket{}, nil
}

func getIndex(s string) (*big.Int, error) {
	idx := big.NewInt(0)
	b, err := hex.DecodeString(s)
	if err != nil {
		return idx, nil
	}
	idx.SetBytes(b)
	return idx, nil
}
