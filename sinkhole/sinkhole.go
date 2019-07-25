package sinkhole

import (
	"crypto"
	"errors"
	"fmt"
	paillier "github.com/Roasbeef/go-go-gadget-paillier"
	"math"
	"math/big"
)

type Sinkhole struct {
	space_len         int //bytes
	suffix_space_len  int
	private_space_len int
	buckets           map[string]bucket
	pk                crypto.PublicKey
	sk                crypto.PrivateKey
}

type bucket struct {
	suffix_space string
	store        [][]byte
}

func New(s_len, ss_len, ps_len int, sk crypto.PrivateKey, pk crypto.PublicKey) Sinkhole {
	buckets := map[string]bucket{}
	return Sinkhole{s_len, ss_len, ps_len, buckets, pk, sk}
}

func (s *Sinkhole) Query(ss string, q [][]byte, pubkey paillier.PublicKey) ([][]byte, error) {
	// select bucket
	var buck bucket
	exists := false
	for k, b := range s.buckets {
		if k == ss {
			buck = b
			exists = true
			break
		}
	}
	if !exists {
		return [][]byte{}, nil
	}

	// go through bucket rowns and multiply homomorphically
	for i, row := range buck.store {

		// TODO: init this before ??
		if len(row) == 0 {
			row = []byte{0}
		}

		q[i] = paillier.Mul(&pubkey, q[i], row)
	}

	return q, nil
}

// TODO: feature more than one entry per row!
func (s *Sinkhole) Add(suffix string, key []byte, value []byte) error {
	b, exists := s.buckets[suffix]

	// if bucket for suffix space of the new key value does not exit yet, create it
	if exists == false {
		num_rows := math.Pow(2, float64(8*s.private_space_len)) // num bits private space == num bucket entries
		s.buckets[suffix] = bucket{
			suffix_space: suffix,
			store:        make([][]byte, int(num_rows)),
		}
		b = s.buckets[suffix]
	}

	index, err := calculateIndex(s.space_len, s.suffix_space_len, s.private_space_len, key)
	if err != nil {
		return err
	}

	b.store[index.Int64()] = value
	return nil
}

func (s *Sinkhole) route(sufx string) (bucket, error) {
	return bucket{}, nil
}

func getIndex(k []byte) *big.Int {
	return big.NewInt(0).SetBytes(k)
}

// breaks key into [suffix_space:private_space:tail_space]
// TODO: refactor, add checks for boundaries, etc..
func calculateIndex(spaceLen, suffixLen, privLen int, key []byte) (*big.Int, error) {
	tailSpace := spaceLen - (suffixLen + privLen)
	privSpaceKey := key[suffixLen : spaceLen-tailSpace]

	for i, _ := range privSpaceKey {
		b, err := hexByte(privSpaceKey[i])
		if err != nil {
			return big.NewInt(0), err
		}
		privSpaceKey[i] = b
	}
	return big.NewInt(0).SetBytes(privSpaceKey), nil
}

func hexByte(b byte) (byte, error) {
	if b >= 48 && b <= 57 {
		return (b - 48), nil
	}
	if b >= 97 && b <= 102 {
		return (b - 87), nil
	}
	return 0, errors.New("out of hex boudaries")
}

var _ = fmt.Sprintf("remove me")
