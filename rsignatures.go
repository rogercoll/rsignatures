package rsignatures

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

type Ring interface {
	//Hash of the message will be the encryption key
	Sign([]byte) (*big.Int, error)
	Verify()
}

type RSARing struct {
}

func randomBigInt() (*big.Int, error) {
	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))

	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	return n, nil
}

//the encryption function will made the hash of msg(x) % key(p)
func (r *RSARing) encrypt(p, x *big.Int) *big.Int {
	m := p.Mod(x, p)
	hasher := sha256.New()
	hasher.Write(m.Bytes())
	mHash := hasher.Sum(nil)
	return new(big.Int).SetBytes(mHash)
}

func (r *RSARing) Sign(ek []byte) (*big.Int, error) {
	ekp := new(big.Int).SetBytes(ek)
	u, err := randomBigInt()
	if err != nil {
		return nil, err
	}
	v := r.encrypt(ekp, u)
	fmt.Println(v)
	return v, nil

}
