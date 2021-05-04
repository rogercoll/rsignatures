package rsignatures

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
)

type Ring interface {
	//Hash of the message will be the encryption key
	Sign([]byte, int) ([]byte, []byte, error)
	Verify() bool
}

type RSARing struct {
	ringKeys []rsa.PrivateKey
	ringMems int
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

//returns the seed and the signatures of all ring members
func (r *RSARing) Sign(ek []byte, round int) ([]byte, [][]byte, error) {
	s := make([][]byte, len(r.ringKeys))
	ekp := new(big.Int).SetBytes(ek)
	u, err := randomBigInt()
	if err != nil {
		return nil, nil, err
	}
	v := r.encrypt(ekp, u)
	c := new(big.Int).Set(v)
	for i := 0; i < len(r.ringKeys)-1; i++ {
		if i != round {
			//random created keys should sign the value here
		}
	}
	return c.Bytes(), s, nil

}
