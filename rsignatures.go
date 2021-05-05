package rsignatures

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"reflect"
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

func (ra *RSARing) g(s, p, n *big.Int) *big.Int {
	return new(big.Int).Exp(s, p, n)
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
			randKey, err := randomBigInt()
			if err != nil {
				return nil, nil, err
			}
			s[i] = append(s[i], randKey.Bytes()...)
			e := r.g(randKey, big.NewInt(int64(r.ringKeys[i].E)), r.ringKeys[i].N)
			v = r.encrypt(ekp, new(big.Int).Xor(v, e))
		}
	}
	sz := new(big.Int).Exp(r.encrypt(ekp, v), r.ringKeys[round].D, r.ringKeys[round].N)
	s[round] = append(s[round], sz.Bytes()...)
	return c.Bytes(), s, nil

}

func (r *RSARing) Verify(messHash, seed []byte, signatures [][]byte) bool {
	result := new(big.Int).SetBytes(seed)
	ekp := new(big.Int).SetBytes(seed)
	for i, s := range signatures {
		e := r.g(new(big.Int).SetBytes(s), big.NewInt(int64(r.ringKeys[i].E)), r.ringKeys[i].N)
		result = r.encrypt(ekp, new(big.Int).Xor(ekp, e))
	}
	return reflect.DeepEqual(result.Bytes(), messHash)
}
