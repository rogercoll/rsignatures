package rsignatures

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"math/big"
)

type Ring interface {
	//Hash of the message will be the encryption key
	Sign([]byte, int) ([]byte, []byte, error)
	Verify() bool
}

type RSARing struct {
	ringKeys []*rsa.PublicKey
	signer   *rsa.PrivateKey
}

func NewRSARing(_ringKeys []*rsa.PublicKey, _signer *rsa.PrivateKey) *RSARing {
	return &RSARing{ringKeys: _ringKeys, signer: _signer}
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
	m := x.String() + p.String()
	hasher := sha1.New()
	hasher.Write([]byte(m))
	mHash := hasher.Sum(nil)
	return new(big.Int).SetBytes(mHash)
}

func (ra *RSARing) g(s, p, n *big.Int) *big.Int {
	q, _ := new(big.Int).DivMod(s, new(big.Int).Set(n), new(big.Int).Set(n))
	r := new(big.Int).Mod(s, n)
	result := new(big.Int).Add(new(big.Int).Mul(q, n), new(big.Int).Exp(r, p, n))
	return result
}

//returns the seed and the signatures of all ring members
func (r *RSARing) Sign(ek []byte, round int) (*big.Int, []*big.Int, error) {
	s := make([]*big.Int, len(r.ringKeys))
	hasher := sha256.New()
	hasher.Write(ek)
	mHash := hasher.Sum(nil)
	ekp := new(big.Int).SetBytes(mHash)
	u, err := randomBigInt()
	if err != nil {
		return nil, nil, err
	}
	v := r.encrypt(ekp, u)
	c := new(big.Int).Set(v)

	loopKeys := make([]int, len(r.ringKeys)-1)
	for i := 0; i < len(r.ringKeys)-1; i++ {
		loopKeys[i] = (round + i + 1) % len(r.ringKeys)
	}

	for _, i := range loopKeys {
		randKey, err := randomBigInt()
		if err != nil {
			return nil, nil, err
		}
		s[i] = randKey
		e := r.g(s[i], big.NewInt(int64(r.ringKeys[i].E)), r.ringKeys[i].N)
		v = r.encrypt(ekp, new(big.Int).Xor(v, e))
		if (i+1)%len(r.ringKeys) == 0 {
			c = new(big.Int).Set(v)
		}
	}

	sz := r.g(new(big.Int).Xor(v, u), r.signer.D, r.signer.N)
	s[round] = sz
	return c, s, nil
}

func (r *RSARing) Verify(messHash []byte, seed *big.Int, signatures []*big.Int) bool {
	hasher := sha256.New()
	hasher.Write(messHash)
	mHash := hasher.Sum(nil)
	ekp := new(big.Int).SetBytes(mHash)
	result := new(big.Int).Set(seed)
	for i, s := range signatures {
		e := r.g(s, big.NewInt(int64(r.ringKeys[i].E)), r.ringKeys[i].N)
		result = r.encrypt(ekp, new(big.Int).Xor(result, e))
	}
	return result.String() == seed.String()
}
