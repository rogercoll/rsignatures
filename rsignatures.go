package rsignatures

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"log"
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
	//m := p.Mod(x, p)
	//p1 := p.String()
	p1 := "1415821221623963719413415453263690387336440359920"
	x1 := x.String()
	m := x1 + p1
	fmt.Printf("Encrypt x:  %v\n", x)
	fmt.Printf("Encrypt p:  %v\n", p1)
	hasher := sha1.New()
	hasher.Write([]byte(m))
	mHash := hasher.Sum(nil)
	return new(big.Int).SetBytes(mHash)
}

func (ra *RSARing) g(s, p, n *big.Int) *big.Int {
	return new(big.Int).Exp(s, p, n)
	//q, r := new(big.Int).DivMod(s, n, n)
	//if max := new(big.Int).Mul(n, q.Add(q, big.NewInt(int64(1)))); max.Cmp( {
	//result := new(big.Int).Mul(q, n)
	//return result.Add(result, new(big.Int).Exp(r, p, n))
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

	//u := big.NewInt(int64(13))
	v := r.encrypt(ekp, u)
	c := new(big.Int).Set(v)
	s[0] = big.NewInt(int64(1))
	s[1] = big.NewInt(int64(2))
	s[2] = big.NewInt(int64(3))
	s[3] = big.NewInt(int64(4))
	for i := round + 1; i < len(r.ringKeys); i++ {
		if i != round {

			randKey, err := randomBigInt()
			if err != nil {
				return nil, nil, err
			}
			/*
				//e := r.g(randKey, big.NewInt(int64(r.ringKeys[i].E)), r.ringKeys[i].N)
				e := randKey
			*/
			s[i] = randKey
			e := s[i]
			fmt.Printf("Sign:  %v\n", e)
			v = r.encrypt(ekp, new(big.Int).Xor(v, e))
			fmt.Printf("Sign:  %v\n", v)
			if i+1 == len(r.ringKeys) {
				fmt.Printf("Hello: %v\n", i)
				c = new(big.Int).Set(v)
			}
		}
	}
	for i := round - 1; i >= 0; i-- {
		if i != round {
			randKey, err := randomBigInt()
			if err != nil {
				return nil, nil, err
			}

			/*
				s[i] = append(s[i], randKey.Bytes()...)
				//e := r.g(randKey, big.NewInt(int64(r.ringKeys[i].E)), r.ringKeys[i].N)
				e := randKey
			*/
			s[i] = randKey
			e := s[i]
			fmt.Printf("Sign:  %v\n", e)
			v = r.encrypt(ekp, new(big.Int).Xor(v, e))
			fmt.Printf("Sign:  %v\n", v)
		}
	}
	//sz := r.g(new(big.Int).Xor(v, u), r.ringKeys[round].D, r.ringKeys[round].N)
	s[round] = new(big.Int).Xor(v, u)
	fmt.Printf("Xor: %v\n", new(big.Int).Xor(v, u))
	for _, sig := range s {
		fmt.Printf("Signature: %#v/n", sig.String())
	}
	return c, s, nil
}

func (r *RSARing) Verify(messHash []byte, seed *big.Int, signatures []*big.Int) bool {
	hasher := sha256.New()
	hasher.Write(messHash)
	mHash := hasher.Sum(nil)
	ekp := new(big.Int).SetBytes(mHash)
	result := new(big.Int).Set(seed)
	for _, e := range signatures {
		//fmt.Printf("Verify: %v\n", result)
		//e := new(big.Int).SetBytes(s)
		fmt.Printf("Verify result:  %v\n", result)
		fmt.Printf("Verify y:  %v\n", e)
		fmt.Printf("Second Xor: %v\n", new(big.Int).Xor(result, e))
		result = r.encrypt(ekp, new(big.Int).Xor(result, e))
	}
	log.Println(result)
	log.Println(seed)
	return result.String() == seed.String()
}
