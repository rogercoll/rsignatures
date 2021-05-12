package rsignatures

import (
	"crypto/rand"
	"crypto/rsa"
	mrand "math/rand"
	"testing"
)

func TestSign(t *testing.T) {
	partyKeys := make([]*rsa.PublicKey, 10)
	signerRound := mrand.Intn(len(partyKeys))
	var signerKey *rsa.PrivateKey
	for i, _ := range partyKeys {
		randKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		if i == signerRound {
			signerKey = randKey
		}
		partyKeys[i] = randKey.Public().(*rsa.PublicKey)
	}
	rsaRing := RSARing{ringKeys: partyKeys, signer: signerKey}
	seed, sig, err := rsaRing.Sign([]byte("hello"), signerRound)
	if err != nil {
		t.Fatal(err)
	}

	//Check with other message
	notok := rsaRing.Verify([]byte("goodbye"), seed, sig)
	if notok {
		t.Errorf("Signature verification mismatch: got %t, want %t", notok, false)
	}
	//Check correct signature
	ok := rsaRing.Verify([]byte("hello"), seed, sig)
	if !ok {
		t.Errorf("Signature verification mismatch: got %t, want %t", ok, true)
	}
	//Modify one key
	randKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	partyKeys[mrand.Intn(len(partyKeys))] = randKey.Public().(*rsa.PublicKey)
	forgedRsaRing := RSARing{ringKeys: partyKeys}
	notok2 := forgedRsaRing.Verify([]byte("hello"), seed, sig)
	if notok2 {
		t.Errorf("Signature verification mismatch: got %t, want %t", notok2, false)
	}
}

func benchmarkSign(i int, b *testing.B) {
	partyKeys := make([]*rsa.PublicKey, i)
	signerRound := mrand.Intn(len(partyKeys))
	var signerKey *rsa.PrivateKey
	for i, _ := range partyKeys {
		randKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			b.Fatal(err)
		}
		if i == signerRound {
			signerKey = randKey
		}
		partyKeys[i] = randKey.Public().(*rsa.PublicKey)
	}
	rsaRing := RSARing{ringKeys: partyKeys, signer: signerKey}
	_, _, err := rsaRing.Sign([]byte("hello"), signerRound)
	if err != nil {
		b.Fatal(err)
	}
}

func BenchmarkSign5(b *testing.B)   { benchmarkSign(5, b) }
func BenchmarkSign10(b *testing.B)  { benchmarkSign(10, b) }
func BenchmarkSign20(b *testing.B)  { benchmarkSign(20, b) }
func BenchmarkSign50(b *testing.B)  { benchmarkSign(50, b) }
func BenchmarkSign100(b *testing.B) { benchmarkSign(100, b) }
