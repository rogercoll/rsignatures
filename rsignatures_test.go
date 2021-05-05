package rsignatures

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestSign(t *testing.T) {
	partyKeys := make([]rsa.PrivateKey, 4)
	for i, _ := range partyKeys {
		randKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		partyKeys[i] = *randKey
	}
	rsaRing := RSARing{ringKeys: partyKeys}
	seed, sig, err := rsaRing.Sign([]byte("hello"), len(partyKeys)-1)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(seed)
	t.Log(rsaRing.Verify([]byte("hello"), seed, sig))
}
