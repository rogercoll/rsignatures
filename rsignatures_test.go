package rsignatures

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"testing"
)

func TestSign(t *testing.T) {
	partyKeys := make([]rsa.PrivateKey, 4)
	for i, _ := range partyKeys {
		keyFile, err := ioutil.ReadFile("/home/neck/tmp/ring/keys/private-key.pem") // just pass the file name
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode([]byte(keyFile))
		key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
		//t.Log(key.D)
		partyKeys[i] = *key
	}
	rsaRing := RSARing{ringKeys: partyKeys}
	seed, sig, err := rsaRing.Sign([]byte("hello"), 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(rsaRing.Verify([]byte("hello"), seed, sig))
}
