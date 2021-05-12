package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	mrand "math/rand"

	"github.com/rogercoll/rsignatures"
)

func main() {
	//Ring participants
	partyKeys := make([]rsa.PublicKey, 10)
	//Random iteration in which the actual issuer will sign the message with its private key
	signerRound := mrand.Intn(len(partyKeys))
	//Signer/Issuer privatekey
	var signerKey rsa.PrivateKey
	//Generation of random keys, this must be changed with your ring members public keys and issuer private key
	for i, _ := range partyKeys {
		randKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}
		if i == signerRound {
			signerKey = *randKey
		}
		partyKeys[i] = *randKey.Public().(*rsa.PublicKey)
	}
	//Create RSA ring
	rsaRing := rsignatures.NewRSARing(partyKeys, signerKey)
	seed, sig, err := rsaRing.Sign([]byte("hello"), signerRound)
	if err != nil {
		log.Fatal(err)
	}

	//Verify signature
	log.Println(rsaRing.Verify([]byte("hello"), seed, sig))
}
