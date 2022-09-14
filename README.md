[![Test](https://github.com/rogercoll/rsignatures/actions/workflows/test.yml/badge.svg)](https://github.com/rogercoll/rsignatures/actions/workflows/test.yml)
# Ring Signatures

**Experimental library: use it at your own risk**

*In cryptography, a ring signature is a type of digital signature that can be performed by any member of a group of users that each have keys. Therefore, a message signed with a ring signature is endorsed by someone in a particular group of people. One of the security properties of a ring signature is that it should be computationally infeasible to determine which of the group members' keys was used to produce the signature.* - [Moneropedia](https://www.getmonero.org/resources/moneropedia/ringsignatures.html)

## Status

- [x] RSA
- [ ] Elliptic curves => TODO(https://github.com/baro77/RingsCS)

## Usage (example)


```go
	...
	//Create RSA ring
	rsaRing := rsignatures.NewRSARing(partyKeys, signerKey)
	seed, sig, err := rsaRing.Sign([]byte("hello"), signerRound)
	if err != nil {
		log.Fatal(err)
	}

	//Verify signature
	log.Println(rsaRing.Verify([]byte("hello"), seed, sig))
	...
```

Full [example](cmd/main.go).
