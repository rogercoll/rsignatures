package rsignatures

import (
	"hash"
)

type Ring interface {
	//Hash of the message will be the encryption key
	Sign(hash.Hash)
	Verify()
	Encrypt()
}

type RSARing struct {

}


func (r *RDSRing) Sign(ek hash.Hash) {
	max := new(big.Int)
max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))

//Generate cryptographically strong pseudo-random between 0 - max
n, err := rand.Int(rand.Reader, max)
if err != nil {
    //error handling
}

}
