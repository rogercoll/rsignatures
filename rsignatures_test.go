package rsignatures

import (
	"testing"
)

func TestSign(t *testing.T) {
	rsaRing := RSARing{}
	v, err := rsaRing.Sign([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(v)
}
