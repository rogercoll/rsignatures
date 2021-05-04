package rsignatures

import (
	"testing"
)

func TestSign(t *testing.T) {
	rsaRing := RSARing{}
	v, _, err := rsaRing.Sign([]byte("hello"), 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(v)
}
