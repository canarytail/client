package canarytail_test

import (
	"bytes"
	"encoding/ascii85"
	"testing"

	canarytail "github.com/canarytail/client"

	"github.com/stretchr/testify/assert"
)

func TestSignature(t *testing.T) {

	publicKey, privateKey, err := canarytail.GenerateKeyPair()
	assert.Nil(t, err)

	bb := &bytes.Buffer{}
	encoder := ascii85.NewEncoder(bb)
	encoder.Write([]byte(publicKey))
	encoder.Close()
	publicKeyEncoded := bb.String()

	c1 := canarytail.Canary{
		Claim: canarytail.CanaryClaim{
			PubKey: publicKeyEncoded,
		},
	}
	signature := canarytail.Sign(c1.Claim, privateKey)
	validated := canarytail.ValidateSignature(c1, signature, publicKey)
	assert.True(t, validated)
}
