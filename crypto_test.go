package canarytail_test

import (
	"testing"

	canarytail "github.com/canarytail/client"

	"github.com/stretchr/testify/assert"
)

func TestSignature(t *testing.T) {

	publicKey, privateKey, err := canarytail.GenerateKeyPair()
	assert.Nil(t, err)

	c1 := canarytail.Canary{
		Claim: canarytail.CanaryClaim{
			Domain:     "test",
			PublicKeys: []string{canarytail.FormatKey(publicKey)},
		},
	}
	signature := canarytail.SignString(c1.Claim.Domain, privateKey)
	validated := canarytail.ValidateSignatureString(c1.Claim.Domain, signature, publicKey)
	assert.True(t, validated)
}
