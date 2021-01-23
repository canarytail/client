package canarytail_test

import (
	"testing"
	"time"

	canarytail "github.com/canarytail/client"

	"github.com/stretchr/testify/assert"
)

func TestInverseCodes(t *testing.T) {
	assert.ElementsMatch(t, []string{"xopers", "war", "subp", "seize", "xcred", "raid", "gag", "trap", "cease"}, canarytail.InverseCodes([]string{"duress"}))
	assert.ElementsMatch(t, canarytail.AllCodes(), canarytail.InverseCodes([]string{}))
	assert.ElementsMatch(t, []string{}, canarytail.InverseCodes(canarytail.AllCodes()))
}

func TestMissingCodes(t *testing.T) {

	c1 := canarytail.Canary{
		Claim: canarytail.CanaryClaim{
			Codes: []string{"SUBP"},
		},
	}

	c2 := canarytail.Canary{
		Claim: canarytail.CanaryClaim{
			Codes: []string{},
		},
	}

	assert.ElementsMatch(t, c1.MissingCodes(), []string{"xopers", "war", "seize", "xcred", "raid", "gag", "trap", "cease", "duress"})
	assert.ElementsMatch(t, c2.MissingCodes(), canarytail.AllCodes())
}

func TestIsExpired(t *testing.T) {
	c1 := canarytail.Canary{
		Claim: canarytail.CanaryClaim{
			Expiry: "2206-01-02T15:04:05+01:00",
		},
	}

	c2 := canarytail.Canary{
		Claim: canarytail.CanaryClaim{
			Expiry: "2006-01-02T15:04:05+01:00",
		},
	}

	c3 := canarytail.Canary{
		Claim: canarytail.CanaryClaim{
			Expiry: time.Now().Format(canarytail.TimestampLayout),
		},
	}

	assert.False(t, c1.IsExpired())
	assert.True(t, c2.IsExpired())
	assert.True(t, c3.IsExpired())
}

func TestCanarySignature(t *testing.T) {

	publicKey, privateKey, err := canarytail.GenerateKeyPair()
	assert.Nil(t, err)

	c1 := canarytail.Canary{
		Claim: canarytail.CanaryClaim{
			Domain:     "test",
			PublicKeys: []string{canarytail.FormatKey(publicKey)},
		},
	}

	err = c1.Sign(privateKey, publicKey)
	assert.Nil(t, err)

	assert.True(t, c1.ValidateSignatures(publicKey))

	c2 := canarytail.Canary{
		Claim: canarytail.CanaryClaim{
			Domain:     "test",
			PublicKeys: []string{canarytail.FormatKey(publicKey)},
			Codes:      canarytail.AllCodes(),
		},
	}

	err = c2.Sign(privateKey, publicKey)
	assert.Nil(t, err)

	assert.True(t, c2.ValidateSignatures(publicKey))
}
