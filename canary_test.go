package canarytail_test

import (
	"testing"
	"time"

	canarytail "github.com/canarytail/client"

	"github.com/stretchr/testify/assert"
)

func TestInverseCodes(t *testing.T) {
	assert.ElementsMatch(t, []string{"XOPERS", "WAR", "SUBP", "SEIZE", "XCRED", "RAID", "GAG", "TRAP", "CEASE", "DURESS"}, canarytail.InverseCodes([]string{"SEPPU"}))
	assert.ElementsMatch(t, canarytail.AllCodes(), canarytail.InverseCodes([]string{}))
	assert.ElementsMatch(t, []string{}, canarytail.InverseCodes(canarytail.AllCodes()))
}

func TestMissingCodes(t *testing.T) {

	c1 := canarytail.Canary{
		Claim: canarytail.CanaryClaim{
			Codes: []string{"SEPPU"},
		},
	}

	c2 := canarytail.Canary{
		Claim: canarytail.CanaryClaim{
			Codes: []string{},
		},
	}

	assert.ElementsMatch(t, c1.MissingCodes(), []string{"XOPERS", "WAR", "SUBP", "SEIZE", "XCRED", "RAID", "GAG", "TRAP", "CEASE", "DURESS"})
	assert.ElementsMatch(t, c2.MissingCodes(), canarytail.AllCodes())
}

func TestIsExpired(t *testing.T) {
	c1 := canarytail.Canary{
		Claim: canarytail.CanaryClaim{
			Expire: "2206-01-02T15:04:05+01:00",
		},
	}

	c2 := canarytail.Canary{
		Claim: canarytail.CanaryClaim{
			Expire: "2006-01-02T15:04:05+01:00",
		},
	}

	c3 := canarytail.Canary{
		Claim: canarytail.CanaryClaim{
			Expire: time.Now().Format(canarytail.TimestampLayout),
		},
	}

	assert.False(t, c1.IsExpired())
	assert.True(t, c2.IsExpired())
	assert.True(t, c3.IsExpired())
}
