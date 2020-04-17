package main

import (
	"strings"
	"time"
)

type Alert struct {
	Code    string
	Message string
}

var (
	alertInvalidDomain      = "Invalid canary domain"
	alertInvalidReleaseDate = "Invalid canary release date (in future)"
	alertInvalidExpireDate  = "Invalid canary expire date (expired)"
	alertWAR                = "Warrants received"
	alertGAG                = "Gag orders received"
	alertSUBP               = "Subpoenas received"
	alertTRAP               = "Trap and trace orders received"
	alertCEASE              = "Court order to cease operations received"
	alertDURESS             = "Coercion, blackmail, or otherwise operating under duress"
	alertRAID               = "Raids with high confidence nothing containing useful data was seized"
	alertSEIZE              = "Raids with low confidence nothing containing useful data was seized"
	alertXCRED              = "Compromised credentials"
	alertXOPERS             = "Compromised operations"
	// alertSEPPU               = "No Seppuku pledge"

	alertsList = []Alert{
		Alert{Code: "WAR", Message: alertWAR},
		Alert{Code: "GAG", Message: alertGAG},
		Alert{Code: "SUBP", Message: alertSUBP},
		Alert{Code: "TRAP", Message: alertTRAP},
		Alert{Code: "CEASE", Message: alertCEASE},
		Alert{Code: "DURESS", Message: alertDURESS},
		Alert{Code: "RAID", Message: alertRAID},
		Alert{Code: "SEIZE", Message: alertSEIZE},
		Alert{Code: "XCRED", Message: alertXCRED},
		Alert{Code: "XOPERS", Message: alertXOPERS},
		// Alert{Code: "SEPPU", Message: alertSEPPU},
	}
)

func validateMessage(msg *Message, host string) (alerts []string) {
	if !strings.HasPrefix(host, "www") {
		host = "www." + host
	}

	// 1) validate domain
	if msg.Domain != host {
		alerts = append(alerts, alertInvalidDomain)
		return
	}

	// 2) validate release date
	now := time.Now()
	if msg.ReleaseDate.After(now) {
		alerts = append(alerts, alertInvalidReleaseDate)
		return
	}

	// 3) validate expire date
	if msg.ExpireDate.Before(now) {
		alerts = append(alerts, alertInvalidExpireDate)
		return
	}

	// 4) collect the flags
	canaryCodes := make(map[string]bool)
	for _, code := range msg.Codes {
		canaryCodes[code] = true
	}
	for _, alert := range alertsList {
		if !canaryCodes[alert.Code] {
			alerts = append(alerts, alert.Message)
		}
	}

	return
}
