package main

import (
	"strings"
	"time"
)

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
	alertSEPU               = "No Seppuku pledge"

	alertsMap = map[string]string{
		"WAR":    alertWAR,
		"GAG":    alertGAG,
		"SUBP":   alertSUBP,
		"TRAP":   alertTRAP,
		"CEASE":  alertCEASE,
		"DURESS": alertDURESS,
		"RAID":   alertRAID,
		"SEIZE":  alertSEIZE,
		"XCRED":  alertXCRED,
		"XOPERS": alertXOPERS,
		"SEPU":   alertSEPU,
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
	for code, val := range msg.Codes {
		if (val == 0 && code != "SEPU") || (val == 1 && code == "SEPU") {
			continue
		}

		if alert, ok := alertsMap[code]; ok {
			alerts = append(alerts, alert)
		}
	}

	return
}
