package tyche

import (
	"fmt"

	"Tyche/Tyche/crypto"
)

type PVSSContextStatus string

const (
	PVSSActive     PVSSContextStatus = "active"
	PVSSHistorical PVSSContextStatus = "historical"
)

// PVSSContext retains the setup that verifies and opens an RBC-delivered
// object. Historical contexts stay available while such objects remain in
// ComQ; no retirement messages or entropy mixing are required.
type PVSSContext struct {
	Configuration Configuration
	Params        crypto.PVSSParams
	Scheme        crypto.PVSSScheme
	Status        PVSSContextStatus
}

func rbcCertificateKey(version uint64, objectID string) string {
	return fmt.Sprintf("%d/%s", version, objectID)
}
