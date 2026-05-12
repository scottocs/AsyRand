package grandline

import (
	"fmt"

	"go.dedis.ch/kyber/v3/pairing/bn256"
)

func roundKey(epoch uint64) string {
	return fmt.Sprintf("epoch:%d", epoch)
}

func pairingSuite() *bn256.Suite {
	return bn256.NewSuite()
}
