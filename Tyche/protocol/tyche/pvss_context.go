package tyche

import "Tyche/Tyche/crypto"

// PVSSContext is the immutable setup used by every slot in the fixed party set.
type PVSSContext struct {
	Configuration Configuration
	Params        crypto.PVSSParams
	Scheme        crypto.PVSSScheme
}
