//go:build !testnet && !mocknet && !stagenet
// +build !testnet,!mocknet,!stagenet

package avalanche

import (
	_ "embed"
)

//go:embed token_list.json
var tokenList []byte
