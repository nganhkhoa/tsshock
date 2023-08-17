//go:build stagenet
// +build stagenet

package avalanche

import (
	_ "embed"
)

//go:embed token_list_stagenet.json
var tokenList []byte
