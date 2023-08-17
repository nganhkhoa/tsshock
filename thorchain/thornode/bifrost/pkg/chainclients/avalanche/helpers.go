package avalanche

import (
	"strings"

	ecore "github.com/ethereum/go-ethereum/core"
)

func isAcceptableError(err error) bool {
	return err == nil || err.Error() == ecore.ErrAlreadyKnown.Error() || strings.HasPrefix(err.Error(), ecore.ErrNonceTooLow.Error())
}
