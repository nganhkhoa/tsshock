package avalanche

import (
	"fmt"

	ecore "github.com/ethereum/go-ethereum/core"
	. "gopkg.in/check.v1"
)

type HelpersTestSuite struct{}

var _ = Suite(&HelpersTestSuite{})

func (s *HelpersTestSuite) TestIsAcceptableError(c *C) {
	c.Assert(isAcceptableError(nil), Equals, true)
	c.Assert(isAcceptableError(ecore.ErrAlreadyKnown), Equals, true)
	c.Assert(isAcceptableError(ecore.ErrNonceTooLow), Equals, true)
	c.Assert(isAcceptableError(fmt.Errorf("%w: foo", ecore.ErrNonceTooLow)), Equals, true)
	c.Assert(isAcceptableError(fmt.Errorf("foo: %w", ecore.ErrNonceTooLow)), Equals, false)
}
