package evm

import (
	"time"
)

// ERC20Token is a struct to represent the token
type ERC20Token struct {
	Address  string `json:"address"`
	Symbol   string `json:"symbol"`
	Name     string `json:"name"`
	Decimals int    `json:"decimals"`
}

type TokenList struct {
	Name      string       `json:"name"`
	LogoURI   string       `json:"logoURI"`
	Tokens    []ERC20Token `json:"tokens"`
	Keywords  []string     `json:"keywords"`
	Timestamp time.Time    `json:"timestamp"`
}
