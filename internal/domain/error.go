package domain

import "errors"

var (
	ErrNotFound = errors.New("item not found")
	ErrExpired  = errors.New("item expired")
	ErrRevoked  = errors.New("item revoked")
)
