package core

import "errors"

var (
	ErrInvalidRequest             = errors.New("invalid request")
	ErrNotFound                   = errors.New("not found")
	ErrUnauthorized               = errors.New("unauthorized")
	ErrForbidden                  = errors.New("forbidden")
	ErrDeliveryModeNotImplemented = errors.New("delivery mode not implemented")
	ErrResourceBudgetExceeded     = errors.New("resource budget exceeded")
)
