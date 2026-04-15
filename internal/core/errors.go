package core

import "errors"

var (
	ErrInvalidRequest             = errors.New("invalid request")
	ErrNotFound                   = errors.New("not found")
	ErrRateLimited                = errors.New("rate limited")
	ErrUnauthorized               = errors.New("unauthorized")
	ErrUnavailable                = errors.New("unavailable")
	ErrForbidden                  = errors.New("forbidden")
	ErrDeliveryModeNotImplemented = errors.New("delivery mode not implemented")
	ErrResourceBudgetExceeded     = errors.New("resource budget exceeded")
)
