package jwtmiddleware

import (
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

func Test_invalidError(t *testing.T) {
	t.Run("Is", func(t *testing.T) {
		err := invalidError{details: errors.New("error details")}

		if !errors.Is(err, ErrJWTInvalid) {
			t.Fatal("expected invalidError to be ErrJWTInvalid via errors.Is, but it was not")
		}
	})

	t.Run("Error", func(t *testing.T) {
		err := invalidError{details: errors.New("error details")}
		expectedErrMsg := "jwt invalid: error details"

		assert.EqualError(t, err, expectedErrMsg)
	})

	t.Run("Unwrap", func(t *testing.T) {
		expectedErr := errors.New("expected err")
		err := invalidError{details: expectedErr}

		if !errors.Is(err, expectedErr) {
			t.Fatal("expected invalidError to be expectedErr via errors.Is, but it was not")
		}
	})
}
