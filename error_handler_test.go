package jwtmiddleware

import (
	"testing"

	"github.com/pkg/errors"
)

func Test_invalidError(t *testing.T) {
	t.Run("Is", func(t *testing.T) {
		e := invalidError{details: errors.New("error details")}

		if !errors.Is(&e, ErrJWTInvalid) {
			t.Fatal("expected invalidError to be ErrJWTInvalid via errors.Is, but it was not")
		}
	})

	t.Run("Error", func(t *testing.T) {
		e := invalidError{details: errors.New("error details")}

		mustErrorMsg(t, "jwt invalid: error details", &e)
	})

	t.Run("Unwrap", func(t *testing.T) {
		expectedErr := errors.New("expected err")
		e := invalidError{details: expectedErr}

		// under the hood errors.Is is unwrapping the invalidError via Unwrap().
		if !errors.Is(&e, expectedErr) {
			t.Fatal("expected invalidError to be expectedErr via errors.Is, but it was not")
		}
	})
}
