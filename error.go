package xddr

import (
	"errors"
	"fmt"
)

type ErrorWithPos struct {
	pos int
	err error
}

func errPos(pos int, err error) error {
	return &ErrorWithPos{pos, err}
}

func errPosF(pos int, format string, args ...interface{}) error {
	return &ErrorWithPos{pos, fmt.Errorf(format, args...)}
}

func (e *ErrorWithPos) Error() string {
	return fmt.Sprintf("[%d]: %s", e.pos, e.err.Error())
}

func (e *ErrorWithPos) Unwrap() error {
	return e.err
}

func (e *ErrorWithPos) Pos() int {
	return e.pos
}

func posOf(err error) int {
	var e *ErrorWithPos
	if errors.As(err, &e) {
		return e.pos
	}
	return -1
}

func accPosErr(err error, offset int) error {
	if err == nil {
		return nil
	}

	var e *ErrorWithPos
	if errors.As(err, &e) {
		return errPos(e.pos+offset, e.err)
	}
	return err
}
