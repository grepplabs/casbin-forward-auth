package server

import (
	"errors"
	"io"
)

type Closers []io.Closer

func (cs *Closers) Add(c io.Closer) {
	if c != nil {
		*cs = append(*cs, c)
	}
}

func (cs *Closers) Close() error {
	var errs []error
	for _, c := range *cs {
		if c != nil {
			if err := c.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

type closeFunc func()

func (f closeFunc) Close() error {
	f()
	return nil
}
