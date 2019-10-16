package stun

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
)

type hexlogger struct {
	w   io.Writer
	err error
	pre string
}

func NewHexLogger(pre string, w io.Writer) io.Writer {
	return &hexlogger{pre: pre, w: w}
}

func (h *hexlogger) Write(p []byte) (n int, err error) {
	fmt.Printf("%s:\n%s", h.pre, hex.Dump(p))

	// perform any necessary edits

	for len(p) > 0 && h.err == nil {
		var written int
		written, h.err = h.w.Write(p)
		n += written
		p = p[written:]
	}
	return n, h.err
}
