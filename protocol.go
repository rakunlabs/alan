package alan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Message types for the on-stream protocol. The first byte of every QUIC stream
// is a MsgType. The framing that follows depends on the type — see the
// Read*/Write* helpers below.
const (
	// MsgTypeData is a fire-and-forget data message. After the type byte and
	// type-name header, the body is delivered as a stream terminated by FIN
	// (no length prefix). Both the sender and receiver may stream the body
	// without buffering it.
	MsgTypeData byte = 0x10
	// MsgTypeRequest is an RPC request expecting a response. Bytes-only;
	// body is length-prefixed (varint) and capped by Config.MaxMessageSize.
	MsgTypeRequest byte = 0x20
	// MsgTypeResponse is an RPC response. Bytes-only; body is length-prefixed
	// and capped by Config.MaxMessageSize.
	MsgTypeResponse byte = 0x21
	// MsgTypeLockRequest acquires a distributed lock.
	MsgTypeLockRequest byte = 0x30
	// MsgTypeLockGrant grants a lock to the requester.
	MsgTypeLockGrant byte = 0x31
	// MsgTypeLockDeny denies a lock request (already held).
	MsgTypeLockDeny byte = 0x32
	// MsgTypeLockRelease notifies that a lock has been released.
	MsgTypeLockRelease byte = 0x33
	// MsgTypeLeave is a graceful leave announcement. The frame consists of
	// just the type byte (no body, no length prefix). The sender's identity
	// is taken from the QUIC connection's RemoteAddr. Receivers fire the
	// OnPeerLeave callback immediately rather than waiting for the QUIC
	// idle timeout to detect the disconnection.
	MsgTypeLeave byte = 0x40
)

// RequestIDSize is the size of request/response correlation IDs in bytes.
const RequestIDSize = 16

// MaxTypeBytes is the wire limit for the message-type string (uint16-prefixed).
const MaxTypeBytes = 65535

// MaxLockKeyBytes is the wire limit for a lock key (uint16-prefixed).
const MaxLockKeyBytes = 65535

// ErrFrameTooLarge is returned when a length-prefixed frame announces a body
// larger than the receiver is willing to allocate.
var ErrFrameTooLarge = errors.New("alan: frame exceeds maximum allowed size")

// ErrMalformedFrame is returned for any structural protocol violation
// (truncated headers, oversized type strings, etc).
var ErrMalformedFrame = errors.New("alan: malformed frame")

// ─────────────────────────────────────────────────────────────────────────────
// MsgType byte
// ─────────────────────────────────────────────────────────────────────────────

func writeMsgType(w io.Writer, t byte) error {
	_, err := w.Write([]byte{t})
	return err
}

func readMsgType(r io.Reader) (byte, error) {
	var buf [1]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return buf[0], nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Data frame: [MsgTypeData:1][TypeLen:2][Type:T] <body until FIN>
// ─────────────────────────────────────────────────────────────────────────────

// writeDataHeader writes the MsgTypeData byte followed by the type-name
// header. After this returns, the caller streams the body and closes the
// stream's write side to signal end of message.
func writeDataHeader(w io.Writer, msgType string) error {
	if len(msgType) > MaxTypeBytes {
		return fmt.Errorf("alan: message type exceeds %d bytes", MaxTypeBytes)
	}
	hdr := make([]byte, 1+2+len(msgType))
	hdr[0] = MsgTypeData
	binary.BigEndian.PutUint16(hdr[1:3], uint16(len(msgType)))
	copy(hdr[3:], msgType)
	_, err := w.Write(hdr)
	return err
}

// readDataHeader reads the type-name header that follows a MsgTypeData byte.
// The MsgType byte must already have been consumed by the caller.
func readDataHeader(r io.Reader) (msgType string, err error) {
	var lenBuf [2]byte
	if _, err = io.ReadFull(r, lenBuf[:]); err != nil {
		return "", err
	}
	tlen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if tlen == 0 {
		return "", nil
	}
	buf := make([]byte, tlen)
	if _, err = io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Request frame:
//   [MsgTypeRequest:1][RequestID:16][TypeLen:2][Type:T][BodyLen:varint][Body]
// ─────────────────────────────────────────────────────────────────────────────

// writeRequestFrame writes a complete request frame including the MsgType byte.
func writeRequestFrame(w io.Writer, reqID []byte, msgType string, body []byte) error {
	if len(reqID) != RequestIDSize {
		return fmt.Errorf("alan: request id must be %d bytes", RequestIDSize)
	}
	if len(msgType) > MaxTypeBytes {
		return fmt.Errorf("alan: message type exceeds %d bytes", MaxTypeBytes)
	}

	hdr := make([]byte, 1+RequestIDSize+2+len(msgType)+binary.MaxVarintLen64)
	off := 0
	hdr[off] = MsgTypeRequest
	off++
	copy(hdr[off:off+RequestIDSize], reqID)
	off += RequestIDSize
	binary.BigEndian.PutUint16(hdr[off:off+2], uint16(len(msgType)))
	off += 2
	copy(hdr[off:off+len(msgType)], msgType)
	off += len(msgType)
	off += binary.PutUvarint(hdr[off:], uint64(len(body)))

	if _, err := w.Write(hdr[:off]); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
	return nil
}

// readRequestFrame reads a request frame after the MsgType byte has been
// consumed. The body size is bounded by max (use a negative value to disable
// the cap, but that's a foot-gun).
func readRequestFrame(r io.Reader, max int64) (reqID []byte, msgType string, body []byte, err error) {
	reqID = make([]byte, RequestIDSize)
	if _, err = io.ReadFull(r, reqID); err != nil {
		return nil, "", nil, err
	}

	var typeLenBuf [2]byte
	if _, err = io.ReadFull(r, typeLenBuf[:]); err != nil {
		return nil, "", nil, err
	}
	tlen := int(binary.BigEndian.Uint16(typeLenBuf[:]))
	if tlen > 0 {
		typeBuf := make([]byte, tlen)
		if _, err = io.ReadFull(r, typeBuf); err != nil {
			return nil, "", nil, err
		}
		msgType = string(typeBuf)
	}

	br := newByteReader(r)
	bodyLen, err := binary.ReadUvarint(br)
	if err != nil {
		return nil, "", nil, fmt.Errorf("alan: read body length: %w", err)
	}
	if max >= 0 && bodyLen > uint64(max) {
		return nil, "", nil, ErrFrameTooLarge
	}
	if bodyLen > 0 {
		body = make([]byte, bodyLen)
		if _, err = io.ReadFull(r, body); err != nil {
			return nil, "", nil, err
		}
	}
	return reqID, msgType, body, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Response frame:
//   [MsgTypeResponse:1][RequestID:16][BodyLen:varint][Body]
// ─────────────────────────────────────────────────────────────────────────────

func writeResponseFrame(w io.Writer, reqID []byte, body []byte) error {
	if len(reqID) != RequestIDSize {
		return fmt.Errorf("alan: request id must be %d bytes", RequestIDSize)
	}

	hdr := make([]byte, 1+RequestIDSize+binary.MaxVarintLen64)
	off := 0
	hdr[off] = MsgTypeResponse
	off++
	copy(hdr[off:off+RequestIDSize], reqID)
	off += RequestIDSize
	off += binary.PutUvarint(hdr[off:], uint64(len(body)))

	if _, err := w.Write(hdr[:off]); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
	return nil
}

func readResponseFrame(r io.Reader, max int64) (reqID []byte, body []byte, err error) {
	reqID = make([]byte, RequestIDSize)
	if _, err = io.ReadFull(r, reqID); err != nil {
		return nil, nil, err
	}

	br := newByteReader(r)
	bodyLen, err := binary.ReadUvarint(br)
	if err != nil {
		return nil, nil, fmt.Errorf("alan: read body length: %w", err)
	}
	if max >= 0 && bodyLen > uint64(max) {
		return nil, nil, ErrFrameTooLarge
	}
	if bodyLen > 0 {
		body = make([]byte, bodyLen)
		if _, err = io.ReadFull(r, body); err != nil {
			return nil, nil, err
		}
	}
	return reqID, body, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Lock frame:
//   [MsgType:1 (one of 0x30..0x33)][RequestID:16][KeyLen:2][Key]
// ─────────────────────────────────────────────────────────────────────────────

func writeLockFrame(w io.Writer, msgType byte, reqID []byte, key string) error {
	if len(reqID) != RequestIDSize {
		return fmt.Errorf("alan: request id must be %d bytes", RequestIDSize)
	}
	if len(key) > MaxLockKeyBytes {
		return fmt.Errorf("alan: lock key exceeds %d bytes", MaxLockKeyBytes)
	}

	frame := make([]byte, 1+RequestIDSize+2+len(key))
	off := 0
	frame[off] = msgType
	off++
	copy(frame[off:off+RequestIDSize], reqID)
	off += RequestIDSize
	binary.BigEndian.PutUint16(frame[off:off+2], uint16(len(key)))
	off += 2
	copy(frame[off:off+len(key)], key)

	_, err := w.Write(frame)
	return err
}

// readLockFrame reads the body of a lock-family frame. The MsgType byte must
// already have been consumed by the caller.
func readLockFrame(r io.Reader) (reqID []byte, key string, err error) {
	reqID = make([]byte, RequestIDSize)
	if _, err = io.ReadFull(r, reqID); err != nil {
		return nil, "", err
	}

	var keyLenBuf [2]byte
	if _, err = io.ReadFull(r, keyLenBuf[:]); err != nil {
		return nil, "", err
	}
	klen := int(binary.BigEndian.Uint16(keyLenBuf[:]))
	if klen == 0 {
		return reqID, "", nil
	}
	keyBuf := make([]byte, klen)
	if _, err = io.ReadFull(r, keyBuf); err != nil {
		return nil, "", err
	}
	return reqID, string(keyBuf), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Leave frame: [MsgTypeLeave:1]
// ─────────────────────────────────────────────────────────────────────────────

// writeLeaveFrame writes a graceful leave announcement (just the type byte).
// The caller is expected to FIN the stream after this returns.
func writeLeaveFrame(w io.Writer) error {
	return writeMsgType(w, MsgTypeLeave)
}

// ─────────────────────────────────────────────────────────────────────────────
// io.ByteReader adapter (binary.ReadUvarint requires it)
// ─────────────────────────────────────────────────────────────────────────────

type byteReader struct {
	r   io.Reader
	buf [1]byte
}

func newByteReader(r io.Reader) *byteReader { return &byteReader{r: r} }

func (b *byteReader) ReadByte() (byte, error) {
	if _, err := io.ReadFull(b.r, b.buf[:]); err != nil {
		return 0, err
	}
	return b.buf[0], nil
}
