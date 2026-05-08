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
	// MsgTypeLockMux opens a long-lived per-peer lock-multiplex channel.
	// The first byte of a uni-directional stream of this type marks it as
	// the lock channel; the rest of the stream carries an unbounded
	// sequence of length-prefixed lock frames (see writeLockMuxFrame).
	// FIFO within this stream is what gives lock messages their ordering
	// guarantee — without it, separate streams reorder freely and Release
	// can clobber a freshly-acquired HeldBy entry.
	MsgTypeLockMux byte = 0x50
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
// Modular sequence-number comparison
//
// Both the per-peer outbound sequence counter (Peer.outboundSeq) and
// the per-peer outbound epoch counter (Peer.outboundEpoch) are uint64
// values that the sender increments with sync/atomic and that wrap
// naturally on overflow. Receivers compare them with these helpers
// rather than the built-in `<` so a value just past 2^64-1 is correctly
// recognised as "after" a value just below 2^64-1.
//
// The trick — borrowed from TCP's PAWS (RFC 1323 §4.2) and from many
// other reliable-transport ACK schemes — is to subtract under uint64
// modular arithmetic and reinterpret the result as a signed int64. As
// long as the two values being compared are within 2^63 of each other,
// the sign of (a - b) reliably tells you which one is "later".
//
// Practical headroom: receiver pending buffers are bounded by
// MessageQueueSize (default 256), so the gap between nextSeq and the
// largest in-flight seq never approaches 2^63 (~9.2 × 10^18) under any
// realistic workload.
// ─────────────────────────────────────────────────────────────────────────────

// seqAfter reports whether `a` is later than `b` in the modular uint64
// sequence space. Equivalent to "(a - b) > 0" if you treated both as
// signed 64-bit values.
func seqAfter(a, b uint64) bool { return int64(a-b) > 0 }

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
// Data frame:
//   [MsgTypeData:1][Epoch:8][Seq:8][TypeLen:2][Type:T] <body until FIN>
//
// Epoch is a random 64-bit identifier for the current sender→receiver
// connection era; it changes every time the Peer record is recreated
// (typically on QUIC reconnect). The receiver compares Epoch to the
// last-seen value: if it differs, the in-order dispatch state is reset
// (nextSeq←1, pending cleared) before this frame is processed. Without
// Epoch, a reconnected sender that resets its Seq counter to 1 would be
// drop-detected as a replay against the receiver's stale nextSeq.
//
// Seq is a per-(sender, receiver, epoch) monotonic sequence number that
// the receiver uses to dispatch messages to byte handlers in send order
// even when multiple QUIC streams race body completion. Streaming
// handlers (HandleStream) ignore Seq.
//
// Seq=0 is reserved for messages that bypass per-peer ordering (the
// receiver dispatches them as soon as the body is ready). Sender code
// uses 1-based sequencing. Epoch=0 is reserved as "uninitialised" and
// MUST NOT appear on the wire.
// ─────────────────────────────────────────────────────────────────────────────

// writeDataHeader writes the MsgTypeData byte followed by the
// connection epoch, per-peer sequence number, and type-name header.
// After this returns, the caller streams the body and closes the
// stream's write side to signal end of message.
func writeDataHeader(w io.Writer, epoch, seq uint64, msgType string) error {
	if len(msgType) > MaxTypeBytes {
		return fmt.Errorf("alan: message type exceeds %d bytes", MaxTypeBytes)
	}
	hdr := make([]byte, 1+8+8+2+len(msgType))
	hdr[0] = MsgTypeData
	binary.BigEndian.PutUint64(hdr[1:9], epoch)
	binary.BigEndian.PutUint64(hdr[9:17], seq)
	binary.BigEndian.PutUint16(hdr[17:19], uint16(len(msgType)))
	copy(hdr[19:], msgType)
	_, err := w.Write(hdr)
	return err
}

// readDataHeader reads the connection epoch, per-peer sequence number,
// and type-name header that follow a MsgTypeData byte. The MsgType byte
// must already have been consumed by the caller.
func readDataHeader(r io.Reader) (epoch, seq uint64, msgType string, err error) {
	var epochBuf [8]byte
	if _, err = io.ReadFull(r, epochBuf[:]); err != nil {
		return 0, 0, "", err
	}
	epoch = binary.BigEndian.Uint64(epochBuf[:])

	var seqBuf [8]byte
	if _, err = io.ReadFull(r, seqBuf[:]); err != nil {
		return 0, 0, "", err
	}
	seq = binary.BigEndian.Uint64(seqBuf[:])

	var lenBuf [2]byte
	if _, err = io.ReadFull(r, lenBuf[:]); err != nil {
		return 0, 0, "", err
	}
	tlen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if tlen == 0 {
		return epoch, seq, "", nil
	}
	buf := make([]byte, tlen)
	if _, err = io.ReadFull(r, buf); err != nil {
		return 0, 0, "", err
	}
	return epoch, seq, string(buf), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Request frame:
//   [MsgTypeRequest:1][Epoch:8][Seq:8][RequestID:16][TypeLen:2][Type:T][BodyLen:varint][Body]
//
// Like Data, Request frames carry a connection epoch and per-peer
// monotonic sequence number used by the receiver to deliver byte
// messages to the handler in send order. See the Data frame docblock
// above for the semantics.
// ─────────────────────────────────────────────────────────────────────────────

// writeRequestFrame writes a complete request frame including the MsgType byte.
func writeRequestFrame(w io.Writer, epoch, seq uint64, reqID []byte, msgType string, body []byte) error {
	if len(reqID) != RequestIDSize {
		return fmt.Errorf("alan: request id must be %d bytes", RequestIDSize)
	}
	if len(msgType) > MaxTypeBytes {
		return fmt.Errorf("alan: message type exceeds %d bytes", MaxTypeBytes)
	}

	hdr := make([]byte, 1+8+8+RequestIDSize+2+len(msgType)+binary.MaxVarintLen64)
	off := 0
	hdr[off] = MsgTypeRequest
	off++
	binary.BigEndian.PutUint64(hdr[off:off+8], epoch)
	off += 8
	binary.BigEndian.PutUint64(hdr[off:off+8], seq)
	off += 8
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
func readRequestFrame(r io.Reader, max int64) (epoch, seq uint64, reqID []byte, msgType string, body []byte, err error) {
	var epochBuf [8]byte
	if _, err = io.ReadFull(r, epochBuf[:]); err != nil {
		return 0, 0, nil, "", nil, err
	}
	epoch = binary.BigEndian.Uint64(epochBuf[:])

	var seqBuf [8]byte
	if _, err = io.ReadFull(r, seqBuf[:]); err != nil {
		return 0, 0, nil, "", nil, err
	}
	seq = binary.BigEndian.Uint64(seqBuf[:])

	reqID = make([]byte, RequestIDSize)
	if _, err = io.ReadFull(r, reqID); err != nil {
		return 0, 0, nil, "", nil, err
	}

	var typeLenBuf [2]byte
	if _, err = io.ReadFull(r, typeLenBuf[:]); err != nil {
		return 0, 0, nil, "", nil, err
	}
	tlen := int(binary.BigEndian.Uint16(typeLenBuf[:]))
	if tlen > 0 {
		typeBuf := make([]byte, tlen)
		if _, err = io.ReadFull(r, typeBuf); err != nil {
			return 0, 0, nil, "", nil, err
		}
		msgType = string(typeBuf)
	}

	br := newByteReader(r)
	bodyLen, err := binary.ReadUvarint(br)
	if err != nil {
		return 0, 0, nil, "", nil, fmt.Errorf("alan: read body length: %w", err)
	}
	if max >= 0 && bodyLen > uint64(max) {
		return 0, 0, nil, "", nil, ErrFrameTooLarge
	}
	if bodyLen > 0 {
		body = make([]byte, bodyLen)
		if _, err = io.ReadFull(r, body); err != nil {
			return 0, 0, nil, "", nil, err
		}
	}
	return epoch, seq, reqID, msgType, body, nil
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
