package alan

import (
	"encoding/binary"
	"fmt"
)

// Message types for internal protocol
const (
	// MsgTypeData is a user data message (fire-and-forget)
	MsgTypeData byte = 0x10
	// MsgTypeRequest is a request message expecting a response
	MsgTypeRequest byte = 0x20
	// MsgTypeResponse is a response to a request message
	MsgTypeResponse byte = 0x21
	// MsgTypeLockRequest is sent to request a distributed lock
	MsgTypeLockRequest byte = 0x30
	// MsgTypeLockGrant is sent to grant a lock to the requester
	MsgTypeLockGrant byte = 0x31
	// MsgTypeLockDeny is sent to deny a lock request (already held)
	MsgTypeLockDeny byte = 0x32
	// MsgTypeLockRelease is sent to notify that a lock has been released
	MsgTypeLockRelease byte = 0x33
)

// RequestIDSize is the size of request IDs in bytes
const RequestIDSize = 16

// encodeLockPayload encodes a lock message payload (without msg type header).
// Format: [RequestID:16][KeyLength:2][Key:N]
func encodeLockPayload(requestID []byte, key string) []byte {
	keyBytes := []byte(key)
	payload := make([]byte, RequestIDSize+2+len(keyBytes))
	copy(payload[:RequestIDSize], requestID)
	binary.BigEndian.PutUint16(payload[RequestIDSize:], uint16(len(keyBytes)))
	copy(payload[RequestIDSize+2:], keyBytes)
	return payload
}

// decodeLockPayload extracts the request ID and key from a lock message payload
func decodeLockPayload(payload []byte) (requestID []byte, key string, err error) {
	if len(payload) < RequestIDSize+2 {
		return nil, "", fmt.Errorf("lock payload too short: need at least %d bytes", RequestIDSize+2)
	}
	requestID = payload[:RequestIDSize]
	keyLen := binary.BigEndian.Uint16(payload[RequestIDSize : RequestIDSize+2])
	if len(payload) < RequestIDSize+2+int(keyLen) {
		return nil, "", fmt.Errorf("lock payload too short for key length %d", keyLen)
	}
	key = string(payload[RequestIDSize+2 : RequestIDSize+2+int(keyLen)])
	return requestID, key, nil
}
