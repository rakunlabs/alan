package alan

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Message types for internal protocol
const (
	// MsgTypeJoin is sent when a peer joins the cluster
	MsgTypeJoin byte = 0x01
	// MsgTypeLeave is sent when a peer leaves the cluster gracefully
	MsgTypeLeave byte = 0x02
	// MsgTypeHeartbeat is sent periodically to maintain membership
	MsgTypeHeartbeat byte = 0x03
	// MsgTypeData is a user data message
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

// Protocol message format:
//   [Type: 1 byte][Payload]
//
// For JOIN/LEAVE/HEARTBEAT:
//   [Type: 1 byte][Port: 2 bytes (big endian)]
//
// For DATA:
//   [Type: 1 byte][User Data: variable]

// encodeControlMessage encodes a control message (JOIN/LEAVE/HEARTBEAT)
// with the sender's port
func encodeControlMessage(msgType byte, port int) []byte {
	msg := make([]byte, 3)
	msg[0] = msgType
	binary.BigEndian.PutUint16(msg[1:3], uint16(port))
	return msg
}

// encodeDataMessage encodes a user data message
func encodeDataMessage(data []byte) []byte {
	msg := make([]byte, 1+len(data))
	msg[0] = MsgTypeData
	copy(msg[1:], data)
	return msg
}

// encodeRequestMessage encodes a request message with a request ID
// Format: [MsgTypeRequest:1][RequestID:16][Data:N]
func encodeRequestMessage(requestID []byte, data []byte) []byte {
	msg := make([]byte, 1+RequestIDSize+len(data))
	msg[0] = MsgTypeRequest
	copy(msg[1:1+RequestIDSize], requestID)
	copy(msg[1+RequestIDSize:], data)
	return msg
}

// encodeResponseMessage encodes a response message with the original request ID
// Format: [MsgTypeResponse:1][RequestID:16][Data:N]
func encodeResponseMessage(requestID []byte, data []byte) []byte {
	msg := make([]byte, 1+RequestIDSize+len(data))
	msg[0] = MsgTypeResponse
	copy(msg[1:1+RequestIDSize], requestID)
	copy(msg[1+RequestIDSize:], data)
	return msg
}

// decodeRequestPayload extracts the request ID and data from a request/response payload
func decodeRequestPayload(payload []byte) (requestID []byte, data []byte, err error) {
	if len(payload) < RequestIDSize {
		return nil, nil, fmt.Errorf("request payload too short: need at least %d bytes", RequestIDSize)
	}
	return payload[:RequestIDSize], payload[RequestIDSize:], nil
}

// decodeMessage decodes a protocol message and returns the type and payload
func decodeMessage(data []byte) (msgType byte, payload []byte, err error) {
	if len(data) < 1 {
		return 0, nil, fmt.Errorf("message too short")
	}
	return data[0], data[1:], nil
}

// decodeControlPayload extracts the port from a control message payload
func decodeControlPayload(payload []byte) (port int, err error) {
	if len(payload) < 2 {
		return 0, fmt.Errorf("control payload too short")
	}
	return int(binary.BigEndian.Uint16(payload[:2])), nil
}

// buildPeerAddr constructs a peer address from the source IP and the port from payload
func buildPeerAddr(sourceAddr *net.UDPAddr, port int) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   sourceAddr.IP,
		Port: port,
		Zone: sourceAddr.Zone,
	}
}

// encodeLockMessage encodes a lock request or release message
// Format: [MsgType:1][RequestID:16][KeyLength:2][Key:N]
func encodeLockMessage(msgType byte, requestID []byte, key string) []byte {
	keyBytes := []byte(key)
	msg := make([]byte, 1+RequestIDSize+2+len(keyBytes))
	msg[0] = msgType
	copy(msg[1:1+RequestIDSize], requestID)
	binary.BigEndian.PutUint16(msg[1+RequestIDSize:], uint16(len(keyBytes)))
	copy(msg[1+RequestIDSize+2:], keyBytes)
	return msg
}

// encodeLockResponseMessage encodes a lock grant or deny message
// Format: [MsgType:1][RequestID:16][KeyLength:2][Key:N]
func encodeLockResponseMessage(msgType byte, requestID []byte, key string) []byte {
	return encodeLockMessage(msgType, requestID, key)
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
