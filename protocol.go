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
)

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
