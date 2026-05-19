// (C) 1f349 2026 - BSD-3-Clause License

package net

import (
	"github.com/1f349/handshake/net/config"
	"github.com/1f349/handshake/net/packets"
	"net"
)

const NoPhase = packets.PacketType(129)
const Init2APhase = packets.PacketType(133)
const Init2BPhase = packets.PacketType(135)
const Init2ABPhase = packets.PacketType(137)

// HandshakeConn provides a generic handshake wrapper for a net.Conn
type HandshakeConn interface {
	net.Conn
	Handshake(marshaller *packets.PacketMarshaller) error
	HandshakeCompleted() bool
	HandshakeFailed() bool
	WaitForHandshakeCompletion()
	CancelHandshake()
	Handshaking() bool
	GetSettings() *config.NodeConfig
	GetPresentedSignatureSettings() *config.SigConfig
	GetSignatureVerificationSettings() []*config.SigVerifierConfig
	SetSignatureVerificationSettings(configs []*config.SigVerifierConfig) HandshakeConn
	GetKnownKEMTable() config.KemTableConfig
	SetKnownKEMTable(config.KemTableConfig) HandshakeConn
	GetLocalSecret() []byte
	GetRemoteSecret() []byte
	/*
		// SetNodeSecret sets the secret of the current node; localConn corresponds to GetLocalSecret while remoteConn corresponds to GetRemoteSecret
		// Can only be modified before a handshake; calls are ignored after.
		SetNodeSecret(secret []byte) HandshakeConn
	*/
	/*
		GetConnectionUUID() [16]byte
		SetConnectionUUID(uuid [16]byte) HandshakeConn
		GetValidDuration() time.Duration
		SetValidDuration(duration time.Duration) HandshakeConn
	*/
}

type sendItem struct {
	header  packets.PacketHeader
	payload packets.PacketPayload
}
