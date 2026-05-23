// (C) 1f349 2026 - BSD-3-Clause License

package net

import (
	"github.com/1f349/handshake/net/config"
	"github.com/1f349/handshake/net/packets"
)

//var ErrHandshakeDone = errors.New("handshake already done")

const NoPhase = packets.PacketType(129)
const Init2APhase = packets.PacketType(133)
const Init2BPhase = packets.PacketType(135)
const Init2ABPhase = packets.PacketType(137)

// HandshakeProcessor provides a generic handshake processor for packets.PacketMarshal
type HandshakeProcessor interface {
	GetPacketMarshal() packets.PacketMarshal
	SetPacketMarshal(packets.PacketMarshal)
	Handshake() error
	HandshakeCompleted() bool
	HandshakeFailed() bool
	WaitForHandshakeCompletion()
	CancelHandshake()
	Handshaking() bool
	GetSettings() *config.NodeConfig
	GetPresentedSignatureSettings() *config.SigConfig
	GetSignatureVerificationTable() config.SigVerifierTableConfig
	SetSignatureVerificationTable(configs config.SigVerifierTableConfig) HandshakeProcessor
	GetKnownKEMTable() config.KemTableConfig
	SetKnownKEMTable(config.KemTableConfig) HandshakeProcessor
	GetLocalSecret() []byte
	GetRemoteSecret() []byte
	/*
		// SetNodeSecret sets the secret of the current node; localHandshake corresponds to GetLocalSecret while remoteHandshake corresponds to GetRemoteSecret
		// Can only be modified before a handshake; calls are ignored after.
		SetNodeSecret(secret []byte) HandshakeProcessor
	*/
	/*
		GetConnectionUUID() [16]byte
		SetConnectionUUID(uuid [16]byte) HandshakeProcessor
		GetValidDuration() time.Duration
		SetValidDuration(duration time.Duration) HandshakeProcessor
	*/
}

type sendItem struct {
	header  packets.PacketHeader
	payload packets.PacketPayload
}
