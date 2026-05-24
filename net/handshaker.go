// (C) 1f349 2026 - BSD-3-Clause License

package net

import (
	"errors"
	"github.com/1f349/handshake/net/config"
	"github.com/1f349/handshake/net/packets"
)

// var ErrHandshakeDone = errors.New("handshake already done")

// ErrInitProofFailed returned from HandshakeProcessor.Handshake when the init proof fails
var ErrInitProofFailed = errors.New("init proof failed")

// ErrFinalProofFailed returned from HandshakeProcessor.Handshake when the final proof fails
var ErrFinalProofFailed = errors.New("final proof failed")

// ErrOtherNodeNotVerified returned from HandshakeProcessor.Handshake when the connected node
// is not part of the KEM table nor can it be verified via signature
var ErrOtherNodeNotVerified = errors.New("other node not verified")

const NoPhase = packets.PacketType(129)
const Init2APhase = packets.PacketType(133)
const Init2BPhase = packets.PacketType(135)

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
}

type sendItem struct {
	header  packets.PacketHeader
	payload packets.PacketPayload
}
