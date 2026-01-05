// (C) 1f349 2025 - BSD-3-Clause License

package net

import (
	"github.com/1f349/handshake/net/config"
	"net"
)

// HandshakeConn provides a generic handshake wrapper for a net.Conn
type HandshakeConn interface {
	net.Conn
	Handshake() error
	HandshakeCompleted() bool
	HandshakeFailed() bool
	// HandshakeCompletedWaiter channel value represents if the handshake was canceled (Only one receiver of this channel with receive the value)
	HandshakeCompletedWaiter() <-chan bool
	CancelHandshake()
	Handshaking() bool
	GetSettings() config.NodeConfig
	SetSettings(config config.NodeConfig) HandshakeConn
	GetPresentedSignatureSettings() config.SigConfig
	SetPresentedSignatureSettings(config.SigConfig) HandshakeConn
	GetSignatureVerificationSettings() []config.SigVerifierConfig
	SetSignatureVerificationSettings([]config.SigVerifierConfig) HandshakeConn
	GetLocalSecret() []byte
	GetRemoteSecret() []byte
	// SetNodeSecret sets the secret of the current node; LocalConn corresponds to GetLocalSecret while RemoteConn corresponds to GetRemoteSecret
	// Can only be modified before a handshake; calls are ignored after.
	SetNodeSecret(secret []byte) HandshakeConn
}
