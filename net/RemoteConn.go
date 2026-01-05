// (C) 1f349 2025 - BSD-3-Clause License

package net

import (
	"github.com/1f349/handshake/net/config"
	"github.com/1f349/handshake/net/packets"
	"net"
	"sync"
)

func NewRemoteConn(conn net.Conn) HandshakeConn {
	return NewRemoteConnWithConfig(conn, config.NodeConfig{}, config.SigConfig{}, nil)
}

func NewRemoteConnWithConfig(conn net.Conn, settings config.NodeConfig, presentedSig config.SigConfig, sigVerifiers []config.SigVerifierConfig) HandshakeConn {
	return &RemoteConn{
		Conn:             conn,
		finishChannel:    make(chan bool, 1),
		handshakeLock:    &sync.Mutex{},
		cancelLock:       &sync.Mutex{},
		handshakePhase:   packets.ZeroReservedPacketType,
		settings:         settings,
		presentSignature: presentedSig,
		verifySignature:  sigVerifiers,
	}
}

type RemoteConn struct {
	net.Conn
	settings         config.NodeConfig
	presentSignature config.SigConfig
	verifySignature  []config.SigVerifierConfig
	finishChannel    chan bool
	cancelLock       *sync.Mutex
	handshakeLock    *sync.Mutex
	handshakePhase   packets.PacketType
	localSecret      []byte
	remoteSecret     []byte
}

func (r *RemoteConn) Handshaking() bool {
	return r.handshakePhase == packets.ZeroReservedPacketType ||
		r.handshakePhase > packets.FinalProofPacketType
}

// GetLocalSecret the secret received from the local node (That is remote to this node)
func (r *RemoteConn) GetLocalSecret() []byte {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	sTR := make([]byte, len(r.localSecret))
	copy(sTR, r.localSecret)
	return sTR
}

// GetRemoteSecret the secret of this node
func (r *RemoteConn) GetRemoteSecret() []byte {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	sTR := make([]byte, len(r.remoteSecret))
	copy(sTR, r.remoteSecret)
	return sTR
}

// SetNodeSecret sets the secret this node uses (Remote Secret)
// Can only be modified before a handshake; calls are ignored after.
func (r *RemoteConn) SetNodeSecret(secret []byte) HandshakeConn {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	if r.handshakePhase == packets.ZeroReservedPacketType {
		copy(r.remoteSecret, secret)
	}
	return r
}

func (r *RemoteConn) GetSettings() config.NodeConfig {
	return r.settings
}

func (r *RemoteConn) SetSettings(config config.NodeConfig) HandshakeConn {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	r.settings = config
	return r
}

func (r *RemoteConn) GetPresentedSignatureSettings() config.SigConfig {
	return r.presentSignature
}

func (r *RemoteConn) SetPresentedSignatureSettings(config config.SigConfig) HandshakeConn {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	r.presentSignature = config
	return r
}

func (r *RemoteConn) GetSignatureVerificationSettings() []config.SigVerifierConfig {
	return r.verifySignature
}

func (r *RemoteConn) SetSignatureVerificationSettings(configs []config.SigVerifierConfig) HandshakeConn {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	r.verifySignature = configs
	return r
}

func (r *RemoteConn) Handshake() error {
	//TODO: implement me
	panic("implement me")
}

func (r *RemoteConn) HandshakeCompleted() bool {
	return r.handshakePhase == packets.InitProofPacketType
}

func (r *RemoteConn) HandshakeFailed() bool {
	return r.handshakePhase == packets.ConnectionRejectedPacketType
}

// HandshakeCompletedWaiter channel value represents if the handshake was canceled (Only one receiver of this channel with receive the value)
func (r *RemoteConn) HandshakeCompletedWaiter() <-chan bool {
	return r.finishChannel
}

func (r *RemoteConn) CancelHandshake() {
	r.cancelLock.Lock()
	defer r.cancelLock.Unlock()
	// Should only be closed within Handshake while locked using cancelLock and the proper final value of handshakePhase is set within this lock
	if !r.HandshakeCompleted() && !r.HandshakeFailed() {
		r.finishChannel <- true
	}
}
