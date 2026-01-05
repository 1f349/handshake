// (C) 1f349 2025 - BSD-3-Clause License

package net

import (
	"github.com/1f349/handshake/net/config"
	"github.com/1f349/handshake/net/packets"
	"net"
	"sync"
)

func NewLocalConn(conn net.Conn) HandshakeConn {
	return NewLocalConnWithConfig(conn, config.NodeConfig{}, config.SigConfig{}, nil)
}

func NewLocalConnWithConfig(conn net.Conn, settings config.NodeConfig, presentedSig config.SigConfig, sigVerifiers []config.SigVerifierConfig) HandshakeConn {
	return &LocalConn{
		Conn:             conn,
		finishChannel:    make(chan bool, 1),
		handshakeLock:    &sync.Mutex{},
		cancelLock:       &sync.Mutex{},
		handshakePhase:   packets.InitPacketType,
		settings:         settings,
		presentSignature: presentedSig,
		verifySignature:  sigVerifiers,
	}
}

type LocalConn struct {
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

func (l *LocalConn) Handshaking() bool {
	return l.handshakePhase == packets.ZeroReservedPacketType ||
		l.handshakePhase == packets.InitPacketType ||
		l.handshakePhase > packets.FinalProofPacketType
}

// GetLocalSecret the secret of this node
func (l *LocalConn) GetLocalSecret() []byte {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	sTR := make([]byte, len(l.localSecret))
	copy(sTR, l.localSecret)
	return sTR
}

// GetRemoteSecret the secret received from the remote node
func (l *LocalConn) GetRemoteSecret() []byte {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	sTR := make([]byte, len(l.remoteSecret))
	copy(sTR, l.remoteSecret)
	return sTR
}

// SetNodeSecret sets the secret this node uses (Local Secret)
// Can only be modified before a handshake; calls are ignored after.
func (l *LocalConn) SetNodeSecret(secret []byte) HandshakeConn {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	if l.handshakePhase == packets.ZeroReservedPacketType || l.handshakePhase == packets.InitPacketType {
		copy(l.localSecret, secret)
	}
	return l
}

func (l *LocalConn) GetSettings() config.NodeConfig {
	return l.settings
}

func (l *LocalConn) SetSettings(config config.NodeConfig) HandshakeConn {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	l.settings = config
	return l
}

func (l *LocalConn) GetPresentedSignatureSettings() config.SigConfig {
	return l.presentSignature
}

func (l *LocalConn) SetPresentedSignatureSettings(config config.SigConfig) HandshakeConn {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	l.presentSignature = config
	return l
}

func (l *LocalConn) GetSignatureVerificationSettings() []config.SigVerifierConfig {
	return l.verifySignature
}

func (l *LocalConn) SetSignatureVerificationSettings(configs []config.SigVerifierConfig) HandshakeConn {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	l.verifySignature = configs
	return l
}

func (l *LocalConn) Handshake() error {
	//TODO: implement me
	panic("implement me")
}

func (l *LocalConn) HandshakeCompleted() bool {
	return l.handshakePhase == packets.FinalProofPacketType
}

func (l *LocalConn) HandshakeFailed() bool {
	return l.handshakePhase == packets.ConnectionRejectedPacketType
}

// HandshakeCompletedWaiter channel value represents if the handshake was canceled (Only one receiver of this channel with receive the value)
func (l *LocalConn) HandshakeCompletedWaiter() <-chan bool {
	return l.finishChannel
}

func (l *LocalConn) CancelHandshake() {
	l.cancelLock.Lock()
	defer l.cancelLock.Unlock()
	// Should only be closed within Handshake while locked using cancelLock and the proper final value of handshakePhase is set within this lock
	if !l.HandshakeCompleted() && !l.HandshakeFailed() {
		l.finishChannel <- true
	}
}
