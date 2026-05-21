// (C) 1f349 2026 - BSD-3-Clause License

package net

import (
	"crypto/hmac"
	"errors"
	"github.com/1f349/handshake/crypto"
	"github.com/1f349/handshake/net/config"
	"github.com/1f349/handshake/net/packets"
	"github.com/1f349/queue"
	"runtime"
	"sync"
	"time"
)

func NewLocalHandshakerWithConfig(marshal packets.PacketMarshal, settings *config.NodeConfig, presentedSig *config.SigConfig, sigVerifiers []*config.SigVerifierConfig, knownKEMTable config.KemTableConfig) HandshakeProcessor {
	return &localHandshake{
		marshal:          marshal,
		finishChannel:    make(chan bool),
		cancelledChannel: make(chan struct{}),
		cancelWaitCond:   sync.NewCond(&sync.Mutex{}),
		sendQueue:        queue.NewQueue[sendItem](),
		handshakeLock:    &sync.Mutex{},
		handshakePhase:   NoPhase,
		settings:         settings,
		presentSignature: presentedSig,
		verifySignature:  sigVerifiers,
		kemTable:         knownKEMTable,
		errorChannel:     make(chan error, 1),
		/*
			connID:           packets.GetUUID(),
			validDuration:    time.Second * 10,
		*/
	}
}

type localHandshake struct {
	marshal          packets.PacketMarshal
	settings         *config.NodeConfig
	presentSignature *config.SigConfig
	verifySignature  []*config.SigVerifierConfig
	kemTable         config.KemTableConfig
	finishChannel    chan bool
	cancelledChannel chan struct{}
	cancelWaitCond   *sync.Cond
	sendQueue        queue.Queue[sendItem]
	handshakeLock    *sync.Mutex
	handshakePhase   packets.PacketType
	localSecret      []byte
	remoteSecret     []byte
	errorChannel     chan error
	/*
		connID           [16]byte
		validDuration    time.Duration
	*/
}

/*
func (l *localHandshake) GetValidDuration() time.Duration {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	return l.validDuration
}

func (l *localHandshake) SetValidDuration(duration time.Duration) HandshakeProcessor {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	l.validDuration = duration
	return l
}

func (l *localHandshake) GetConnectionUUID() [16]byte {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	return l.connID
}

func (l *localHandshake) SetConnectionUUID(uuid [16]byte) HandshakeProcessor {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	l.connID = uuid
	return l
}
*/

func (l *localHandshake) GetPacketMarshal() packets.PacketMarshal {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	return l.marshal
}

func (l *localHandshake) SetPacketMarshal(marshal packets.PacketMarshal) {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	l.marshal = marshal
}

func (l *localHandshake) Handshaking() bool {
	return l.handshakePhase == packets.ZeroReservedPacketType ||
		l.handshakePhase == packets.InitPacketType ||
		l.handshakePhase > packets.FinalProofPacketType
}

// GetLocalSecret the secret of this node
func (l *localHandshake) GetLocalSecret() []byte {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	sTR := make([]byte, len(l.localSecret))
	copy(sTR, l.localSecret)
	return sTR
}

// GetRemoteSecret the secret received from the remote node
func (l *localHandshake) GetRemoteSecret() []byte {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	sTR := make([]byte, len(l.remoteSecret))
	copy(sTR, l.remoteSecret)
	return sTR
}

/*
// SetNodeSecret sets the secret this node uses (Local Secret)
// Can only be modified before a handshake; calls are ignored after.
func (l *localHandshake) SetNodeSecret(secret []byte) HandshakeProcessor {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	if l.handshakePhase == packets.ZeroReservedPacketType || l.handshakePhase == packets.InitPacketType {
		copy(l.localSecret, secret)
	}
	return l
}
*/

func (l *localHandshake) GetSettings() *config.NodeConfig {
	return l.settings
}

func (l *localHandshake) GetPresentedSignatureSettings() *config.SigConfig {
	return l.presentSignature
}

func (l *localHandshake) GetSignatureVerificationSettings() []*config.SigVerifierConfig {
	return l.verifySignature
}

func (l *localHandshake) SetSignatureVerificationSettings(configs []*config.SigVerifierConfig) HandshakeProcessor {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	l.verifySignature = configs
	return l
}

func (l *localHandshake) GetKnownKEMTable() config.KemTableConfig {
	return l.kemTable
}

func (l *localHandshake) SetKnownKEMTable(kemTable config.KemTableConfig) HandshakeProcessor {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	l.kemTable = kemTable
	return l
}

func (l *localHandshake) sendPump() {
	defer l.sendQueue.Clear()
	for {
		toSend := l.sendQueue.Pop()
		if toSend == nil {
			return
		}
		err := l.marshal.Marshal(toSend.header, toSend.payload)
		if err != nil {
			select {
			case l.errorChannel <- err:
			default:
			}
			return
		}
		if toSend.header.ID == packets.ConnectionRejectedPacketType || toSend.header.ID == packets.FinalProofPacketType {
			l.handshakePhase = toSend.header.ID
			l.broadcastCancel()
			select {
			case l.finishChannel <- false:
			default:
			}
			return
		}
	}
}

func (l *localHandshake) cancelWaiter() {
	defer close(l.cancelledChannel)
	defer l.sendQueue.StartUnBlocking()
	select {
	case cancelled := <-l.finishChannel:
		if cancelled {
			l.handshakePhase = packets.ConnectionRejectedPacketType
			l.broadcastCancel()
			l.sendQueue.Enqueue(sendItem{
				header: packets.PacketHeader{
					ID:             packets.ConnectionRejectedPacketType,
					ConnectionUUID: l.settings.ConnID,
					Time:           time.Now(),
				},
				payload: &packets.EmptyPayload{},
			})
		}
	}
}

func (l *localHandshake) broadcastCancel() {
	l.cancelWaitCond.L.Lock()
	defer l.cancelWaitCond.L.Unlock()
	l.cancelWaitCond.Broadcast()
}

func (l *localHandshake) getInitPayload() (*packets.InitPayload, packets.PacketType, error) { // 2
	var err error
	pret := packets.InitPacketType
	p := &packets.InitPayload{}
	if !l.settings.RequestLocalPublicKey {
		p.PublicKeyHash = l.settings.GetPublicKeyHash(l.settings.KeyCheckHash()) // 2(B)
		pret = Init2BPhase
	}
	var rpk crypto.KemPublicKey
	rpk, err = l.kemTable.GetRemoteKey()
	if err == nil { // 2
		l.localSecret, err = p.Encapsulate(rpk)
		if err != nil {
			return nil, packets.ConnectionRejectedPacketType, err
		}
		p.PacketHasher = hmac.New(l.settings.HMACHash, l.localSecret)
	} else { // 2(A)
		if pret == packets.InitPacketType {
			pret = Init2APhase
		} else {
			pret = Init2ABPhase
		}
	}
	return p, pret, nil
}

func (l *localHandshake) Handshake() error {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	/*if l.HandshakeFailed() || l.HandshakeCompleted() {
		return ErrHandshakeDone
	}*/
	func() {
		l.cancelWaitCond.L.Lock()
		defer l.cancelWaitCond.L.Unlock()
		l.handshakePhase = packets.ZeroReservedPacketType
	}()
	l.sendQueue.EndUnBlocking()
	select {
	case <-l.errorChannel:
	default:
	}
	ipp, pktyp, err := l.getInitPayload()
	if err != nil {
		l.broadcastCancel()
		return err
	}
	l.handshakePhase = pktyp
	l.sendQueue.Enqueue(sendItem{
		header:  packets.PacketHeader{ID: packets.InitPacketType, ConnectionUUID: l.settings.ConnID, Time: time.Now()},
		payload: ipp,
	})
	go l.sendPump()
	go l.cancelWaiter()
	for {
		recvHeader, recvPayload, err := l.marshal.Unmarshal()
		if err != nil {
			if errors.Is(err, packets.ErrFragmentReceived) {
				continue
			}
			select {
			case l.errorChannel <- err:
			default:
			}
			break
		}
		runtime.KeepAlive(recvPayload) //TODO: Remove once used
		if recvHeader.ConnectionUUID == l.settings.ConnID &&
			!time.Now().Add(-l.settings.ValidDuration).After(recvHeader.Time) &&
			!time.Now().Add(l.settings.ValidDuration).Before(recvHeader.Time) {
			switch recvHeader.ID {
			case packets.ConnectionRejectedPacketType:
				select {
				case l.finishChannel <- false:
				default:
				}
				break
			case packets.InitProofPacketType:
			case packets.PublicKeyRequestPacketType:
			case packets.PublicKeyDataPacketType:
			case packets.SignatureRequestPacketType:
			case packets.PublicKeySignedPacketType:
			case packets.SignaturePublicKeyRequestPacketType:
			case packets.SignedPacketPublicKeyPacketType:
				//TODO : Implement me
			}
		}
	}
	defer l.broadcastCancel()
	select {
	case err := <-l.errorChannel:
		l.handshakePhase = packets.ConnectionRejectedPacketType
		return err
	default:
		return nil
	}
}

func (l *localHandshake) HandshakeCompleted() bool {
	return l.handshakePhase == packets.FinalProofPacketType
}

func (l *localHandshake) HandshakeFailed() bool {
	return l.handshakePhase == packets.ConnectionRejectedPacketType
}

func (l *localHandshake) WaitForHandshakeCompletion() {
	l.cancelWaitCond.L.Lock()
	defer l.cancelWaitCond.L.Unlock()
	for l.Handshaking() {
		l.cancelWaitCond.Wait()
	}
}

func (l *localHandshake) CancelHandshake() {
	if l.Handshaking() {
		select {
		case l.finishChannel <- true:
		case <-l.cancelledChannel:
		}
	}
}
