// (C) 1f349 2026 - BSD-3-Clause License

package net

import (
	"errors"
	"github.com/1f349/handshake/net/config"
	"github.com/1f349/handshake/net/packets"
	"github.com/1f349/queue"
	"runtime"
	"sync"
	"time"
)

func NewRemoteHandshakerWithConfig(marshal packets.PacketMarshal, settings *config.NodeConfig, presentedSig *config.SigConfig, sigVerifierTable config.SigVerifierTableConfig, knownKEMTable config.KemTableConfig) HandshakeProcessor {
	return &remoteHandshake{
		marshal:          marshal,
		finishChannel:    make(chan bool),
		cancelledChannel: make(chan struct{}),
		cancelWaitCond:   sync.NewCond(&sync.Mutex{}),
		sendQueue:        queue.NewQueue[sendItem](),
		handshakeLock:    &sync.Mutex{},
		handshakePhase:   NoPhase,
		settings:         settings,
		presentSignature: presentedSig,
		verifySignature:  sigVerifierTable,
		kemTable:         knownKEMTable,
		errorChannel:     make(chan error, 1),
		/*
			validDuration:    time.Second * 10,
		*/
	}
}

type remoteHandshake struct {
	marshal          packets.PacketMarshal
	settings         *config.NodeConfig
	presentSignature *config.SigConfig
	verifySignature  config.SigVerifierTableConfig
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
		validDuration    time.Duration
		connID           [16]byte
	*/
}

/*
func (r *remoteHandshake) GetValidDuration() time.Duration {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	return r.validDuration
}

func (r *remoteHandshake) SetValidDuration(duration time.Duration) HandshakeProcessor {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	r.validDuration = duration
	return r
}

func (r *remoteHandshake) GetConnectionUUID() [16]byte {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	return r.connID
}

func (r *remoteHandshake) SetConnectionUUID(uuid [16]byte) HandshakeProcessor {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	r.connID = uuid
	return r
}

*/

func (r *remoteHandshake) GetPacketMarshal() packets.PacketMarshal {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	return r.marshal
}

func (r *remoteHandshake) SetPacketMarshal(marshal packets.PacketMarshal) {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	r.marshal = marshal
}

func (r *remoteHandshake) Handshaking() bool {
	return r.handshakePhase == packets.ZeroReservedPacketType ||
		r.handshakePhase > packets.FinalProofPacketType
}

// GetLocalSecret the secret received from the local node (That is remote to this node)
func (r *remoteHandshake) GetLocalSecret() []byte {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	sTR := make([]byte, len(r.localSecret))
	copy(sTR, r.localSecret)
	return sTR
}

// GetRemoteSecret the secret of this node
func (r *remoteHandshake) GetRemoteSecret() []byte {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	sTR := make([]byte, len(r.remoteSecret))
	copy(sTR, r.remoteSecret)
	return sTR
}

/*
// SetNodeSecret sets the secret this node uses (Remote Secret)
// Can only be modified before a handshake; calls are ignored after.
func (r *remoteHandshake) SetNodeSecret(secret []byte) HandshakeProcessor {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	if r.handshakePhase == packets.ZeroReservedPacketType {
		copy(r.remoteSecret, secret)
	}
	return r
}
*/

func (r *remoteHandshake) GetSettings() *config.NodeConfig {
	return r.settings
}

func (r *remoteHandshake) GetPresentedSignatureSettings() *config.SigConfig {
	return r.presentSignature
}

func (r *remoteHandshake) GetSignatureVerificationTable() config.SigVerifierTableConfig {
	return r.verifySignature
}

func (r *remoteHandshake) SetSignatureVerificationTable(configs config.SigVerifierTableConfig) HandshakeProcessor {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	r.verifySignature = configs
	return r
}

func (r *remoteHandshake) GetKnownKEMTable() config.KemTableConfig {
	return r.kemTable
}

func (r *remoteHandshake) SetKnownKEMTable(kemTable config.KemTableConfig) HandshakeProcessor {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	r.kemTable = kemTable
	return r
}

func (r *remoteHandshake) sendPump() {
	defer r.sendQueue.Clear()
	for {
		toSend := r.sendQueue.Pop()
		if toSend == nil {
			return
		}
		err := r.marshal.Marshal(toSend.header, toSend.payload)
		if err != nil {
			select {
			case r.errorChannel <- err:
			default:
			}
			return
		}
		if toSend.header.ID == packets.ConnectionRejectedPacketType {
			r.handshakePhase = toSend.header.ID
			r.broadcastCancel()
			select {
			case r.finishChannel <- false:
			default:
			}
			return
		}
	}
}

func (r *remoteHandshake) cancelWaiter() {
	defer close(r.cancelledChannel)
	defer r.sendQueue.StartUnBlocking()
	select {
	case cancelled := <-r.finishChannel:
		if cancelled {
			r.handshakePhase = packets.ConnectionRejectedPacketType
			r.broadcastCancel()
			r.sendQueue.Enqueue(sendItem{
				header: packets.PacketHeader{
					ID:             packets.ConnectionRejectedPacketType,
					ConnectionUUID: r.settings.ConnID,
					Time:           time.Now(),
				},
				payload: &packets.EmptyPayload{},
			})
		}
	}
}

func (r *remoteHandshake) broadcastCancel() {
	r.cancelWaitCond.L.Lock()
	defer r.cancelWaitCond.L.Unlock()
	r.cancelWaitCond.Broadcast()
}

func (r *remoteHandshake) Handshake() error {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	func() {
		r.cancelWaitCond.L.Lock()
		defer r.cancelWaitCond.L.Unlock()
		r.handshakePhase = packets.ZeroReservedPacketType
	}()
	r.sendQueue.EndUnBlocking()
	select {
	case <-r.errorChannel:
	default:
	}
	go r.sendPump()
	go r.cancelWaiter()
	for {
		recvHeader, recvPayload, err := r.marshal.Unmarshal()
		if err != nil {
			if errors.Is(err, packets.ErrFragmentReceived) || errors.Is(err, packets.ErrFragmentIndexOutOfRange) {
				continue
			}
			select {
			case r.errorChannel <- err:
			default:
			}
			break
		}
		runtime.KeepAlive(recvPayload) //TODO: Remove once used
		if recvHeader.ConnectionUUID == r.settings.ConnID &&
			!time.Now().Add(-r.settings.ValidDuration).After(recvHeader.Time) &&
			!time.Now().Add(r.settings.ValidDuration).Before(recvHeader.Time) {
			switch recvHeader.ID {
			case packets.ConnectionRejectedPacketType:
				select {
				case r.finishChannel <- false:
				default:
				}
				break
			case packets.InitPacketType:
			case packets.FinalProofPacketType:
			case packets.PublicKeyDataPacketType:
			case packets.SignatureRequestPacketType:
			case packets.PublicKeySignedPacketType:
			case packets.SignaturePublicKeyRequestPacketType:
			case packets.SignedPacketPublicKeyPacketType:
				//TODO : Implement me
			}
		}
	}
	select {
	case err := <-r.errorChannel:
		r.handshakePhase = packets.ConnectionRejectedPacketType
		r.broadcastCancel()
		return err
	default:
		return nil
	}
}

func (r *remoteHandshake) HandshakeCompleted() bool {
	return r.handshakePhase == packets.InitProofPacketType
}

func (r *remoteHandshake) HandshakeFailed() bool {
	return r.handshakePhase == packets.ConnectionRejectedPacketType
}

func (r *remoteHandshake) WaitForHandshakeCompletion() {
	r.cancelWaitCond.L.Lock()
	defer r.cancelWaitCond.L.Unlock()
	for r.Handshaking() {
		r.cancelWaitCond.Wait()
	}
}

func (r *remoteHandshake) CancelHandshake() {
	if r.Handshaking() {
		select {
		case r.finishChannel <- true:
		case <-r.cancelledChannel:
		}
	}
}
