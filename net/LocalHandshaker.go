// (C) 1f349 2026 - BSD-3-Clause License

package net

import (
	"crypto/hmac"
	"crypto/subtle"
	"errors"
	"github.com/1f349/handshake/crypto"
	"github.com/1f349/handshake/net/config"
	"github.com/1f349/handshake/net/packets"
	"github.com/1f349/queue"
	"runtime"
	"sync"
	"time"
)

func NewLocalHandshakerWithConfig(marshal packets.PacketMarshal, settings *config.NodeConfig, presentedSig *config.SigConfig, sigVerifierTable config.SigVerifierTableConfig, knownKEMTable config.KemTableConfig) HandshakeProcessor {
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
		verifySignature:  sigVerifierTable,
		kemTable:         knownKEMTable,
		errorChannel:     make(chan error, 1),
	}
}

type localHandshake struct {
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
}

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
	subtle.ConstantTimeCopy(1, sTR, l.localSecret)
	return sTR
}

// GetRemoteSecret the secret received from the remote node
func (l *localHandshake) GetRemoteSecret() []byte {
	l.handshakeLock.Lock()
	defer l.handshakeLock.Unlock()
	sTR := make([]byte, len(l.remoteSecret))
	subtle.ConstantTimeCopy(1, sTR, l.remoteSecret)
	return sTR
}

func (l *localHandshake) GetSettings() *config.NodeConfig {
	return l.settings
}

func (l *localHandshake) GetPresentedSignatureSettings() *config.SigConfig {
	return l.presentSignature
}

func (l *localHandshake) GetSignatureVerificationTable() config.SigVerifierTableConfig {
	return l.verifySignature
}

func (l *localHandshake) SetSignatureVerificationTable(configs config.SigVerifierTableConfig) HandshakeProcessor {
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
			l.broadcastCancel()
			select {
			case l.finishChannel <- false:
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
	// 2(AB) does not exist; 2(A) should be returned first so 2(B) can be returned once the remote key is available
	var err error
	pret := packets.InitPacketType
	p := &packets.InitPayload{}
	var rpk crypto.KemPublicKey
	rpk, err = l.kemTable.GetRemoteKey()
	if err == nil { // 2
		l.localSecret, err = p.Encapsulate(rpk)
		if err != nil {
			return nil, packets.ConnectionRejectedPacketType, err
		}
		p.PacketHasher = hmac.New(l.settings.HMACHash, l.localSecret)
		if !l.settings.RequestLocalPublicKey { // 2(B)
			p.PublicKeyHash = l.settings.GetPublicKeyHash(l.settings.KeyCheckHash())
			pret = Init2BPhase
		}
	} else { // 2(A)
		pret = Init2APhase
	}
	return p, pret, nil
}

func (l *localHandshake) errTerminate(err error) {
	select {
	case l.errorChannel <- err:
	default:
	}
	l.sendQueue.Enqueue(sendItem{
		header:  packets.PacketHeader{ID: packets.ConnectionRejectedPacketType, ConnectionUUID: l.settings.ConnID, Time: time.Now()},
		payload: &packets.EmptyPayload{},
	})
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
		l.handshakePhase = NoPhase
		l.broadcastCancel()
		return err
	}
	go l.sendPump()
	go l.cancelWaiter()
	l.handshakePhase = pktyp
	l.sendQueue.Enqueue(sendItem{
		header:  packets.PacketHeader{ID: packets.InitPacketType, ConnectionUUID: l.settings.ConnID, Time: time.Now()},
		payload: ipp,
	})
	var recvKeyPyl *packets.PublicKeyDataPayload
	for {
		recvHeader, recvPayload, err := l.marshal.Unmarshal()
		if err != nil {
			if errors.Is(err, packets.ErrFragmentReceived) || errors.Is(err, packets.ErrInvalidPacketID) {
				continue
			}
			l.errTerminate(err)
			break
		}
		if recvHeader.ConnectionUUID == l.settings.ConnID &&
			!time.Now().Add(-l.settings.ValidDuration).After(recvHeader.Time) &&
			!time.Now().Add(l.settings.ValidDuration).Before(recvHeader.Time) {
			if recvHeader.ID == packets.ConnectionRejectedPacketType {
				select {
				case l.finishChannel <- false:
				default:
				}
				break
			} else if recvHeader.ID == packets.InitProofPacketType {
				if l.handshakePhase == packets.InitPacketType || l.handshakePhase == packets.PublicKeyDataPacketType ||
					l.handshakePhase == packets.PublicKeySignedPacketType || l.handshakePhase == packets.SignedPacketPublicKeyPacketType {
					if lpyl, k := recvPayload.(*packets.InitProofPayload); k {
						if subtle.ConstantTimeCompare(lpyl.ProofHMAC, ipp.PacketHash) == 1 {
							l.remoteSecret, err = lpyl.Decapsulate(l.settings.GetPrivateKey())
							if err == nil {
								l.sendQueue.Enqueue(sendItem{
									header:  packets.PacketHeader{ID: packets.FinalProofPacketType, ConnectionUUID: l.settings.ConnID, Time: time.Now()},
									payload: &packets.FinalProofPayload{ProofHMAC: packets.PacketDataHash(*recvHeader, recvPayload, hmac.New(l.settings.HMACHash, l.remoteSecret))},
								})
								break
							} else {
								l.errTerminate(ErrInitProofFailed)
								break
							}
						} else {
							l.errTerminate(ErrInitProofFailed)
							break
						}
					}
				}
			} else if recvHeader.ID == packets.PublicKeyRequestPacketType {
				if l.handshakePhase == packets.InitPacketType || l.handshakePhase == Init2BPhase {
					l.handshakePhase = packets.PublicKeyDataPacketType
					l.sendQueue.Enqueue(sendItem{
						header:  packets.PacketHeader{ID: packets.PublicKeyDataPacketType, ConnectionUUID: l.settings.ConnID, Time: time.Now()},
						payload: &packets.PublicKeyDataPayload{Data: l.settings.GetPublicKeyData()},
					})
				}
			} else if recvHeader.ID == packets.PublicKeyDataPacketType {
				if l.handshakePhase == Init2APhase {
					if lpyl, k := recvPayload.(*packets.PublicKeyDataPayload); k {
						recvKeyPyl = lpyl
						err := l.kemTable.SetRemoteKeyData(lpyl.Data)
						if err == nil {
							ipp, pktyp, err = l.getInitPayload()
							if err == nil {
								l.handshakePhase = pktyp
								l.sendQueue.Enqueue(sendItem{
									header:  packets.PacketHeader{ID: packets.InitPacketType, ConnectionUUID: l.settings.ConnID, Time: time.Now()},
									payload: ipp,
								})
							} else {
								l.errTerminate(err)
								break
							}
						} else {
							l.handshakePhase = packets.SignatureRequestPacketType
							l.sendQueue.Enqueue(sendItem{
								header:  packets.PacketHeader{ID: packets.SignatureRequestPacketType, ConnectionUUID: l.settings.ConnID, Time: time.Now()},
								payload: &packets.EmptyPayload{},
							})
						}
					}
				}
			} else if recvHeader.ID == packets.SignatureRequestPacketType {
				//TODO : Implement me
			} else if recvHeader.ID == packets.PublicKeySignedPacketType {
				//TODO : Implement me
			} else if recvHeader.ID == packets.SignaturePublicKeyRequestPacketType {
				//TODO : Implement me
			} else if recvHeader.ID == packets.SignedPacketPublicKeyPacketType {
				//TODO : Implement me
			}
		}
	}
	runtime.KeepAlive(recvKeyPyl) // TODO: Remove once used
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
