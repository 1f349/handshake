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
	"hash"
	"sync"
	"time"
)

func NewRemoteHandshakerWithConfig(marshal packets.PacketMarshal, settings *config.NodeConfig, presentedSig *config.SigConfig,
	sigVerifierTable config.SigVerifierTableConfig, sigVerifierHashProvider func() hash.Hash, knownKEMTable config.KemTableConfig) HandshakeProcessor {
	return &remoteHandshake{
		marshal:                 marshal,
		finishChannel:           make(chan bool),
		cancelledChannel:        make(chan struct{}),
		cancelWaitCond:          sync.NewCond(&sync.Mutex{}),
		sendQueue:               queue.NewQueue[sendItem](),
		handshakeLock:           &sync.Mutex{},
		handshakePhase:          NoPhase,
		settings:                settings,
		presentSignature:        presentedSig,
		verifySignature:         sigVerifierTable,
		kemTable:                knownKEMTable,
		errorChannel:            make(chan error, 1),
		sigVerifierHashProvider: sigVerifierHashProvider,
	}
}

type remoteHandshake struct {
	marshal                 packets.PacketMarshal
	settings                *config.NodeConfig
	presentSignature        *config.SigConfig
	verifySignature         config.SigVerifierTableConfig
	kemTable                config.KemTableConfig
	finishChannel           chan bool
	cancelledChannel        chan struct{}
	cancelWaitCond          *sync.Cond
	sendQueue               queue.Queue[sendItem]
	handshakeLock           *sync.Mutex
	handshakePhase          packets.PacketType
	localSecret             []byte
	remoteSecret            []byte
	errorChannel            chan error
	sigVerifierHashProvider func() hash.Hash
}

func (r *remoteHandshake) GetSignatureVerifierHashProvider() func() hash.Hash {
	return r.sigVerifierHashProvider
}

func (r *remoteHandshake) SetSignatureVerifierHashProvider(prov func() hash.Hash) {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	r.sigVerifierHashProvider = prov
}

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
	subtle.ConstantTimeCopy(1, sTR, r.localSecret)
	return sTR
}

// GetRemoteSecret the secret of this node
func (r *remoteHandshake) GetRemoteSecret() []byte {
	r.handshakeLock.Lock()
	defer r.handshakeLock.Unlock()
	sTR := make([]byte, len(r.remoteSecret))
	subtle.ConstantTimeCopy(1, sTR, r.remoteSecret)
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
			r.broadcastCancel()
			select {
			case r.finishChannel <- false:
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

func (r *remoteHandshake) getInitProofPayload(proofHMAC []byte, localKey crypto.KemPublicKey) (*packets.InitProofPayload, error) {
	var err error
	p := &packets.InitProofPayload{ProofHMAC: proofHMAC}
	r.remoteSecret, err = p.Encapsulate(localKey)
	if err != nil {
		return nil, err
	}
	p.PacketHasher = hmac.New(r.settings.HMACHash, r.remoteSecret)
	return p, nil
}

func (r *remoteHandshake) errTerminate(err error) {
	select {
	case r.errorChannel <- err:
	default:
	}
	r.sendQueue.Enqueue(sendItem{
		header:  packets.PacketHeader{ID: packets.ConnectionRejectedPacketType, ConnectionUUID: r.settings.ConnID, Time: time.Now()},
		payload: &packets.EmptyPayload{},
	})
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
	var recvKey crypto.KemPublicKey
	var initHeader *packets.PacketHeader
	var initPyl *packets.InitPayload
	var initProofPyl *packets.InitProofPayload
	var sigDataPyl *packets.PublicKeySignedPacketPayload // TODO: Needed for stored hash...
	for {
		recvHeader, recvPayload, err := r.marshal.Unmarshal()
		if err != nil {
			if errors.Is(err, packets.ErrFragmentReceived) || errors.Is(err, packets.ErrInvalidPacketID) {
				continue
			}
			r.errTerminate(err)
			break
		}
		if recvHeader.ConnectionUUID == r.settings.ConnID &&
			!time.Now().Add(-r.settings.ValidDuration).After(recvHeader.Time) &&
			!time.Now().Add(r.settings.ValidDuration).Before(recvHeader.Time) {
			if recvHeader.ID == packets.ConnectionRejectedPacketType {
				select {
				case r.finishChannel <- false:
				default:
				}
				break
			} else if recvHeader.ID == packets.InitPacketType {
				if r.handshakePhase == NoPhase || r.handshakePhase == Init2APhase ||
					r.handshakePhase == packets.SignatureRequestPacketType || r.handshakePhase == packets.SignaturePublicKeyRequestPacketType {
					if lpyl, k := recvPayload.(*packets.InitPayload); k {
						initHeader = recvHeader
						initPyl = lpyl
						r.localSecret, err = lpyl.Decapsulate(r.settings.GetPrivateKey())
						if err == nil { // 2/(B)
							// TODO: In future, store hash if available
							lflg := r.settings.RequestLocalPublicKey || len(lpyl.PublicKeyHash) == 0
							if !lflg {
								recvKey, err = r.kemTable.FindFromHash(lpyl.PublicKeyHash)
								if err == nil {
									err = r.kemTable.SetRemoteKey(recvKey, r.settings.ConnID) // Actually local key in this scenario
								}
								if errors.Is(err, config.ErrNoKey) || errors.Is(err, config.ErrMultipleKeys) {
									lflg = true
								} else {
									r.errTerminate(err)
									break
								}
							}
							if lflg { // 2(B)
								r.handshakePhase = packets.PublicKeyRequestPacketType
								r.sendQueue.Enqueue(sendItem{
									header:  packets.PacketHeader{ID: packets.PublicKeyRequestPacketType, ConnectionUUID: r.settings.ConnID, Time: time.Now()},
									payload: &packets.EmptyPayload{},
								})
							} else { // 2
								initProofPyl, err = r.getInitProofPayload(packets.PacketDataHash(*initHeader, initPyl, hmac.New(r.settings.HMACHash, r.localSecret)), recvKey)
								if err == nil {
									r.handshakePhase = packets.InitProofPacketType
									r.sendQueue.Enqueue(sendItem{header: packets.PacketHeader{ID: packets.InitProofPacketType, ConnectionUUID: r.settings.ConnID, Time: time.Now()},
										payload: initProofPyl,
									})
								} else {
									r.errTerminate(err)
									break
								}
							}
						} else if errors.Is(err, packets.ErrNoEncapsulation) { // 2(A)
							// TODO: In future, store hash if available
							r.handshakePhase = packets.PublicKeyDataPacketType
							r.sendQueue.Enqueue(sendItem{
								header:  packets.PacketHeader{ID: packets.PublicKeyDataPacketType, ConnectionUUID: r.settings.ConnID, Time: time.Now()},
								payload: &packets.PublicKeyDataPayload{Data: r.settings.GetPublicKeyData()},
							})
						} else {
							r.errTerminate(err)
							break
						}
					}
				}
			} else if recvHeader.ID == packets.FinalProofPacketType {
				if r.handshakePhase == packets.InitProofPacketType {
					if lpyl, k := recvPayload.(*packets.FinalProofPayload); k {
						if subtle.ConstantTimeCompare(lpyl.ProofHMAC, initProofPyl.PacketHash) == 1 {
							select {
							case r.finishChannel <- false:
							default:
							}
							break
						} else {
							r.handshakePhase = packets.ConnectionRejectedPacketType
							select {
							case r.errorChannel <- ErrFinalProofFailed:
							default:
							}
							select {
							case r.finishChannel <- false:
							default:
							}
							break
						}
					} else {
						r.handshakePhase = packets.ConnectionRejectedPacketType
						select {
						case r.errorChannel <- ErrFinalProofFailed:
						default:
						}
						select {
						case r.finishChannel <- false:
						default:
						}
						break
					}
				}
			} else if recvHeader.ID == packets.PublicKeyDataPacketType {
				if r.handshakePhase == packets.PublicKeyRequestPacketType {
					if lpyl, k := recvPayload.(*packets.PublicKeyDataPayload); k && initHeader != nil {
						err := r.kemTable.SetRemoteKeyData(lpyl.Data, r.settings.ConnID)
						var err2 error
						recvKey, err2 = lpyl.Load(r.settings.KEM)
						if err2 == nil {
							if err == nil {
								initProofPyl, err = r.getInitProofPayload(packets.PacketDataHash(*initHeader, initPyl, hmac.New(r.settings.HMACHash, r.localSecret)), recvKey)
								if err == nil {
									r.handshakePhase = packets.InitProofPacketType
									r.sendQueue.Enqueue(sendItem{header: packets.PacketHeader{ID: packets.InitProofPacketType, ConnectionUUID: r.settings.ConnID, Time: time.Now()},
										payload: initProofPyl,
									})
								} else {
									r.errTerminate(err)
									break
								}
							} else {
								r.handshakePhase = packets.SignatureRequestPacketType
								r.sendQueue.Enqueue(sendItem{
									header:  packets.PacketHeader{ID: packets.SignatureRequestPacketType, ConnectionUUID: r.settings.ConnID, Time: time.Now()},
									payload: &packets.EmptyPayload{},
								})
							}
						} else {
							r.errTerminate(err2)
							break
						}
					}
				}
			} else if recvHeader.ID == packets.SignatureRequestPacketType {
				if r.handshakePhase == packets.PublicKeyDataPacketType {
					if r.presentSignature == nil {
						r.errTerminate(ErrNoSignatureToPresent)
						break
					} else {
						r.handshakePhase = packets.PublicKeySignedPacketType
						r.sendQueue.Enqueue(sendItem{
							header:  packets.PacketHeader{ID: packets.PublicKeySignedPacketType, ConnectionUUID: r.settings.ConnID, Time: time.Now()},
							payload: &packets.PublicKeySignedPacketPayload{SignatureData: r.presentSignature.Data, SigPubKeyHash: r.presentSignature.KeyHash(r.settings.KeyCheckHash())},
						})
					}
				}
			} else if recvHeader.ID == packets.PublicKeySignedPacketType {
				if r.handshakePhase == packets.SignatureRequestPacketType {
					if lpyl, k := recvPayload.(*packets.PublicKeySignedPacketPayload); k && initHeader != nil {
						sigDataPyl = lpyl
						rk, err := r.verifySignature.FindFromHash(lpyl.SigPubKeyHash)
						if err == nil {
							sigData, err := lpyl.Load(recvKey)
							if err == nil {
								if sigData.Verify(r.sigVerifierHashProvider(), rk) {
									err = r.kemTable.Add(recvKey, &r.settings.ConnID)
									if err == nil {
										initProofPyl, err = r.getInitProofPayload(packets.PacketDataHash(*initHeader, initPyl, hmac.New(r.settings.HMACHash, r.localSecret)), recvKey)
										if err == nil {
											r.handshakePhase = packets.InitProofPacketType
											r.sendQueue.Enqueue(sendItem{header: packets.PacketHeader{ID: packets.InitProofPacketType, ConnectionUUID: r.settings.ConnID, Time: time.Now()},
												payload: initProofPyl,
											})
										} else {
											r.errTerminate(err)
											break
										}
									} else {
										r.errTerminate(err)
										break
									}
								} else {
									r.errTerminate(ErrOtherNodeNotVerified)
									break
								}
							} else {
								r.errTerminate(err)
								break
							}
						} else if errors.Is(err, config.ErrMultipleKeys) {
							r.handshakePhase = packets.SignaturePublicKeyRequestPacketType
							r.sendQueue.Enqueue(sendItem{
								header:  packets.PacketHeader{ID: packets.SignaturePublicKeyRequestPacketType, ConnectionUUID: r.settings.ConnID, Time: time.Now()},
								payload: &packets.EmptyPayload{},
							})
						} else {
							r.errTerminate(ErrOtherNodeNotVerified)
							break
						}
					} else {
						r.errTerminate(ErrOtherNodeNotVerified)
						break
					}
				}
			} else if recvHeader.ID == packets.SignaturePublicKeyRequestPacketType {
				if r.handshakePhase == packets.PublicKeySignedPacketType {
					if r.presentSignature == nil {
						r.errTerminate(ErrNoSignatureToPresent)
						break
					} else {
						r.handshakePhase = packets.SignedPacketPublicKeyPacketType
						r.sendQueue.Enqueue(sendItem{
							header:  packets.PacketHeader{ID: packets.SignedPacketPublicKeyPacketType, ConnectionUUID: r.settings.ConnID, Time: time.Now()},
							payload: &packets.SignedPacketPublicKeyPayload{Data: r.presentSignature.Key},
						})
					}
				}
			} else if recvHeader.ID == packets.SignedPacketPublicKeyPacketType {
				if r.handshakePhase == packets.SignaturePublicKeyRequestPacketType {
					if lpyl, k := recvPayload.(*packets.SignedPacketPublicKeyPayload); k && sigDataPyl != nil && initHeader != nil {
						rk, err := r.verifySignature.Find(lpyl.Data)
						if err == nil {
							sigData, err := sigDataPyl.Load(recvKey)
							if err == nil {
								if sigData.Verify(r.sigVerifierHashProvider(), rk) {
									err = r.kemTable.Add(recvKey, &r.settings.ConnID)
									if err == nil {
										initProofPyl, err = r.getInitProofPayload(packets.PacketDataHash(*initHeader, initPyl, hmac.New(r.settings.HMACHash, r.localSecret)), recvKey)
										if err == nil {
											r.handshakePhase = packets.InitProofPacketType
											r.sendQueue.Enqueue(sendItem{header: packets.PacketHeader{ID: packets.InitProofPacketType, ConnectionUUID: r.settings.ConnID, Time: time.Now()},
												payload: initProofPyl,
											})
										} else {
											r.errTerminate(err)
											break
										}
									} else {
										r.errTerminate(err)
										break
									}
								} else {
									r.errTerminate(ErrOtherNodeNotVerified)
									break
								}
							} else {
								r.errTerminate(err)
								break
							}
						} else {
							r.errTerminate(ErrOtherNodeNotVerified)
							break
						}
					}
				}
			}
		}
	}
	select { // Should we?
	case <-r.cancelledChannel:
		defer func() { r.cancelledChannel = make(chan struct{}) }()
	}
	defer r.broadcastCancel()
	select {
	case err := <-r.errorChannel:
		r.handshakePhase = packets.ConnectionRejectedPacketType
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
