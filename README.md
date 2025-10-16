# Handshake

Provides a protocol and net implementation to use key encapsulation and signature functions to prove ownership of keys and share a session key.
The architecture of the library allows for the use of the use of any compatible algorithms for key encapsulation, HMAC, hashing and signing.
This can even include providing a capabilities packet for negotiating those aforementioned algorithms (Hence ID 0 has been reserved for this).
Any ID 0 packets will be incompatible with the current implementation as payload length is not explicitly stored.
Fragmentation is supported with up to 255 fragments per packet, however automatic requesting of missing fragments is not yet supported by the protocol.

This library provides an RSA KEM scheme and RSA Sig Scheme wrapping ``crypto/rsa`` from the go standard library

Post quantum cryptography is supported by the library through wrappers around the [github.com/cloudflare/circl](https://github.com/cloudflare/circl) package, provided by [github.com/1f349/pqc-handshake](https://github.com/1f349/pqc-handshake) .

Proving key ownership is as simple as sending the encapsulated symmetric key to the other node, 
with a HMAC of the previous packet bytes 
(Using the key derived from the encapsulation of that packet) 
but only if this is not the initiator packet. 
When receiving a packet confirm the provided HMAC (If there is one) is correct 
(The expected HMAC is calculated before the packet is sent to the other side). 
This proves key ownership as only the private key owner can de-encapsulate the sent encapsulation and use it for the HMAC. 
The encapsulated key also serves as a nonce due to its guaranteed randomisation due to the way KEMs work with deriving a new random key. 

A key derived using the wrong private key can, depending on the KEM implementation, negligibly collide with the actual encapsulated key, 
thereby failing the proof check (A probability equal to 1/[Number of possible keys]). 

The signatures are performed over a hashed form of the data they are signing, 
which also have a much higher, but still negligible chance of collision, 
with other valid data (Due to hashes being shorter than the input data therefore having less entropy)
snd is mitigated via specifying the use of a 'collision-resistant' hash function.

## Packets

### Format Key

[Byte Array {Array Length}]

(Variable uint)

([] Variable byte array headed by variable uint)

? means any positive size

Time is considered in milliseconds from the unix epoch.

### Structure
[Type {1 Byte}] [UUID {16 Byte}] [Timestamp {8 Byte}]

Where the highest bit of type denotes a fragmented packet when set and adds the following to the header:

[Fragment N.o. {1 Byte}] [Fragment Count {1 Byte}] [Fragment Length {2 Byte}]

The Fragment Count value of 0 is reserved for future use and a value of 1 is not expected from sending implementations.

All other internal fields, that are byte arrays, 
are headed with an unsigned integer represented using the 
[github.com/1f349/int-byte-utils](https://github.com/1f349/int-byte-utils) package
signifying the length of the following field, where these are denoted as ([] Field), 
if only an unsigned integer is represented, this is denoted as (Field).

### Types

#### 0) Reserved for future use

Could be used by the user for negotiation of algorithms to be used.

#### 1) Connection Rejected

Sent to end the handshake with a failure.

#### 2) Initiate Packet
([] Encapsulation data via Remote Public Key) ([] Local Public Key Hash)

(A) Encapsulation can be empty to request the remote public key.
(B) Local public key hash can be empty to signify that local should be asked to send key.

Sent as the first packet of the handshake from local or after (6), (8) or (10) towards local.

#### 3) Initiate Proof Packet
([] Encapsulation data via Remote Public Key) ([] HMAC using encapsulated key from local on the initiate packet bytes)

Sent as a response from remote after a (2), allowing local to validate remote's key.

#### 4) Final Proof Packet
([] HMAC using encapsulated key from remote on the initiate proof packet bytes)

Sent as a response from local after a (3), (6), (8) or (10), allowing remote to validate local's key.

#### 5) Public Key Request

Sent as a response from remote after a (2) if the public key from the hash is not found, multi-matched or (2B).

#### 6) Public Key Data Packet
([] Local/Remote Public key)

Sent as a response to (2A) or (5).

#### 7) Signature Request

Sent as a response to (6).

#### 8) Public Key Signed Packet
([] Signature Data) ([] Hash of Signing Public Key)

Sent as a response to (7).

#### 9) Signature Public Key Request

Sent as a response to (8) if the Signing Public Key is not found or multi-matched.

#### 10) Signed Packet Public Key
([] Public Key for Signature)

Sent as a response to (9).

#### 11-31) Reserved for future use

#### 32-127) Reserved for user extended use

## Protocol

### Signature Format

Signature is a byte array represented as base64 when being used in configuration data.

#### Signed Data aka Signature (Once hashed)

[Public Key {? Bytes}] (Issue Time) (Expiry Time) -> Hashed

#### Signature Data

(Signature Length) [Signature {Signature Length}] (Issue Time) (Expiry Time)

### List of Flows

Any handshake stage after (2) can be ended using (1).

A successful handshake is subsequently handled by user packets ((4) received by remote).

These flows are shown in partial where the surrounding flow is the same (As the flows act as portions of state-machines representing the protocol).

2/2B -> 3 -> 4

2/2B -> 5 -> 6 -> 3

2/2B -> 5 -> 6 -> 7 -> 8 -> 3

2/2B -> 5 -> 6 -> 7 -> 8 -> 9 -> 10 -> 3

2A -> 6 -> 2/2B

2A -> 6 -> 7 -> 8 -> 2/2B

2A -> 6 -> 7 -> 8 -> 9 -> 10 -> 2/2B

## License
BSD 3-Clause - (C) 1f349 2025
