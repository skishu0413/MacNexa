//
//  MNSecurity.h
//  MacNexa
//
//  Hardened Zero-Trust Cryptographic Engine:
//  - ECDH (P-256) ephemeral key exchange (shared secrets never cross network)
//  - 6-digit Short Authentication String (SAS) visual confirmation
//  - AES-256 + HMAC-SHA256 Encrypt-then-MAC (EtM) authenticated encryption
//  - Monotonic replay protection & timestamp validation
//  - Hardware-backed macOS Keychain storage for secret keys
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN

@interface MNEphemeralKeyPair : NSObject
@property (nonatomic, assign) SecKeyRef privateKey;
@property (nonatomic, strong) NSData *publicKeyData;
@end

@interface MNSecurity : NSObject

+ (instancetype)shared;

@property (nonatomic, readonly) NSString *localPeerId;
@property (nonatomic, readonly) NSString *localPeerName;

// Keychain-backed Trust Store
- (BOOL)isPeerTrusted:(NSString *)peerId;
- (nullable NSDictionary *)trustedPeerInfo:(NSString *)peerId;
- (nullable NSData *)trustedPeerSecret:(NSString *)peerId;
- (NSArray<NSDictionary *> *)allTrustedPeers;
- (void)saveTrustedPeerId:(NSString *)peerId name:(NSString *)name secret:(NSData *)secret;
- (void)removeTrustedPeerId:(NSString *)peerId;

// Diffie-Hellman Key Exchange (ECDH P-256)
- (MNEphemeralKeyPair *)generateEphemeralKeyPair;
- (nullable NSData *)deriveSharedSecretWithPrivateKey:(SecKeyRef)privateKey
                                  remotePublicKeyData:(NSData *)remotePublicKeyData;

// SAS (Short Authentication String) Calculation
- (NSString *)computeSASFromSecret:(NSData *)secret peerA:(NSString *)peerA peerB:(NSString *)peerB;

// Nonce Generation & Replay Protection
- (uint64_t)nextOutgoingNonce;
- (BOOL)validateIncomingNonce:(uint64_t)nonce timestamp:(NSTimeInterval)timestamp fromPeer:(NSString *)peerId;

// Authenticated Encryption (AES-256 + HMAC-SHA256 Encrypt-then-MAC)
- (nullable NSDictionary *)encryptDictionary:(NSDictionary *)dict
                                   forPeerId:(NSString *)peerId
                                       nonce:(uint64_t)nonce
                                   timestamp:(NSTimeInterval)timestamp;

- (nullable NSDictionary *)decryptAndVerifyDictionary:(NSDictionary *)envelope
                                           fromPeerId:(NSString *)peerId;

@end

NS_ASSUME_NONNULL_END
