//
//  MNSecurity.h
//  MacNexa
//
//  Hardened Zero-Trust Cryptographic Engine & Injected File Secret Storage:
//  - ECDH (P-256) ephemeral key exchange (shared secrets never cross network)
//  - 6-digit Short Authentication String (SAS) visual confirmation
//  - AES-256 + HMAC-SHA256 Encrypt-then-MAC (EtM) authenticated encryption
//  - Monotonic replay protection & timestamp validation
//  - Injected FileSecretStore with 0600/0700 enforced permissions & corruption isolation
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>

NS_ASSUME_NONNULL_BEGIN

#pragma mark - Storage Error Domain & Codes

extern NSErrorDomain const MNStorageErrorDomain;

typedef NS_ERROR_ENUM(MNStorageErrorDomain, MNStorageErrorCode) {
    MNStorageErrorUnknown = 1000,
    MNStorageErrorCorruptedData = 1001,
    MNStorageErrorDecryptionFailed = 1002,
    MNStorageErrorPermissionDenied = 1003,
    MNStorageErrorWriteFailed = 1004,
    MNStorageErrorSeedGenerationFailed = 1005,
    MNStorageErrorInvalidKey = 1006
};

#pragma mark - Injected Secret Storing Protocol

@protocol MNSecretStoring <NSObject>

- (BOOL)setSecret:(NSData *)secret forKey:(NSString *)key error:(NSError * _Nullable * _Nullable)error;
- (nullable NSData *)secretForKey:(NSString *)key error:(NSError * _Nullable * _Nullable)error;
- (BOOL)removeSecretForKey:(NSString *)key error:(NSError * _Nullable * _Nullable)error;
- (nullable NSArray<NSString *> *)allKeysWithPrefix:(NSString *)prefix error:(NSError * _Nullable * _Nullable)error;

@end

#pragma mark - Concrete File Secret Store

@interface MNFileSecretStore : NSObject <MNSecretStoring>

@property (nonatomic, readonly) NSURL *directoryURL;
@property (nonatomic, readonly) NSURL *fileURL;
@property (nonatomic, readonly) NSURL *seedURL;

- (instancetype)init; // Defaults to ~/Library/Application Support/MacNexa
- (instancetype)initWithDirectoryURL:(NSURL *)directoryURL;
- (instancetype)initWithDirectoryPath:(NSString *)directoryPath;

// Explicitly enforces 0600 on files and 0700 on directories
- (BOOL)enforceFilePermissionsWithError:(NSError * _Nullable * _Nullable)error;

@end

#pragma mark - Ephemeral Key Pair

@interface MNEphemeralKeyPair : NSObject
@property (nonatomic, assign) SecKeyRef privateKey;
@property (nonatomic, strong) NSData *publicKeyData;
@end

#pragma mark - Security Controller

@interface MNSecurity : NSObject

+ (instancetype)shared;

// Dependency injection of Secret Store
@property (nonatomic, strong) id<MNSecretStoring> secretStore;
@property (nonatomic, strong, nullable) NSError *lastStorageError;

- (instancetype)init;
- (instancetype)initWithSecretStore:(id<MNSecretStoring>)secretStore;
- (void)clearLastStorageError;

@property (nonatomic, readonly) NSString *localPeerId;
@property (nonatomic, readonly) NSString *localPeerName;

// Trusted Store
- (BOOL)isPeerTrusted:(NSString *)peerId;
- (nullable NSDictionary *)trustedPeerInfo:(NSString *)peerId;
- (nullable NSData *)trustedPeerSecret:(NSString *)peerId;
- (nullable NSData *)trustedPeerSecret:(NSString *)peerId error:(NSError * _Nullable * _Nullable)error;
- (NSArray<NSDictionary *> *)allTrustedPeers;

// Saving & Removing Peers with Error Reporting
- (BOOL)saveTrustedPeerId:(NSString *)peerId
                     name:(NSString *)name
                   secret:(NSData *)secret
                    error:(NSError * _Nullable * _Nullable)error;
- (void)saveTrustedPeerId:(NSString *)peerId name:(NSString *)name secret:(NSData *)secret;

- (BOOL)removeTrustedPeerId:(NSString *)peerId
                      error:(NSError * _Nullable * _Nullable)error;
- (void)removeTrustedPeerId:(NSString *)peerId;

// Diffie-Hellman Key Exchange (ECDH P-256)
- (nullable MNEphemeralKeyPair *)generateEphemeralKeyPair;
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
