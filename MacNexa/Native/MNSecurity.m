//
//  MNSecurity.m
//  MacNexa
//
//  Hardened Zero-Trust Cryptographic Engine & Injected File Secret Storage
//

#import "MNSecurity.h"
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>
#import <sys/stat.h>
#import <string.h>

NSErrorDomain const MNStorageErrorDomain = @"com.macnexa.storage.error";

static NSString * const kMNLocalPeerIdKey = @"com.macnexa.local_peer_id";
static NSString * const kMNTrustedMetadataKey = @"com.macnexa.trusted_metadata";
static NSString * const kMNReplayHistoryKey = @"com.macnexa.replay_history";
static NSString * const kMNLastOutgoingNonceKey = @"com.macnexa.last_outgoing_nonce";

#pragma mark - MNFileSecretStore Implementation

@interface MNFileSecretStore ()
@property (nonatomic, strong) NSURL *directoryURL;
@property (nonatomic, strong) NSURL *fileURL;
@property (nonatomic, strong) NSURL *seedURL;
@property (nonatomic, strong) NSLock *storeLock;
@end

@implementation MNFileSecretStore

- (instancetype)init {
    NSURL *appSupport = [[NSFileManager defaultManager] URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask].firstObject;
    NSURL *macNexaDir = [appSupport URLByAppendingPathComponent:@"MacNexa" isDirectory:YES];
    return [self initWithDirectoryURL:macNexaDir];
}

- (instancetype)initWithDirectoryPath:(NSString *)directoryPath {
    return [self initWithDirectoryURL:[NSURL fileURLWithPath:[directoryPath stringByExpandingTildeInPath] isDirectory:YES]];
}

- (instancetype)initWithDirectoryURL:(NSURL *)directoryURL {
    self = [super init];
    if (self) {
        _directoryURL = directoryURL;
        _fileURL = [directoryURL URLByAppendingPathComponent:@"secrets.enc" isDirectory:NO];
        _seedURL = [directoryURL URLByAppendingPathComponent:@"secrets.seed" isDirectory:NO];
        _storeLock = [[NSLock alloc] init];

        [self ensureDirectoryExistsWithError:nil];
    }
    return self;
}

- (BOOL)ensureDirectoryExistsWithError:(NSError **)error {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *path = self.directoryURL.path;
    if (![fm fileExistsAtPath:path]) {
        NSError *createErr = nil;
        NSDictionary *attrs = @{ NSFilePosixPermissions: @(0700) };
        if (![fm createDirectoryAtURL:self.directoryURL withIntermediateDirectories:YES attributes:attrs error:&createErr]) {
            if (error) {
                *error = [NSError errorWithDomain:MNStorageErrorDomain
                                             code:MNStorageErrorPermissionDenied
                                         userInfo:@{
                    NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to create storage directory at %@", path],
                    NSLocalizedRecoverySuggestionErrorKey: @"Verify your user home directory permissions.",
                    NSUnderlyingErrorKey: createErr ?: [NSNull null]
                }];
            }
            return NO;
        }
    }
    chmod([path fileSystemRepresentation], 0700);
    return YES;
}

- (BOOL)enforceFilePermissionsWithError:(NSError **)error {
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:self.directoryURL.path]) {
        if (chmod(self.directoryURL.path.fileSystemRepresentation, 0700) != 0) {
            if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:@{NSLocalizedDescriptionKey: @"Failed to set 0700 on storage directory"}];
            return NO;
        }
    }
    if ([fm fileExistsAtPath:self.seedURL.path]) {
        if (chmod(self.seedURL.path.fileSystemRepresentation, 0600) != 0) {
            if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:@{NSLocalizedDescriptionKey: @"Failed to set 0600 on seed file"}];
            return NO;
        }
    }
    if ([fm fileExistsAtPath:self.fileURL.path]) {
        if (chmod(self.fileURL.path.fileSystemRepresentation, 0600) != 0) {
            if (error) *error = [NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:@{NSLocalizedDescriptionKey: @"Failed to set 0600 on secrets file"}];
            return NO;
        }
    }
    return YES;
}

- (void)quarantineCorruptFileAtURL:(NSURL *)url reason:(NSString *)reason {
    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:url.path]) return;

    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    NSString *corruptName = [NSString stringWithFormat:@"%@.corrupt.%ld", url.lastPathComponent, (long)now];
    NSURL *dest = [url.URLByDeletingLastPathComponent URLByAppendingPathComponent:corruptName];
    [fm moveItemAtURL:url toURL:dest error:nil];
    if ([fm fileExistsAtPath:dest.path]) {
        chmod(dest.path.fileSystemRepresentation, 0600);
    }
    NSLog(@"[MacNexa Storage] ⚠️ QUARANTINED corrupt file: %@ -> %@ (Reason: %@)", url.lastPathComponent, corruptName, reason);
}

- (nullable NSData *)loadOrCreateMasterKeyWithError:(NSError **)error {
    if (![self ensureDirectoryExistsWithError:error]) return nil;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *seedPath = self.seedURL.path;

    if ([fm fileExistsAtPath:seedPath]) {
        chmod(seedPath.fileSystemRepresentation, 0600);
        NSData *existing = [NSData dataWithContentsOfURL:self.seedURL];
        if (existing && existing.length == 32) {
            return existing;
        }
        // Corruption in seed file
        [self quarantineCorruptFileAtURL:self.seedURL reason:@"Seed file is corrupted or not exactly 32 bytes"];
    }

    // Generate fresh 32 bytes
    NSMutableData *seed = [NSMutableData dataWithLength:32];
    int status = SecRandomCopyBytes(kSecRandomDefault, 32, seed.mutableBytes);
    if (status != errSecSuccess) {
        if (error) {
            *error = [NSError errorWithDomain:MNStorageErrorDomain
                                         code:MNStorageErrorSeedGenerationFailed
                                     userInfo:@{
                NSLocalizedDescriptionKey: @"Failed to generate cryptographically secure random seed.",
                NSLocalizedRecoverySuggestionErrorKey: @"Ensure system entropy pool is available."
            }];
        }
        return nil;
    }

    NSError *wErr = nil;
    if (![seed writeToURL:self.seedURL options:NSDataWritingAtomic error:&wErr]) {
        if (error) {
            *error = [NSError errorWithDomain:MNStorageErrorDomain
                                         code:MNStorageErrorWriteFailed
                                     userInfo:@{
                NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to write seed file: %@", wErr.localizedDescription],
                NSUnderlyingErrorKey: wErr ?: [NSNull null]
            }];
        }
        return nil;
    }

    chmod(seedPath.fileSystemRepresentation, 0600);
    [fm setAttributes:@{NSFilePosixPermissions: @(0600)} ofItemAtPath:seedPath error:nil];
    return seed;
}

- (nullable NSMutableDictionary<NSString *, NSData *> *)readAllDictionaryWithError:(NSError **)error {
    if (![self ensureDirectoryExistsWithError:error]) return nil;

    NSFileManager *fm = [NSFileManager defaultManager];
    if (![fm fileExistsAtPath:self.fileURL.path]) {
        return [NSMutableDictionary dictionary];
    }

    chmod(self.fileURL.path.fileSystemRepresentation, 0600);

    NSError *rErr = nil;
    NSData *raw = [NSData dataWithContentsOfURL:self.fileURL options:0 error:&rErr];
    if (!raw) {
        if (error) {
            *error = [NSError errorWithDomain:MNStorageErrorDomain
                                         code:MNStorageErrorCorruptedData
                                     userInfo:@{
                NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to read secrets file: %@", rErr.localizedDescription],
                NSUnderlyingErrorKey: rErr ?: [NSNull null]
            }];
        }
        return nil;
    }

    if (raw.length == 0) {
        return [NSMutableDictionary dictionary];
    }

    // Header layout:
    // Magic: "MNSS" (4 bytes)
    // Version: 0x01 (1 byte)
    // IV: 16 bytes
    // HMAC: 32 bytes (SHA-256)
    // Ciphertext: remaining bytes (must be multiple of 16)
    const size_t kHeaderSize = 4 + 1 + 16 + 32; // 53 bytes
    if (raw.length < kHeaderSize) {
        [self quarantineCorruptFileAtURL:self.fileURL reason:@"File truncated (less than 53-byte header)"];
        if (error) {
            *error = [NSError errorWithDomain:MNStorageErrorDomain
                                         code:MNStorageErrorCorruptedData
                                     userInfo:@{
                NSLocalizedDescriptionKey: @"Encrypted secret store is truncated or corrupted.",
                NSLocalizedRecoverySuggestionErrorKey: @"The corrupted store has been quarantined to prevent further errors. Please re-pair your Macs."
            }];
        }
        return nil;
    }

    const uint8_t *bytes = (const uint8_t *)raw.bytes;
    if (memcmp(bytes, "MNSS", 4) != 0) {
        [self quarantineCorruptFileAtURL:self.fileURL reason:@"Invalid header magic signature"];
        if (error) {
            *error = [NSError errorWithDomain:MNStorageErrorDomain
                                         code:MNStorageErrorCorruptedData
                                     userInfo:@{
                NSLocalizedDescriptionKey: @"Secret store has an invalid file header signature.",
                NSLocalizedRecoverySuggestionErrorKey: @"The corrupted file was safely quarantined."
            }];
        }
        return nil;
    }

    uint8_t version = bytes[4];
    if (version != 0x01) {
        [self quarantineCorruptFileAtURL:self.fileURL reason:[NSString stringWithFormat:@"Unsupported store version: %d", version]];
        if (error) {
            *error = [NSError errorWithDomain:MNStorageErrorDomain
                                         code:MNStorageErrorCorruptedData
                                     userInfo:@{
                NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Unsupported secret store version %d.", version]
            }];
        }
        return nil;
    }

    NSData *masterKey = [self loadOrCreateMasterKeyWithError:error];
    if (!masterKey) return nil;

    const uint8_t *iv = bytes + 5;
    const uint8_t *storedHmac = bytes + 21;
    const uint8_t *ciphertext = bytes + 53;
    size_t cipherLen = raw.length - 53;

    if (cipherLen == 0 || (cipherLen % kCCBlockSizeAES128 != 0)) {
        [self quarantineCorruptFileAtURL:self.fileURL reason:@"Ciphertext length is not a multiple of AES block size"];
        if (error) {
            *error = [NSError errorWithDomain:MNStorageErrorDomain
                                         code:MNStorageErrorCorruptedData
                                     userInfo:@{
                NSLocalizedDescriptionKey: @"Secret store ciphertext is truncated or corrupted."
            }];
        }
        return nil;
    }

    // Compute HMAC over (Magic[4] + Version[1] + IV[16] + Ciphertext[cipherLen])
    NSMutableData *macData = [NSMutableData dataWithBytes:bytes length:5];
    [macData appendBytes:iv length:16];
    [macData appendBytes:ciphertext length:cipherLen];

    uint8_t computedHmac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, masterKey.bytes, masterKey.length, macData.bytes, macData.length, computedHmac);

    if (timingsafe_bcmp(computedHmac, storedHmac, CC_SHA256_DIGEST_LENGTH) != 0) {
        [self quarantineCorruptFileAtURL:self.fileURL reason:@"HMAC verification failed (tampered or corrupted data)"];
        if (error) {
            *error = [NSError errorWithDomain:MNStorageErrorDomain
                                         code:MNStorageErrorDecryptionFailed
                                     userInfo:@{
                NSLocalizedDescriptionKey: @"Secret store HMAC authentication failed. The data is corrupted or has been tampered with.",
                NSLocalizedRecoverySuggestionErrorKey: @"The corrupted file was safely quarantined."
            }];
        }
        return nil;
    }

    // Decrypt ciphertext
    NSMutableData *plainData = [NSMutableData dataWithLength:cipherLen];
    size_t numDecrypted = 0;
    CCCryptorStatus status = CCCrypt(
        kCCDecrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding,
        masterKey.bytes,
        kCCKeySizeAES256,
        iv,
        ciphertext,
        cipherLen,
        plainData.mutableBytes,
        plainData.length,
        &numDecrypted
    );
    if (status != kCCSuccess) {
        [self quarantineCorruptFileAtURL:self.fileURL reason:@"AES-256 decryption failed"];
        if (error) {
            *error = [NSError errorWithDomain:MNStorageErrorDomain
                                         code:MNStorageErrorDecryptionFailed
                                     userInfo:@{
                NSLocalizedDescriptionKey: [NSString stringWithFormat:@"AES decryption failed with status %d.", (int)status]
            }];
        }
        return nil;
    }
    plainData.length = numDecrypted;

    NSError *jsonErr = nil;
    NSDictionary *rawDict = [NSJSONSerialization JSONObjectWithData:plainData options:0 error:&jsonErr];
    if (![rawDict isKindOfClass:[NSDictionary class]]) {
        [self quarantineCorruptFileAtURL:self.fileURL reason:@"JSON payload is not a dictionary"];
        if (error) {
            *error = [NSError errorWithDomain:MNStorageErrorDomain
                                         code:MNStorageErrorCorruptedData
                                     userInfo:@{
                NSLocalizedDescriptionKey: @"Failed to decode JSON dictionary from decrypted secret store.",
                NSUnderlyingErrorKey: jsonErr ?: [NSNull null]
            }];
        }
        return nil;
    }

    NSMutableDictionary<NSString *, NSData *> *result = [NSMutableDictionary dictionaryWithCapacity:rawDict.count];
    for (NSString *k in rawDict) {
        NSString *b64 = rawDict[k];
        if ([b64 isKindOfClass:[NSString class]]) {
            NSData *sec = [[NSData alloc] initWithBase64EncodedString:b64 options:0];
            if (sec) {
                result[k] = sec;
            }
        }
    }
    return result;
}

- (BOOL)writeAllDictionary:(NSDictionary<NSString *, NSData *> *)dict error:(NSError **)error {
    if (![self ensureDirectoryExistsWithError:error]) return NO;

    NSData *masterKey = [self loadOrCreateMasterKeyWithError:error];
    if (!masterKey) return NO;

    NSMutableDictionary<NSString *, NSString *> *wireDict = [NSMutableDictionary dictionaryWithCapacity:dict.count];
    for (NSString *k in dict) {
        NSData *val = dict[k];
        if ([val isKindOfClass:[NSData class]]) {
            wireDict[k] = [val base64EncodedStringWithOptions:0];
        }
    }

    NSError *jsonErr = nil;
    NSData *plainData = [NSJSONSerialization dataWithJSONObject:wireDict options:0 error:&jsonErr];
    if (!plainData) {
        if (error) {
            *error = [NSError errorWithDomain:MNStorageErrorDomain
                                         code:MNStorageErrorWriteFailed
                                     userInfo:@{
                NSLocalizedDescriptionKey: @"Failed to serialize secret store dictionary to JSON.",
                NSUnderlyingErrorKey: jsonErr ?: [NSNull null]
            }];
        }
        return NO;
    }

    // Generate 16 bytes random IV
    uint8_t iv[16];
    if (SecRandomCopyBytes(kSecRandomDefault, 16, iv) != errSecSuccess) {
        arc4random_buf(iv, 16);
    }

    NSMutableData *cipherData = [NSMutableData dataWithLength:plainData.length + kCCBlockSizeAES128];
    size_t numEncrypted = 0;
    CCCryptorStatus status = CCCrypt(
        kCCEncrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding,
        masterKey.bytes,
        kCCKeySizeAES256,
        iv,
        plainData.bytes,
        plainData.length,
        cipherData.mutableBytes,
        cipherData.length,
        &numEncrypted
    );
    if (status != kCCSuccess) {
        if (error) {
            *error = [NSError errorWithDomain:MNStorageErrorDomain
                                         code:MNStorageErrorWriteFailed
                                     userInfo:@{
                NSLocalizedDescriptionKey: [NSString stringWithFormat:@"AES encryption failed with status %d.", (int)status]
            }];
        }
        return NO;
    }
    cipherData.length = numEncrypted;

    // Compute HMAC-SHA256 over Magic (4) + Version (1) + IV (16) + Ciphertext
    NSMutableData *macData = [NSMutableData dataWithBytes:"MNSS" length:4];
    uint8_t ver = 0x01;
    [macData appendBytes:&ver length:1];
    [macData appendBytes:iv length:16];
    [macData appendData:cipherData];

    uint8_t hmac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, masterKey.bytes, masterKey.length, macData.bytes, macData.length, hmac);

    // Assemble final container:
    // Magic (4) + Version (1) + IV (16) + HMAC (32) + Ciphertext
    NSMutableData *container = [NSMutableData dataWithBytes:"MNSS" length:4];
    [container appendBytes:&ver length:1];
    [container appendBytes:iv length:16];
    [container appendBytes:hmac length:CC_SHA256_DIGEST_LENGTH];
    [container appendData:cipherData];

    NSError *wErr = nil;
    BOOL written = [container writeToURL:self.fileURL options:NSDataWritingAtomic error:&wErr];
    if (!written) {
        if (error) {
            *error = [NSError errorWithDomain:MNStorageErrorDomain
                                         code:MNStorageErrorWriteFailed
                                     userInfo:@{
                NSLocalizedDescriptionKey: [NSString stringWithFormat:@"Failed to write secrets file atomically: %@", wErr.localizedDescription],
                NSUnderlyingErrorKey: wErr ?: [NSNull null]
            }];
        }
        return NO;
    }

    chmod(self.fileURL.path.fileSystemRepresentation, 0600);
    [[NSFileManager defaultManager] setAttributes:@{NSFilePosixPermissions: @(0600)} ofItemAtPath:self.fileURL.path error:nil];
    return YES;
}

#pragma mark - MNSecretStoring Protocol

- (BOOL)setSecret:(NSData *)secret forKey:(NSString *)key error:(NSError **)error {
    if (!key || !secret) {
        if (error) *error = [NSError errorWithDomain:MNStorageErrorDomain code:MNStorageErrorInvalidKey userInfo:@{NSLocalizedDescriptionKey: @"Key and secret data must not be nil"}];
        return NO;
    }
    [self.storeLock lock];
    NSMutableDictionary *dict = [self readAllDictionaryWithError:error];
    if (!dict) {
        [self.storeLock unlock];
        return NO;
    }
    dict[key] = secret;
    BOOL ok = [self writeAllDictionary:dict error:error];
    [self.storeLock unlock];
    return ok;
}

- (nullable NSData *)secretForKey:(NSString *)key error:(NSError **)error {
    if (!key) return nil;
    [self.storeLock lock];
    NSMutableDictionary *dict = [self readAllDictionaryWithError:error];
    NSData *sec = dict[key];
    [self.storeLock unlock];
    return sec;
}

- (BOOL)removeSecretForKey:(NSString *)key error:(NSError **)error {
    if (!key) return YES;
    [self.storeLock lock];
    NSMutableDictionary *dict = [self readAllDictionaryWithError:error];
    if (!dict) {
        [self.storeLock unlock];
        return NO;
    }
    [dict removeObjectForKey:key];
    BOOL ok = [self writeAllDictionary:dict error:error];
    [self.storeLock unlock];
    return ok;
}

- (nullable NSArray<NSString *> *)allKeysWithPrefix:(NSString *)prefix error:(NSError **)error {
    [self.storeLock lock];
    NSMutableDictionary *dict = [self readAllDictionaryWithError:error];
    if (!dict) {
        [self.storeLock unlock];
        return nil;
    }
    NSMutableArray *result = [NSMutableArray array];
    for (NSString *k in dict) {
        if (!prefix || prefix.length == 0 || [k hasPrefix:prefix]) {
            [result addObject:k];
        }
    }
    [self.storeLock unlock];
    return result;
}

@end

#pragma mark - MNEphemeralKeyPair Implementation

@implementation MNEphemeralKeyPair
- (void)dealloc {
    if (_privateKey) {
        CFRelease(_privateKey);
        _privateKey = NULL;
    }
}
@end

#pragma mark - MNSecurity Implementation

@interface MNSecurity ()
@property (nonatomic, copy) NSString *localPeerId;
@property (nonatomic, copy) NSString *localPeerName;
@property (nonatomic, assign) uint64_t currentNonce;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSNumber *> *lastSeenNonces;
@property (nonatomic, strong) NSLock *securityLock;
@end

@implementation MNSecurity

+ (instancetype)shared {
    static MNSecurity *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[MNSecurity alloc] init];
    });
    return instance;
}

- (instancetype)init {
    return [self initWithSecretStore:[[MNFileSecretStore alloc] init]];
}

- (instancetype)initWithSecretStore:(id<MNSecretStoring>)secretStore localPeerId:(nullable NSString *)localPeerId {
    self = [super init];
    if (self) {
        _secretStore = secretStore ?: [[MNFileSecretStore alloc] init];
        _securityLock = [[NSLock alloc] init];

        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        NSDictionary *savedNonces = [defaults dictionaryForKey:kMNReplayHistoryKey];
        _lastSeenNonces = [savedNonces mutableCopy] ?: [NSMutableDictionary dictionary];

        uint64_t savedOutgoing = (uint64_t)[defaults integerForKey:kMNLastOutgoingNonceKey];
        uint64_t nowMs = (uint64_t)[[NSDate date] timeIntervalSince1970] * 1000;
        _currentNonce = (savedOutgoing >= nowMs) ? (savedOutgoing + 1000) : nowMs;

        if (localPeerId && localPeerId.length > 0) {
            _localPeerId = [localPeerId copy];
        } else {
            NSString *existingId = [defaults stringForKey:kMNLocalPeerIdKey];
            if (!existingId) {
                existingId = [[NSUUID UUID] UUIDString];
                [defaults setObject:existingId forKey:kMNLocalPeerIdKey];
                [defaults synchronize];
            }
            _localPeerId = existingId;
        }
        _localPeerName = [[NSHost currentHost] localizedName] ?: @"Mac";
    }
    return self;
}

- (instancetype)initWithSecretStore:(id<MNSecretStoring>)secretStore {
    return [self initWithSecretStore:secretStore localPeerId:nil];
}

- (void)clearLastStorageError {
    [self.securityLock lock];
    self.lastStorageError = nil;
    [self.securityLock unlock];
}

- (void)resetReplayHistory {
    [self.securityLock lock];
    [self.lastSeenNonces removeAllObjects];
    [[NSUserDefaults standardUserDefaults] removeObjectForKey:kMNReplayHistoryKey];
    [[NSUserDefaults standardUserDefaults] synchronize];
    [self.securityLock unlock];
}

#pragma mark - Trusted Peers Management

- (BOOL)isPeerTrusted:(NSString *)peerId {
    if (!peerId) return NO;
    return [self trustedPeerSecret:peerId error:nil] != nil;
}

- (nullable NSDictionary *)trustedPeerInfo:(NSString *)peerId {
    if (!peerId) return nil;
    NSDictionary *meta = [[NSUserDefaults standardUserDefaults] dictionaryForKey:kMNTrustedMetadataKey];
    return meta[peerId];
}

- (nullable NSData *)trustedPeerSecret:(NSString *)peerId error:(NSError **)error {
    if (!peerId) return nil;
    NSError *storeErr = nil;
    NSData *sec = [self.secretStore secretForKey:peerId error:&storeErr];
    if (storeErr) {
        [self.securityLock lock];
        self.lastStorageError = storeErr;
        [self.securityLock unlock];
        if (error) *error = storeErr;
    }
    return sec;
}

- (nullable NSData *)trustedPeerSecret:(NSString *)peerId {
    return [self trustedPeerSecret:peerId error:nil];
}

- (NSArray<NSDictionary *> *)allTrustedPeers {
    NSDictionary *meta = [[NSUserDefaults standardUserDefaults] dictionaryForKey:kMNTrustedMetadataKey];
    NSMutableArray *result = [NSMutableArray array];
    for (NSString *peerId in meta) {
        if ([self isPeerTrusted:peerId]) {
            NSMutableDictionary *dict = [meta[peerId] mutableCopy];
            dict[@"id"] = peerId;
            [result addObject:dict];
        }
    }
    return result;
}

- (BOOL)saveTrustedPeerId:(NSString *)peerId
                     name:(NSString *)name
                   secret:(NSData *)secret
                    error:(NSError **)error {
    if (!peerId || !secret) {
        if (error) {
            *error = [NSError errorWithDomain:MNStorageErrorDomain
                                         code:MNStorageErrorInvalidKey
                                     userInfo:@{ NSLocalizedDescriptionKey: @"Peer ID and secret must not be nil." }];
        }
        return NO;
    }

    [self.securityLock lock];

    NSError *storeErr = nil;
    BOOL saved = [self.secretStore setSecret:secret forKey:peerId error:&storeErr];
    if (!saved) {
        self.lastStorageError = storeErr;
        if (error) *error = storeErr;
        [self.securityLock unlock];
        return NO;
    }

    // Save metadata
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSMutableDictionary *meta = [[defaults dictionaryForKey:kMNTrustedMetadataKey] mutableCopy] ?: [NSMutableDictionary dictionary];
    meta[peerId] = @{
        @"name": name ?: @"Mac",
        @"pairedAt": @([[NSDate date] timeIntervalSince1970])
    };
    [defaults setObject:meta forKey:kMNTrustedMetadataKey];
    [defaults synchronize];

    [self.securityLock unlock];
    return YES;
}

- (void)saveTrustedPeerId:(NSString *)peerId name:(NSString *)name secret:(NSData *)secret {
    [self saveTrustedPeerId:peerId name:name secret:secret error:nil];
}

- (BOOL)removeTrustedPeerId:(NSString *)peerId error:(NSError **)error {
    if (!peerId) return YES;
    [self.securityLock lock];

    NSError *storeErr = nil;
    BOOL removed = [self.secretStore removeSecretForKey:peerId error:&storeErr];
    if (!removed) {
        self.lastStorageError = storeErr;
        if (error) *error = storeErr;
        [self.securityLock unlock];
        return NO;
    }

    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSMutableDictionary *meta = [[defaults dictionaryForKey:kMNTrustedMetadataKey] mutableCopy];
    if (meta) {
        [meta removeObjectForKey:peerId];
        [defaults setObject:meta forKey:kMNTrustedMetadataKey];
    }

    [self.lastSeenNonces removeObjectForKey:peerId];
    [defaults setObject:[self.lastSeenNonces copy] forKey:kMNReplayHistoryKey];
    [defaults synchronize];

    [self.securityLock unlock];
    return YES;
}

- (void)removeTrustedPeerId:(NSString *)peerId {
    [self removeTrustedPeerId:peerId error:nil];
}

#pragma mark - Diffie-Hellman Key Exchange (ECDH P-256)

- (nullable MNEphemeralKeyPair *)generateEphemeralKeyPair {
    NSDictionary *params = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrKeySizeInBits: @256
    };
    CFErrorRef error = NULL;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)params, &error);
    if (!privateKey) return nil;

    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    CFDataRef pubData = SecKeyCopyExternalRepresentation(publicKey, &error);
    if (publicKey) CFRelease(publicKey);
    if (!pubData) {
        CFRelease(privateKey);
        return nil;
    }

    MNEphemeralKeyPair *pair = [[MNEphemeralKeyPair alloc] init];
    pair.privateKey = privateKey;
    pair.publicKeyData = (__bridge_transfer NSData *)pubData;
    return pair;
}

- (nullable NSData *)deriveSharedSecretWithPrivateKey:(SecKeyRef)privateKey
                                  remotePublicKeyData:(NSData *)remotePublicKeyData {
    if (!privateKey || !remotePublicKeyData) return nil;

    NSDictionary *keyParams = @{
        (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
        (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPublic,
        (__bridge id)kSecAttrKeySizeInBits: @256
    };
    CFErrorRef error = NULL;
    SecKeyRef remotePubKey = SecKeyCreateWithData((__bridge CFDataRef)remotePublicKeyData,
                                                  (__bridge CFDictionaryRef)keyParams,
                                                  &error);
    if (!remotePubKey) return nil;

    NSDictionary *exchangeParams = @{
        (__bridge id)kSecKeyKeyExchangeParameterRequestedSize: @32
    };
    CFDataRef shared = SecKeyCopyKeyExchangeResult(privateKey,
                                                   kSecKeyAlgorithmECDHKeyExchangeStandard,
                                                   remotePubKey,
                                                   (__bridge CFDictionaryRef)exchangeParams,
                                                   &error);
    CFRelease(remotePubKey);
    if (!shared) return nil;

    return (__bridge_transfer NSData *)shared;
}

#pragma mark - SAS (Short Authentication String)

- (NSString *)computeSASFromSecret:(NSData *)secret peerA:(NSString *)peerA peerB:(NSString *)peerB {
    NSArray *sorted = [@[peerA ?: @"", peerB ?: @""] sortedArrayUsingSelector:@selector(compare:)];
    NSString *context = [NSString stringWithFormat:@"MacNexa-SAS-v1:%@:%@", sorted[0], sorted[1]];

    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, secret.bytes, secret.length, [context UTF8String], [context length], digest);

    uint32_t val = (digest[0] << 24) | (digest[1] << 16) | (digest[2] << 8) | digest[3];
    uint32_t code = (val % 900000) + 100000;

    return [NSString stringWithFormat:@"%03u %03u", code / 1000, code % 1000];
}

#pragma mark - Nonce & Replay Protection

- (uint64_t)nextOutgoingNonce {
    [self.securityLock lock];
    self.currentNonce++;
    uint64_t n = self.currentNonce;
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setInteger:(NSInteger)n forKey:kMNLastOutgoingNonceKey];
    [defaults synchronize];
    [self.securityLock unlock];
    return n;
}

- (BOOL)checkAndCommitIncomingNonce:(uint64_t)nonce timestamp:(NSTimeInterval)timestamp fromPeer:(NSString *)peerId {
    if (!peerId) return NO;
    [self.securityLock lock];
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];

    // 1. Strict 30-second window to prevent replaying captured frames
    if (fabs(now - timestamp) > 30.0) {
        [self.securityLock unlock];
        return NO;
    }

    // 2. Nonce must strictly increase monotonically
    NSNumber *last = self.lastSeenNonces[peerId];
    if (last && nonce <= [last unsignedLongLongValue]) {
        [self.securityLock unlock];
        return NO;
    }

    // 3. Atomically mutate state and persist across restarts
    self.lastSeenNonces[peerId] = @(nonce);
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    [defaults setObject:[self.lastSeenNonces copy] forKey:kMNReplayHistoryKey];
    [defaults synchronize];

    [self.securityLock unlock];
    return YES;
}

- (BOOL)isIncomingNonceValid:(uint64_t)nonce timestamp:(NSTimeInterval)timestamp fromPeer:(NSString *)peerId {
    if (!peerId) return NO;
    [self.securityLock lock];
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];

    if (fabs(now - timestamp) > 30.0) {
        [self.securityLock unlock];
        return NO;
    }

    NSNumber *last = self.lastSeenNonces[peerId];
    if (last && nonce <= [last unsignedLongLongValue]) {
        [self.securityLock unlock];
        return NO;
    }

    [self.securityLock unlock];
    return YES;
}

- (BOOL)commitIncomingNonce:(uint64_t)nonce timestamp:(NSTimeInterval)timestamp fromPeer:(NSString *)peerId {
    return [self checkAndCommitIncomingNonce:nonce timestamp:timestamp fromPeer:peerId];
}

- (BOOL)validateIncomingNonce:(uint64_t)nonce timestamp:(NSTimeInterval)timestamp fromPeer:(NSString *)peerId {
    return [self checkAndCommitIncomingNonce:nonce timestamp:timestamp fromPeer:peerId];
}

#pragma mark - Authenticated Encryption (AES-256 + HMAC-SHA256 Encrypt-then-MAC)

- (nullable NSDictionary *)encryptDictionary:(NSDictionary *)dict
                                   forPeerId:(NSString *)peerId
                                       nonce:(uint64_t)nonce
                                   timestamp:(NSTimeInterval)timestamp {
    NSData *masterSecret = [self trustedPeerSecret:peerId];
    if (!masterSecret) return nil;

    // Derive K_enc and K_mac from masterSecret
    unsigned char k_enc[CC_SHA256_DIGEST_LENGTH];
    unsigned char k_mac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, masterSecret.bytes, masterSecret.length, "macnexa-enc", 11, k_enc);
    CCHmac(kCCHmacAlgSHA256, masterSecret.bytes, masterSecret.length, "macnexa-mac", 11, k_mac);

    // Generate random 16-byte IV
    unsigned char iv[16];
    arc4random_buf(iv, 16);

    NSData *plainData = [NSJSONSerialization dataWithJSONObject:dict options:0 error:nil];
    if (!plainData) return nil;

    NSMutableData *cipherData = [NSMutableData dataWithLength:plainData.length + kCCBlockSizeAES128];
    size_t numBytesEncrypted = 0;
    CCCryptorStatus status = CCCrypt(
        kCCEncrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding,
        k_enc,
        kCCKeySizeAES256,
        iv,
        plainData.bytes,
        plainData.length,
        cipherData.mutableBytes,
        cipherData.length,
        &numBytesEncrypted
    );
    if (status != kCCSuccess) return nil;
    cipherData.length = numBytesEncrypted;

    // Compute HMAC-SHA256 Tag over (IV + Ciphertext + Nonce + Timestamp + SenderID)
    NSMutableData *macInput = [NSMutableData dataWithBytes:iv length:16];
    [macInput appendData:cipherData];
    uint64_t bigNonce = CFSwapInt64HostToBig(nonce);
    [macInput appendBytes:&bigNonce length:sizeof(bigNonce)];
    int64_t bigTs = CFSwapInt64HostToBig((int64_t)timestamp);
    [macInput appendBytes:&bigTs length:sizeof(bigTs)];
    [macInput appendData:[self.localPeerId dataUsingEncoding:NSUTF8StringEncoding]];

    unsigned char tag[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, k_mac, CC_SHA256_DIGEST_LENGTH, macInput.bytes, macInput.length, tag);

    NSData *ivData = [NSData dataWithBytes:iv length:16];
    NSData *tagData = [NSData dataWithBytes:tag length:CC_SHA256_DIGEST_LENGTH];

    return @{
        @"senderId": self.localPeerId,
        @"nonce": @(nonce),
        @"timestamp": @(timestamp),
        @"iv": [ivData base64EncodedStringWithOptions:0],
        @"ciphertext": [cipherData base64EncodedStringWithOptions:0],
        @"tag": [tagData base64EncodedStringWithOptions:0]
    };
}

- (nullable NSDictionary *)decryptAndVerifyDictionary:(NSDictionary *)envelope
                                           fromPeerId:(NSString *)peerId {
    NSData *masterSecret = [self trustedPeerSecret:peerId];
    if (!masterSecret) return nil;

    uint64_t nonce = [envelope[@"nonce"] unsignedLongLongValue];
    NSTimeInterval timestamp = [envelope[@"timestamp"] doubleValue];
    NSString *b64IV = envelope[@"iv"];
    NSString *b64Cipher = envelope[@"ciphertext"];
    NSString *b64Tag = envelope[@"tag"];

    if (!b64IV || !b64Cipher || !b64Tag) return nil;

    NSData *ivData = [[NSData alloc] initWithBase64EncodedString:b64IV options:0];
    NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:b64Cipher options:0];
    NSData *tagData = [[NSData alloc] initWithBase64EncodedString:b64Tag options:0];

    if (ivData.length != 16 || tagData.length != CC_SHA256_DIGEST_LENGTH || cipherData.length == 0) return nil;

    // 1. Authenticate FIRST: Derive subkeys and verify HMAC-SHA256 Tag
    // Any unauthenticated or forged packet is dropped immediately.
    // Zero replay state is read or mutated for unauthenticated packets.
    unsigned char k_enc[CC_SHA256_DIGEST_LENGTH];
    unsigned char k_mac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, masterSecret.bytes, masterSecret.length, "macnexa-enc", 11, k_enc);
    CCHmac(kCCHmacAlgSHA256, masterSecret.bytes, masterSecret.length, "macnexa-mac", 11, k_mac);

    NSMutableData *macInput = [NSMutableData dataWithData:ivData];
    [macInput appendData:cipherData];
    uint64_t bigNonce = CFSwapInt64HostToBig(nonce);
    [macInput appendBytes:&bigNonce length:sizeof(bigNonce)];
    int64_t bigTs = CFSwapInt64HostToBig((int64_t)timestamp);
    [macInput appendBytes:&bigTs length:sizeof(bigTs)];
    [macInput appendData:[peerId dataUsingEncoding:NSUTF8StringEncoding]];

    unsigned char expectedTag[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, k_mac, CC_SHA256_DIGEST_LENGTH, macInput.bytes, macInput.length, expectedTag);

    // Constant-time check prevents timing attacks
    if (timingsafe_bcmp(tagData.bytes, expectedTag, CC_SHA256_DIGEST_LENGTH) != 0) {
        return nil; // Forged or invalid packet! Dropped before checking or mutating replay state.
    }

    // 2. Atomically check and commit replay state ONLY AFTER HMAC authentication succeeds
    // Both freshness (30-second window) and monotonicity (nonce > lastSeen) are checked,
    // and committed in a single locked atomic operation that persists to disk across restarts.
    if (![self checkAndCommitIncomingNonce:nonce timestamp:timestamp fromPeer:peerId]) {
        return nil; // Replay detected or timestamp out of window!
    }

    // 3. Decrypt AES-256 Ciphertext
    NSMutableData *plainData = [NSMutableData dataWithLength:cipherData.length];
    size_t numBytesDecrypted = 0;
    CCCryptorStatus status = CCCrypt(
        kCCDecrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding,
        k_enc,
        kCCKeySizeAES256,
        ivData.bytes,
        cipherData.bytes,
        cipherData.length,
        plainData.mutableBytes,
        plainData.length,
        &numBytesDecrypted
    );
    if (status != kCCSuccess) return nil;
    plainData.length = numBytesDecrypted;

    return [NSJSONSerialization JSONObjectWithData:plainData options:0 error:nil];
}

@end
