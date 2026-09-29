//
//  MNSecurity.m
//  MacNexa
//

#import "MNSecurity.h"
#import <CommonCrypto/CommonHMAC.h>
#import <CommonCrypto/CommonCryptor.h>
#import <string.h>

static NSString * const kMNKeychainService = @"com.macnexa.secrets";
static NSString * const kMNLocalPeerIdKey = @"com.macnexa.local_peer_id";
static NSString * const kMNTrustedMetadataKey = @"com.macnexa.trusted_metadata";

@implementation MNEphemeralKeyPair
- (void)dealloc {
    if (_privateKey) {
        CFRelease(_privateKey);
        _privateKey = NULL;
    }
}
@end

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
    self = [super init];
    if (self) {
        _securityLock = [[NSLock alloc] init];
        _lastSeenNonces = [NSMutableDictionary dictionary];
        _currentNonce = (uint64_t)[[NSDate date] timeIntervalSince1970] * 1000;

        NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
        NSString *existingId = [defaults stringForKey:kMNLocalPeerIdKey];
        if (!existingId) {
            existingId = [[NSUUID UUID] UUIDString];
            [defaults setObject:existingId forKey:kMNLocalPeerIdKey];
            [defaults synchronize];
        }
        _localPeerId = existingId;
        _localPeerName = [[NSHost currentHost] localizedName] ?: @"Mac";
    }
    return self;
}

#pragma mark - Keychain Storage

- (void)saveSecretToKeychain:(NSData *)secret forAccount:(NSString *)account {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kMNKeychainService,
        (__bridge id)kSecAttrAccount: account
    };
    SecItemDelete((__bridge CFDictionaryRef)query);

    NSMutableDictionary *item = [query mutableCopy];
    item[(__bridge id)kSecValueData] = secret;
    item[(__bridge id)kSecAttrAccessible] = (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    SecItemAdd((__bridge CFDictionaryRef)item, NULL);
}

- (nullable NSData *)loadSecretFromKeychainForAccount:(NSString *)account {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kMNKeychainService,
        (__bridge id)kSecAttrAccount: account,
        (__bridge id)kSecReturnData: @YES,
        (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
    };
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecSuccess && result) {
        return (__bridge_transfer NSData *)result;
    }
    return nil;
}

- (void)deleteSecretFromKeychainForAccount:(NSString *)account {
    NSDictionary *query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: kMNKeychainService,
        (__bridge id)kSecAttrAccount: account
    };
    SecItemDelete((__bridge CFDictionaryRef)query);
}

#pragma mark - Trusted Peers Management

- (BOOL)isPeerTrusted:(NSString *)peerId {
    if (!peerId) return NO;
    return [self trustedPeerSecret:peerId] != nil;
}

- (nullable NSDictionary *)trustedPeerInfo:(NSString *)peerId {
    if (!peerId) return nil;
    NSDictionary *meta = [[NSUserDefaults standardUserDefaults] dictionaryForKey:kMNTrustedMetadataKey];
    return meta[peerId];
}

- (nullable NSData *)trustedPeerSecret:(NSString *)peerId {
    if (!peerId) return nil;
    return [self loadSecretFromKeychainForAccount:peerId];
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

- (void)saveTrustedPeerId:(NSString *)peerId name:(NSString *)name secret:(NSData *)secret {
    if (!peerId || !secret) return;
    [self.securityLock lock];
    
    // Save master key to hardware-encrypted Keychain
    [self saveSecretToKeychain:secret forAccount:peerId];

    // Save non-sensitive metadata to NSUserDefaults
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSMutableDictionary *meta = [[defaults dictionaryForKey:kMNTrustedMetadataKey] mutableCopy] ?: [NSMutableDictionary dictionary];
    meta[peerId] = @{
        @"name": name ?: @"Mac",
        @"pairedAt": @([[NSDate date] timeIntervalSince1970])
    };
    [defaults setObject:meta forKey:kMNTrustedMetadataKey];
    [defaults synchronize];

    [self.securityLock unlock];
}

- (void)removeTrustedPeerId:(NSString *)peerId {
    if (!peerId) return;
    [self.securityLock lock];
    [self deleteSecretFromKeychainForAccount:peerId];

    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSMutableDictionary *meta = [[defaults dictionaryForKey:kMNTrustedMetadataKey] mutableCopy];
    if (meta) {
        [meta removeObjectForKey:peerId];
        [defaults setObject:meta forKey:kMNTrustedMetadataKey];
        [defaults synchronize];
    }
    [self.securityLock unlock];
}

#pragma mark - Diffie-Hellman Key Exchange (ECDH P-256)

- (MNEphemeralKeyPair *)generateEphemeralKeyPair {
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
    [self.securityLock unlock];
    return n;
}

- (BOOL)validateIncomingNonce:(uint64_t)nonce timestamp:(NSTimeInterval)timestamp fromPeer:(NSString *)peerId {
    if (!peerId) return NO;
    [self.securityLock lock];
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    
    // Strict 30-second window to prevent replaying captured frames
    if (fabs(now - timestamp) > 30.0) {
        [self.securityLock unlock];
        return NO;
    }
    
    // Nonce must strictly increase monotonically
    NSNumber *last = self.lastSeenNonces[peerId];
    if (last && nonce <= [last unsignedLongLongValue]) {
        [self.securityLock unlock];
        return NO;
    }
    
    self.lastSeenNonces[peerId] = @(nonce);
    [self.securityLock unlock];
    return YES;
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

    // 1. Replay & Timestamp Check
    if (![self validateIncomingNonce:nonce timestamp:timestamp fromPeer:peerId]) {
        return nil;
    }

    // 2. Derive K_enc and K_mac
    unsigned char k_enc[CC_SHA256_DIGEST_LENGTH];
    unsigned char k_mac[CC_SHA256_DIGEST_LENGTH];
    CCHmac(kCCHmacAlgSHA256, masterSecret.bytes, masterSecret.length, "macnexa-enc", 11, k_enc);
    CCHmac(kCCHmacAlgSHA256, masterSecret.bytes, masterSecret.length, "macnexa-mac", 11, k_mac);

    // 3. Constant-Time HMAC-SHA256 Tag Verification
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
        return nil; // Tampering detected!
    }

    // 4. Decrypt AES-256 Ciphertext
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
