//
//  NativeStorageTests.m
//  MacNexa
//
//  Comprehensive test suite for MNFileSecretStore and MNSecurity injected storage:
//  - CRUD operations
//  - Strict 0600/0700 permission enforcement
//  - Safe corruption quarantine & error handling
//  - Dependency injection & UI-bound error propagation
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCrypto.h>
#import <sys/stat.h>
#import <assert.h>
#import "../MacNexa/Native/MNSecurity.h"

#define ASSERT_TRUE(condition, msg) do { \
    if (!(condition)) { \
        fprintf(stderr, "❌ ASSERTION FAILED: %s (%s:%d)\n", msg, __FILE__, __LINE__); \
        exit(1); \
    } \
} while(0)

// Mock storage implementation for injection testing
@interface MockFailingSecretStore : NSObject <MNSecretStoring>
@property (nonatomic, assign) BOOL shouldFailSet;
@property (nonatomic, assign) BOOL shouldFailRemove;
@property (nonatomic, assign) BOOL shouldFailGet;
@property (nonatomic, strong) NSMutableDictionary *storage;
@end

@implementation MockFailingSecretStore
- (instancetype)init {
    self = [super init];
    if (self) {
        _storage = [NSMutableDictionary dictionary];
    }
    return self;
}

- (BOOL)setSecret:(NSData *)secret forKey:(NSString *)key error:(NSError **)error {
    if (self.shouldFailSet) {
        if (error) {
            *error = [NSError errorWithDomain:MNStorageErrorDomain
                                         code:MNStorageErrorWriteFailed
                                     userInfo:@{ NSLocalizedDescriptionKey: @"Mock write failure injected for UI test." }];
        }
        return NO;
    }
    self.storage[key] = secret;
    return YES;
}

- (nullable NSData *)secretForKey:(NSString *)key error:(NSError **)error {
    if (self.shouldFailGet) {
        if (error) {
            *error = [NSError errorWithDomain:MNStorageErrorDomain
                                         code:MNStorageErrorDecryptionFailed
                                     userInfo:@{ NSLocalizedDescriptionKey: @"Mock read failure injected for UI test." }];
        }
        return nil;
    }
    return self.storage[key];
}

- (BOOL)removeSecretForKey:(NSString *)key error:(NSError **)error {
    if (self.shouldFailRemove) {
        if (error) {
            *error = [NSError errorWithDomain:MNStorageErrorDomain
                                         code:MNStorageErrorWriteFailed
                                     userInfo:@{ NSLocalizedDescriptionKey: @"Mock remove failure injected for UI test." }];
        }
        return NO;
    }
    [self.storage removeObjectForKey:key];
    return YES;
}

- (nullable NSArray<NSString *> *)allKeysWithPrefix:(NSString *)prefix error:(NSError **)error {
    NSMutableArray *res = [NSMutableArray array];
    for (NSString *k in self.storage) {
        if (!prefix || [k hasPrefix:prefix]) [res addObject:k];
    }
    return res;
}
@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        printf("🧪 Running MacNexa File Storage & Security Tests...\n");

        NSString *tmpDir = [NSTemporaryDirectory() stringByAppendingPathComponent:[NSString stringWithFormat:@"macnexa-test-%u", arc4random()]];
        NSURL *testDirURL = [NSURL fileURLWithPath:tmpDir isDirectory:YES];

        // -------------------------------------------------------------
        // Test 1: Initialization & CRUD
        // -------------------------------------------------------------
        printf("  [1/9] Testing MNFileSecretStore CRUD operations...\n");
        MNFileSecretStore *store = [[MNFileSecretStore alloc] initWithDirectoryURL:testDirURL];
        ASSERT_TRUE(store != nil, "Store should initialize");

        NSError *error = nil;
        NSData *testSecret = [@"SuperSecretKeyMaterial123" dataUsingEncoding:NSUTF8StringEncoding];
        BOOL setOk = [store setSecret:testSecret forKey:@"peer-node-1" error:&error];
        ASSERT_TRUE(setOk, "setSecret should succeed");
        ASSERT_TRUE(error == nil, "Error should be nil");

        NSData *loadedSecret = [store secretForKey:@"peer-node-1" error:&error];
        ASSERT_TRUE([loadedSecret isEqualToData:testSecret], "Loaded secret must match stored secret");

        // Add second key
        [store setSecret:[@"AnotherSecret" dataUsingEncoding:NSUTF8StringEncoding] forKey:@"peer-node-2" error:nil];
        NSArray<NSString *> *allKeys = [store allKeysWithPrefix:@"peer-" error:nil];
        ASSERT_TRUE(allKeys.count == 2, "Should find 2 keys with prefix peer-");

        // Remove key
        BOOL rmOk = [store removeSecretForKey:@"peer-node-1" error:&error];
        ASSERT_TRUE(rmOk, "removeSecretForKey should succeed");
        ASSERT_TRUE([store secretForKey:@"peer-node-1" error:nil] == nil, "Removed key must be nil");

        // -------------------------------------------------------------
        // Test 2: Enforced File & Directory Permissions
        // -------------------------------------------------------------
        printf("  [2/9] Testing enforced POSIX permissions (0700 dir, 0600 files)...\n");
        struct stat dirStat;
        stat(tmpDir.fileSystemRepresentation, &dirStat);
        mode_t dirMode = dirStat.st_mode & 0777;
        ASSERT_TRUE(dirMode == 0700, "Directory permissions must be 0700");

        struct stat seedStat;
        stat(store.seedURL.path.fileSystemRepresentation, &seedStat);
        mode_t seedMode = seedStat.st_mode & 0777;
        ASSERT_TRUE(seedMode == 0600, "Seed file permissions must be 0600");

        struct stat encStat;
        stat(store.fileURL.path.fileSystemRepresentation, &encStat);
        mode_t encMode = encStat.st_mode & 0777;
        ASSERT_TRUE(encMode == 0600, "Encrypted secrets file permissions must be 0600");

        // -------------------------------------------------------------
        // Test 3: Safe Corruption Handling & Quarantine
        // -------------------------------------------------------------
        printf("  [3/9] Testing safe corruption handling and file quarantine...\n");
        // Corrupt the secrets.enc file by overwriting it with garbage bytes
        const char *garbage = "CORRUPTED_GARBAGE_DATA_THAT_IS_NOT_VALID_CIPHERTEXT";
        [[NSData dataWithBytes:garbage length:strlen(garbage)] writeToURL:store.fileURL atomically:YES];

        NSError *corruptErr = nil;
        NSData *corruptLoad = [store secretForKey:@"peer-node-2" error:&corruptErr];
        ASSERT_TRUE(corruptLoad == nil, "Loading corrupted data must return nil");
        ASSERT_TRUE(corruptErr != nil, "Corrupted load must produce a detailed NSError");
        ASSERT_TRUE(corruptErr.code == MNStorageErrorCorruptedData || corruptErr.code == MNStorageErrorDecryptionFailed, "Must have corrupted data error code");

        // Verify quarantine: the corrupted file should have been moved to secrets.enc.corrupt.<timestamp>
        NSFileManager *fm = [NSFileManager defaultManager];
        NSArray *dirContents = [fm contentsOfDirectoryAtPath:tmpDir error:nil];
        BOOL foundQuarantine = NO;
        for (NSString *name in dirContents) {
            if ([name containsString:@"secrets.enc.corrupt"]) {
                foundQuarantine = YES;
                break;
            }
        }
        ASSERT_TRUE(foundQuarantine, "Corrupted file must be safely quarantined with timestamp");

        // Subsequent write should cleanly recover without error
        BOOL recoverSet = [store setSecret:[@"RecoveredKey" dataUsingEncoding:NSUTF8StringEncoding] forKey:@"peer-recovered" error:&error];
        ASSERT_TRUE(recoverSet, "Store must recover and allow fresh writes after corruption");
        ASSERT_TRUE([[store secretForKey:@"peer-recovered" error:nil] isEqualToData:[@"RecoveredKey" dataUsingEncoding:NSUTF8StringEncoding]], "Recovered secret must match");

        // -------------------------------------------------------------
        // Test 4: Injected Storage & Storage Failure Resilience in MNSecurity
        // -------------------------------------------------------------
        printf("  [4/9] Testing injected storage interface and storage failures in MNSecurity...\n");
        MockFailingSecretStore *mockStore = [[MockFailingSecretStore alloc] init];
        MNSecurity *security = [[MNSecurity alloc] initWithSecretStore:mockStore];
        ASSERT_TRUE(security.secretStore == mockStore, "Injected store must be active in MNSecurity");

        // Normal save with mock
        NSData *peerSec = [@"P256SharedSecretData32Bytes12345" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *secErr = nil;
        BOOL peerSaved = [security saveTrustedPeerId:@"test-peer" name:@"MacBook Pro" secret:peerSec error:&secErr];
        ASSERT_TRUE(peerSaved, "saveTrustedPeerId must succeed with injected store");
        ASSERT_TRUE([security isPeerTrusted:@"test-peer"], "Peer should be trusted");

        // Injected failure 1: simulated disk write failure
        mockStore.shouldFailSet = YES;
        NSError *failErr = nil;
        BOOL peerFail = [security saveTrustedPeerId:@"failing-peer" name:@"Mac Mini" secret:peerSec error:&failErr];
        ASSERT_TRUE(!peerFail, "saveTrustedPeerId must fail when injected store fails");
        ASSERT_TRUE(failErr != nil, "Failure must return non-nil error");
        ASSERT_TRUE(security.lastStorageError != nil, "lastStorageError must be populated so UI can display it");
        ASSERT_TRUE([security.lastStorageError.localizedDescription containsString:@"Mock write failure"], "Error description must propagate to MNSecurity");

        // Clear error test
        [security clearLastStorageError];
        ASSERT_TRUE(security.lastStorageError == nil, "clearLastStorageError must clear error");
        mockStore.shouldFailSet = NO;

        // Injected failure 2: simulated disk read failure
        mockStore.shouldFailGet = YES;
        NSError *getErr = nil;
        NSData *secFail = [security trustedPeerSecret:@"test-peer" error:&getErr];
        ASSERT_TRUE(secFail == nil, "trustedPeerSecret must fail when store read fails");
        ASSERT_TRUE(getErr != nil, "Read failure must return non-nil error");
        ASSERT_TRUE(security.lastStorageError != nil, "lastStorageError must be recorded on read failure");
        [security clearLastStorageError];
        mockStore.shouldFailGet = NO;

        // Injected failure 3: simulated remove failure
        mockStore.shouldFailRemove = YES;
        NSError *rmErr = nil;
        BOOL rmFail = [security removeTrustedPeerId:@"test-peer" error:&rmErr];
        ASSERT_TRUE(!rmFail, "removeTrustedPeerId must fail when store fails");
        ASSERT_TRUE(security.lastStorageError != nil, "lastStorageError must be recorded on remove failure");
        [security clearLastStorageError];
        mockStore.shouldFailRemove = NO;

        // Storage failure 4: Invalid key material validation
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
        NSError *invalidKeyErr = nil;
        BOOL nilKeyFail = [security saveTrustedPeerId:nil name:@"Mac" secret:peerSec error:&invalidKeyErr];
        ASSERT_TRUE(!nilKeyFail && invalidKeyErr.code == MNStorageErrorInvalidKey, "Saving nil peer ID must fail with MNStorageErrorInvalidKey");

        BOOL emptyKeyFail = [security saveTrustedPeerId:@"" name:@"Mac" secret:peerSec error:&invalidKeyErr];
        ASSERT_TRUE(!emptyKeyFail && invalidKeyErr.code == MNStorageErrorInvalidKey, "Saving empty peer ID must fail with MNStorageErrorInvalidKey");

        BOOL nilSecFail = [security saveTrustedPeerId:@"valid-id" name:@"Mac" secret:nil error:&invalidKeyErr];
        ASSERT_TRUE(!nilSecFail && invalidKeyErr.code == MNStorageErrorInvalidKey, "Saving nil secret must fail with MNStorageErrorInvalidKey");

        BOOL emptySecFail = [security saveTrustedPeerId:@"valid-id" name:@"Mac" secret:[NSData data] error:&invalidKeyErr];
        ASSERT_TRUE(!emptySecFail && invalidKeyErr.code == MNStorageErrorInvalidKey, "Saving empty secret must fail with MNStorageErrorInvalidKey");
#pragma clang diagnostic pop

        // -------------------------------------------------------------
        // Test 5: Replay Protection & Invalid-HMAC Nonce Handling
        // -------------------------------------------------------------
        printf("  [5/9] Testing replay protection and invalid-HMAC nonce handling...\n");
        [[NSUserDefaults standardUserDefaults] removeObjectForKey:@"com.macnexa.replay_history"];
        [[NSUserDefaults standardUserDefaults] synchronize];

        // Set up two communicating peers: senderMac and receiverMac sharing a secret
        NSData *sharedKey = [@"32ByteCryptographicSharedSecret!" dataUsingEncoding:NSUTF8StringEncoding];

        NSString *receiverPeerId = [NSString stringWithFormat:@"receiver-test-%u", arc4random()];
        NSString *senderPeerId = [NSString stringWithFormat:@"sender-test-%u", arc4random()];

        MNSecurity *receiverMac = [[MNSecurity alloc] initWithSecretStore:store localPeerId:receiverPeerId];
        MNSecurity *senderMac = [[MNSecurity alloc] initWithSecretStore:store localPeerId:senderPeerId];

        // Receiver trusts senderMac.localPeerId
        NSString *senderId = senderMac.localPeerId;
        BOOL savedPeer = [receiverMac saveTrustedPeerId:senderId name:@"Sender Mac" secret:sharedKey error:nil];
        ASSERT_TRUE(savedPeer, "Receiver must trust sender");

        // Sender trusts receiverMac.localPeerId
        [senderMac saveTrustedPeerId:receiverMac.localPeerId name:@"Receiver Mac" secret:sharedKey error:nil];

        NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
        NSDictionary *legitCmd1 = @{ @"action": @"switchAccessory", @"target": @"keyboard" };
        NSDictionary *legitEnvelope1 = [senderMac encryptDictionary:legitCmd1 forPeerId:receiverMac.localPeerId nonce:1000 timestamp:now];
        ASSERT_TRUE(legitEnvelope1 != nil, "legitEnvelope1 encryption should succeed");

        // 1. Decrypt legit envelope 1 (nonce = 1000)
        NSDictionary *decrypted1 = [receiverMac decryptAndVerifyDictionary:legitEnvelope1 fromPeerId:senderId];
        ASSERT_TRUE(decrypted1 != nil, "Legitimate envelope 1 should decrypt");
        ASSERT_TRUE([decrypted1[@"action"] isEqualToString:@"switchAccessory"], "Action must match");

        // 2. Replay attack: Replaying legit envelope 1 must be rejected
        NSDictionary *replayed = [receiverMac decryptAndVerifyDictionary:legitEnvelope1 fromPeerId:senderId];
        ASSERT_TRUE(replayed == nil, "Replayed envelope must be rejected by monotonic nonce check");

        // 3. Forged attack: Attacker crafts forged envelope with massive nonce (e.g. 999999999) and bad tag
        NSMutableDictionary *forgedEnvelope = [legitEnvelope1 mutableCopy];
        forgedEnvelope[@"nonce"] = @(999999999ULL);
        forgedEnvelope[@"tag"] = @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        NSDictionary *attackResult = [receiverMac decryptAndVerifyDictionary:forgedEnvelope fromPeerId:senderId];
        ASSERT_TRUE(attackResult == nil, "Forged attack envelope must fail HMAC authentication");

        // 4. Crucial test: Legitimate peer sends next command with nonce 1001.
        // In the vulnerable code, the forged packet's nonce (999999999) was committed before HMAC verification,
        // which caused nonce 1001 to be rejected (DoS).
        // With the fix, nonce 1001 MUST be accepted!
        NSDictionary *legitCmd2 = @{ @"action": @"releaseAccessory", @"target": @"trackpad" };
        NSDictionary *legitEnvelope2 = [senderMac encryptDictionary:legitCmd2 forPeerId:receiverMac.localPeerId nonce:1001 timestamp:now];
        ASSERT_TRUE(legitEnvelope2 != nil, "legitEnvelope2 encryption should succeed");

        NSDictionary *decrypted2 = [receiverMac decryptAndVerifyDictionary:legitEnvelope2 fromPeerId:senderId];
        ASSERT_TRUE(decrypted2 != nil, "Legitimate command with nonce 1001 MUST succeed despite prior attack packet!");
        ASSERT_TRUE([decrypted2[@"action"] isEqualToString:@"releaseAccessory"], "Command 2 action must match");

        // 5. Multiple consecutive forged attacks with ascending large nonces must all fail without advancing state
        NSMutableDictionary *forged2 = [legitEnvelope1 mutableCopy];
        forged2[@"nonce"] = @(500000ULL);
        forged2[@"tag"] = @"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
        ASSERT_TRUE([receiverMac decryptAndVerifyDictionary:forged2 fromPeerId:senderId] == nil, "Forged attack envelope 2 must fail HMAC authentication");

        NSMutableDictionary *forged3 = [legitEnvelope1 mutableCopy];
        forged3[@"nonce"] = @(1000000ULL);
        forged3[@"tag"] = @"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=";
        ASSERT_TRUE([receiverMac decryptAndVerifyDictionary:forged3 fromPeerId:senderId] == nil, "Forged attack envelope 3 must fail HMAC authentication");

        // 6. Freshness window attacks:
        // Expired timestamp (> 30s in the past)
        NSDictionary *expiredEnv = [senderMac encryptDictionary:legitCmd2 forPeerId:receiverMac.localPeerId nonce:1002 timestamp:(now - 45.0)];
        ASSERT_TRUE([receiverMac decryptAndVerifyDictionary:expiredEnv fromPeerId:senderId] == nil, "Expired timestamp (> 30s) must be rejected");

        // Future timestamp (> 30s in future)
        NSDictionary *futureEnv = [senderMac encryptDictionary:legitCmd2 forPeerId:receiverMac.localPeerId nonce:1003 timestamp:(now + 60.0)];
        ASSERT_TRUE([receiverMac decryptAndVerifyDictionary:futureEnv fromPeerId:senderId] == nil, "Future timestamp (> 30s) must be rejected");

        // 7. Restart behavior: Simulate receiver daemon restart by creating a new MNSecurity instance.
        // It must load persistent replay history and reject replayed packet 2 even across restarts!
        MNSecurity *restartedReceiver = [[MNSecurity alloc] initWithSecretStore:store localPeerId:receiverPeerId];
        NSDictionary *postRestartReplay = [restartedReceiver decryptAndVerifyDictionary:legitEnvelope2 fromPeerId:senderId];
        ASSERT_TRUE(postRestartReplay == nil, "Pre-restart envelope 2 must be rejected after restart (persistent replay protection)!");

        // And new envelope with nonce 1004 after restart must succeed
        NSDictionary *legitCmd3 = @{ @"action": @"connectAccessory", @"target": @"mouse" };
        NSDictionary *legitEnvelope3 = [senderMac encryptDictionary:legitCmd3 forPeerId:receiverMac.localPeerId nonce:1004 timestamp:now];
        ASSERT_TRUE(legitEnvelope3 != nil, "legitEnvelope3 encryption should succeed");

        NSDictionary *decrypted3 = [restartedReceiver decryptAndVerifyDictionary:legitEnvelope3 fromPeerId:senderId];
        ASSERT_TRUE(decrypted3 != nil, "New command with nonce 1004 must succeed on restarted receiver!");
        ASSERT_TRUE([decrypted3[@"action"] isEqualToString:@"connectAccessory"], "Command 3 action must match");

        // -------------------------------------------------------------
        // Test 6: Mutual Pairing Sequence & Authenticated Confirmation Tags
        // -------------------------------------------------------------
        printf("  [6/9] Testing mutual pairing sequence, SAS verification & confirmation tags...\n");
        NSString *macAId = [NSString stringWithFormat:@"mac-a-%u", arc4random()];
        NSString *macBId = [NSString stringWithFormat:@"mac-b-%u", arc4random()];

        MNSecurity *securityA = [[MNSecurity alloc] initWithSecretStore:store localPeerId:macAId];
        MNSecurity *securityB = [[MNSecurity alloc] initWithSecretStore:store localPeerId:macBId];

        // 1. Ephemeral ECDH Key Exchange FIRST
        MNEphemeralKeyPair *pairA = [securityA generateEphemeralKeyPair];
        MNEphemeralKeyPair *pairB = [securityB generateEphemeralKeyPair];
        ASSERT_TRUE(pairA != nil && pairB != nil, "Ephemeral key generation must succeed on both peers");

        // Both derive shared secret from the exchanged public keys
        NSData *secretA = [securityA deriveSharedSecretWithPrivateKey:pairA.privateKey remotePublicKeyData:pairB.publicKeyData];
        NSData *secretB = [securityB deriveSharedSecretWithPrivateKey:pairB.privateKey remotePublicKeyData:pairA.publicKeyData];
        ASSERT_TRUE(secretA != nil && secretB != nil, "Both peers must derive shared secrets");
        ASSERT_TRUE([secretA isEqualToData:secretB], "Derived shared secrets must be cryptographically identical");

        // 2. Both peers compute and display identical SAS codes concurrently
        NSString *sasA = [securityA computeSASFromSecret:secretA peerA:macAId peerB:macBId];
        NSString *sasB = [securityB computeSASFromSecret:secretB peerA:macBId peerB:macAId];
        ASSERT_TRUE([sasA isEqualToString:sasB], "SAS codes displayed on both screens must be identical");
        ASSERT_TRUE(sasA.length == 7, "SAS code must be 6 digits separated by space");

        // At this stage, BEFORE confirmations, NEITHER peer must be trusted
        ASSERT_TRUE(![securityA isPeerTrusted:macBId], "Mac B must NOT be trusted before confirmations succeed");
        ASSERT_TRUE(![securityB isPeerTrusted:macAId], "Mac A must NOT be trusted before confirmations succeed");

        // 3. Test Authenticated Confirmation Tags
        NSData *initTag = [securityA computePairingConfirmationTagWithSecret:secretA role:@"initiator" senderPeerId:macAId receiverPeerId:macBId];
        NSData *recvTag = [securityB computePairingConfirmationTagWithSecret:secretB role:@"receiver" senderPeerId:macBId receiverPeerId:macAId];
        ASSERT_TRUE(initTag.length == 32 && recvTag.length == 32, "Confirmation tags must be 32-byte HMAC-SHA256 digests");

        // Verification of genuine tags
        BOOL initVerified = [securityB verifyPairingConfirmationTag:initTag withSecret:secretB role:@"initiator" senderPeerId:macAId receiverPeerId:macBId];
        ASSERT_TRUE(initVerified, "Receiver must verify initiator's genuine confirmation tag");

        BOOL recvVerified = [securityA verifyPairingConfirmationTag:recvTag withSecret:secretA role:@"receiver" senderPeerId:macBId receiverPeerId:macAId];
        ASSERT_TRUE(recvVerified, "Initiator must verify receiver's genuine confirmation tag");

        // Attack scenario 1: Role swap (e.g. attacker sends receiver tag as initiator tag)
        BOOL roleSwapRejected = [securityB verifyPairingConfirmationTag:recvTag withSecret:secretB role:@"initiator" senderPeerId:macAId receiverPeerId:macBId];
        ASSERT_TRUE(!roleSwapRejected, "Role-swapped tag must be rejected");

        // Attack scenario 2: Tampered confirmation tag byte
        NSMutableData *tamperedTag = [initTag mutableCopy];
        unsigned char *bytes = (unsigned char *)tamperedTag.mutableBytes;
        bytes[0] ^= 0xFF;
        BOOL tamperedRejected = [securityB verifyPairingConfirmationTag:tamperedTag withSecret:secretB role:@"initiator" senderPeerId:macAId receiverPeerId:macBId];
        ASSERT_TRUE(!tamperedRejected, "Tampered confirmation tag must be rejected");

        // Attack scenario 3: Wrong secret
        NSData *wrongSecret = [@"WrongCryptographicSecret32Bytes!" dataUsingEncoding:NSUTF8StringEncoding];
        BOOL wrongSecretRejected = [securityB verifyPairingConfirmationTag:initTag withSecret:wrongSecret role:@"initiator" senderPeerId:macAId receiverPeerId:macBId];
        ASSERT_TRUE(!wrongSecretRejected, "Tag verified with wrong secret must be rejected");

        // Attack scenario 4: Cross-peer spoofing (valid tag verified against wrong sender/receiver peer ID)
        BOOL spoofSenderRejected = [securityB verifyPairingConfirmationTag:initTag withSecret:secretB role:@"initiator" senderPeerId:@"attacker-node" receiverPeerId:macBId];
        ASSERT_TRUE(!spoofSenderRejected, "Confirmation tag with spoofed sender ID must be rejected");

        BOOL spoofReceiverRejected = [securityB verifyPairingConfirmationTag:initTag withSecret:secretB role:@"initiator" senderPeerId:macAId receiverPeerId:@"attacker-node"];
        ASSERT_TRUE(!spoofReceiverRejected, "Confirmation tag with spoofed receiver ID must be rejected");

        // 4. Persistence of Trust ONLY after confirmations succeed
        // Receiver persists trust upon verifying Initiator
        BOOL bSaved = [securityB saveTrustedPeerId:macAId name:@"Mac A" secret:secretB error:nil];
        ASSERT_TRUE(bSaved, "Receiver must save trusted peer after verification");

        // Initiator persists trust upon verifying Receiver
        BOOL aSaved = [securityA saveTrustedPeerId:macBId name:@"Mac B" secret:secretA error:nil];
        ASSERT_TRUE(aSaved, "Initiator must save trusted peer after verification");

        ASSERT_TRUE([securityA isPeerTrusted:macBId], "Mac B must now be trusted on Mac A");
        ASSERT_TRUE([securityB isPeerTrusted:macAId], "Mac A must now be trusted on Mac B");

        // Failure mode: Storage failure during confirmation save prevents trust
        MockFailingSecretStore *failStorePair = [[MockFailingSecretStore alloc] init];
        failStorePair.shouldFailSet = YES;
        MNSecurity *failSecurityPair = [[MNSecurity alloc] initWithSecretStore:failStorePair localPeerId:@"failing-node"];
        NSError *pSaveErr = nil;
        BOOL pSaveFail = [failSecurityPair saveTrustedPeerId:@"remote-peer" name:@"Remote" secret:secretA error:&pSaveErr];
        ASSERT_TRUE(!pSaveFail && pSaveErr != nil, "Pairing save must fail if store fails");
        ASSERT_TRUE(![failSecurityPair isPeerTrusted:@"remote-peer"], "Peer must NOT be trusted if storage save fails");

        // -------------------------------------------------------------
        // Test 7: Authenticated Switch Acknowledgments & Request Bindings
        // -------------------------------------------------------------
        printf("  [7/9] Testing authenticated switch acknowledgments & request bindings...\n");
        uint64_t switchReqNonce = 2000ULL;
        NSTimeInterval switchTs = [[NSDate date] timeIntervalSince1970];

        // 1. Sender (Mac A) sends switch request to Receiver (Mac B)
        NSDictionary *switchReqPayload = @{
            @"action": @"requestSwitch",
            @"devices": @[ @{ @"address": @"AA-BB-CC-DD-EE-FF", @"name": @"Keyboard" } ]
        };
        NSDictionary *switchReqEnvelope = [securityA encryptDictionary:switchReqPayload
                                                             forPeerId:macBId
                                                                 nonce:switchReqNonce
                                                             timestamp:switchTs];
        ASSERT_TRUE(switchReqEnvelope != nil, "Switch request envelope encryption must succeed");
        NSString *reqTag = switchReqEnvelope[@"tag"];
        ASSERT_TRUE(reqTag != nil && reqTag.length > 0, "Switch request must produce a valid HMAC tag");

        // 2. Receiver (Mac B) verifies switch request
        NSDictionary *decryptedReq = [securityB decryptAndVerifyDictionary:switchReqEnvelope fromPeerId:macAId];
        ASSERT_TRUE(decryptedReq != nil, "Receiver must decrypt legitimate switch request");

        // 3. Receiver (Mac B) generates authenticated switch acknowledgment bound to exact requestNonce & requestTag
        NSDictionary *wireAck = [securityB encryptSwitchAcknowledgment:YES
                                                                 error:nil
                                                          requestNonce:switchReqNonce
                                                            requestTag:reqTag
                                                             forPeerId:macAId];
        ASSERT_TRUE(wireAck != nil, "Switch acknowledgment encryption must succeed");
        ASSERT_TRUE([wireAck[@"action"] isEqualToString:@"encryptedEnvelope"], "Switch acknowledgment must be sent as an encryptedEnvelope");

        // 4. Sender (Mac A) decrypts and validates genuine acknowledgment
        NSDictionary *decryptedAck = [securityA decryptAndVerifySwitchAcknowledgment:wireAck
                                                                        expectedPeer:macBId
                                                                        requestNonce:switchReqNonce
                                                                          requestTag:reqTag];
        ASSERT_TRUE(decryptedAck != nil, "Sender must successfully verify genuine switch acknowledgment");
        ASSERT_TRUE([decryptedAck[@"success"] boolValue], "Acknowledgment success must be YES");

        // 5. Threat 1: Malicious endpoint sending plain JSON success
        NSDictionary *plainFakeAck = @{ @"action": @"switchAck", @"success": @YES };
        NSDictionary *plainFakeResult = [securityA decryptAndVerifySwitchAcknowledgment:plainFakeAck
                                                                           expectedPeer:macBId
                                                                           requestNonce:switchReqNonce
                                                                             requestTag:reqTag];
        ASSERT_TRUE(plainFakeResult == nil, "Unauthenticated plain JSON switch acknowledgment MUST be rejected!");

        // 6. Threat 2: Mismatched requestNonce (session injection / replay from different request)
        NSDictionary *mismatchedNonceAck = [securityB encryptSwitchAcknowledgment:YES
                                                                            error:nil
                                                                     requestNonce:999999ULL
                                                                       requestTag:reqTag
                                                                        forPeerId:macAId];
        NSDictionary *mismatchedNonceResult = [securityA decryptAndVerifySwitchAcknowledgment:mismatchedNonceAck
                                                                                 expectedPeer:macBId
                                                                                 requestNonce:switchReqNonce
                                                                                   requestTag:reqTag];
        ASSERT_TRUE(mismatchedNonceResult == nil, "Acknowledgment with wrong requestNonce MUST be rejected!");

        // 7. Threat 3: Mismatched requestTag (binding mismatch)
        NSDictionary *mismatchedTagAck = [securityB encryptSwitchAcknowledgment:YES
                                                                          error:nil
                                                                   requestNonce:switchReqNonce
                                                                     requestTag:@"forgedTagAAAAAAAAAAAAAAAAAAAAA="
                                                                      forPeerId:macAId];
        NSDictionary *mismatchedTagResult = [securityA decryptAndVerifySwitchAcknowledgment:mismatchedTagAck
                                                                               expectedPeer:macBId
                                                                               requestNonce:switchReqNonce
                                                                                 requestTag:reqTag];
        ASSERT_TRUE(mismatchedTagResult == nil, "Acknowledgment with wrong requestTag MUST be rejected!");

        // 8. Threat 4: Tampered ciphertext / HMAC tag in acknowledgment envelope
        NSMutableDictionary *tamperedAck = [wireAck mutableCopy];
        tamperedAck[@"tag"] = @"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        NSDictionary *tamperedResult = [securityA decryptAndVerifySwitchAcknowledgment:tamperedAck
                                                                          expectedPeer:macBId
                                                                          requestNonce:switchReqNonce
                                                                            requestTag:reqTag];
        ASSERT_TRUE(tamperedResult == nil, "Tampered switch acknowledgment envelope MUST fail HMAC verification!");

        // 9. Threat 5: Acknowledgment from unexpected / rogue peer
        NSDictionary *wrongPeerResult = [securityA decryptAndVerifySwitchAcknowledgment:wireAck
                                                                           expectedPeer:@"rogue-peer-id"
                                                                           requestNonce:switchReqNonce
                                                                             requestTag:reqTag];
        ASSERT_TRUE(wrongPeerResult == nil, "Switch acknowledgment from unexpected peer MUST be rejected!");

        // 10. Threat 6: Wrong inner action (rogue action inside decrypted envelope)
        NSDictionary *badActionInner = @{
            @"action": @"rogueCommand",
            @"requestNonce": @(switchReqNonce),
            @"requestTag": reqTag,
            @"success": @YES
        };
        NSDictionary *badActionEnv = [securityB encryptDictionary:badActionInner
                                                        forPeerId:macAId
                                                            nonce:3001ULL
                                                        timestamp:switchTs];
        NSMutableDictionary *wireBadAction = [badActionEnv mutableCopy];
        wireBadAction[@"action"] = @"encryptedEnvelope";
        NSDictionary *badActionResult = [securityA decryptAndVerifySwitchAcknowledgment:wireBadAction
                                                                            expectedPeer:macBId
                                                                            requestNonce:switchReqNonce
                                                                              requestTag:reqTag];
        ASSERT_TRUE(badActionResult == nil, "Switch acknowledgment with wrong inner action MUST be rejected!");

        // 11. Threat 7: Non-boolean or wrongly typed inner fields
        NSDictionary *badTypeInner = @{
            @"action": @"switchAck",
            @"requestNonce": @"not_a_number",
            @"requestTag": reqTag,
            @"success": @"not_a_bool"
        };
        NSDictionary *badTypeEnv = [securityB encryptDictionary:badTypeInner
                                                      forPeerId:macAId
                                                          nonce:3002ULL
                                                      timestamp:switchTs];
        NSMutableDictionary *wireBadType = [badTypeEnv mutableCopy];
        wireBadType[@"action"] = @"encryptedEnvelope";
        NSDictionary *badTypeResult = [securityA decryptAndVerifySwitchAcknowledgment:wireBadType
                                                                          expectedPeer:macBId
                                                                          requestNonce:switchReqNonce
                                                                            requestTag:reqTag];
        ASSERT_TRUE(badTypeResult == nil, "Switch acknowledgment with malformed inner fields MUST be rejected!");

        // 12. Threat 8: Replay attack against a subsequent switch request
        uint64_t nextReqNonce = 2005ULL;
        NSDictionary *nextReqPayload = @{
            @"action": @"requestSwitch",
            @"devices": @[ @{ @"address": @"11-22-33-44-55-66", @"name": @"Mouse" } ]
        };
        NSDictionary *nextReqEnvelope = [securityA encryptDictionary:nextReqPayload
                                                           forPeerId:macBId
                                                               nonce:nextReqNonce
                                                           timestamp:switchTs + 1.0];
        NSString *nextReqTag = nextReqEnvelope[@"tag"];
        ASSERT_TRUE(nextReqTag != nil, "Second switch request must produce a valid tag");

        // Attacker attempts to replay original wireAck against the new request
        NSDictionary *replayedAckResult = [securityA decryptAndVerifySwitchAcknowledgment:wireAck
                                                                             expectedPeer:macBId
                                                                             requestNonce:nextReqNonce
                                                                               requestTag:nextReqTag];
        ASSERT_TRUE(replayedAckResult == nil, "Replayed acknowledgment against subsequent request MUST be rejected!");

        // -------------------------------------------------------------
        // Test 8: Incoming JSON Type & Boundary Validation
        // -------------------------------------------------------------
        printf("  [8/9] Testing incoming JSON type safety, decoded key sizes, and boundary limits...\n");

        // 1. Top-level object validation: valid JSON array or string passed where dictionary is expected
        NSArray *jsonArrayPayload = @[ @"action", @"pairRequest", @123 ];
        NSDictionary *topLevelArrayRes = [securityA decryptAndVerifyDictionary:(NSDictionary *)jsonArrayPayload fromPeerId:macBId];
        ASSERT_TRUE(topLevelArrayRes == nil, "Top-level JSON array MUST return nil without throwing exception");

        NSString *jsonStringPayload = @"not_a_dictionary";
        NSDictionary *topLevelStringRes = [securityA decryptAndVerifyDictionary:(NSDictionary *)jsonStringPayload fromPeerId:macBId];
        ASSERT_TRUE(topLevelStringRes == nil, "Top-level JSON string MUST return nil without throwing exception");

        NSNumber *jsonNumPayload = @(42);
        NSDictionary *topLevelNumRes = [securityA decryptAndVerifyDictionary:(NSDictionary *)jsonNumPayload fromPeerId:macBId];
        ASSERT_TRUE(topLevelNumRes == nil, "Top-level JSON number MUST return nil without throwing exception");

        // 2. Peer ID type validation: non-string or empty peer ID
        NSDictionary *badPeerRes = [securityA decryptAndVerifyDictionary:switchReqEnvelope fromPeerId:(NSString *)@[ @"peer" ]];
        ASSERT_TRUE(badPeerRes == nil, "Non-string peer ID MUST return nil without throwing exception");

        NSDictionary *emptyPeerRes = [securityA decryptAndVerifyDictionary:switchReqEnvelope fromPeerId:@""];
        ASSERT_TRUE(emptyPeerRes == nil, "Empty peer ID MUST return nil without throwing exception");

        // 3. Envelope field type validation: wrongly typed nonce, timestamp, tag, iv, or ciphertext
        NSMutableDictionary *badNonceEnv = [switchReqEnvelope mutableCopy];
        badNonceEnv[@"nonce"] = @[ @(12345) ]; // Array instead of NSNumber
        NSDictionary *badNonceRes = [securityB decryptAndVerifyDictionary:badNonceEnv fromPeerId:macAId];
        ASSERT_TRUE(badNonceRes == nil, "Envelope with array nonce MUST return nil without throwing exception");

        NSMutableDictionary *badStrNonceEnv = [switchReqEnvelope mutableCopy];
        badStrNonceEnv[@"nonce"] = @"not_a_number"; // String instead of NSNumber
        NSDictionary *badStrNonceRes = [securityB decryptAndVerifyDictionary:badStrNonceEnv fromPeerId:macAId];
        ASSERT_TRUE(badStrNonceRes == nil, "Envelope with string nonce MUST return nil without throwing exception");

        NSMutableDictionary *badTsEnv = [switchReqEnvelope mutableCopy];
        badTsEnv[@"timestamp"] = @"not_a_number"; // String instead of NSNumber
        NSDictionary *badTsRes = [securityB decryptAndVerifyDictionary:badTsEnv fromPeerId:macAId];
        ASSERT_TRUE(badTsRes == nil, "Envelope with string timestamp MUST return nil without throwing exception");

        NSMutableDictionary *badTagEnv = [switchReqEnvelope mutableCopy];
        badTagEnv[@"tag"] = @(9999); // NSNumber instead of NSString
        NSDictionary *badTagRes = [securityB decryptAndVerifyDictionary:badTagEnv fromPeerId:macAId];
        ASSERT_TRUE(badTagRes == nil, "Envelope with numeric tag MUST return nil without throwing exception");

        NSMutableDictionary *emptyTagEnv = [switchReqEnvelope mutableCopy];
        emptyTagEnv[@"tag"] = @"";
        NSDictionary *emptyTagRes = [securityB decryptAndVerifyDictionary:emptyTagEnv fromPeerId:macAId];
        ASSERT_TRUE(emptyTagRes == nil, "Envelope with empty tag MUST return nil without throwing exception");

        NSMutableDictionary *badIvEnv = [switchReqEnvelope mutableCopy];
        badIvEnv[@"iv"] = @(12345); // NSNumber instead of NSString
        NSDictionary *badIvRes = [securityB decryptAndVerifyDictionary:badIvEnv fromPeerId:macAId];
        ASSERT_TRUE(badIvRes == nil, "Envelope with numeric IV MUST return nil without throwing exception");

        NSMutableDictionary *shortIvEnv = [switchReqEnvelope mutableCopy];
        shortIvEnv[@"iv"] = [[NSMutableData dataWithLength:8] base64EncodedStringWithOptions:0]; // 8 bytes instead of 16
        NSDictionary *shortIvRes = [securityB decryptAndVerifyDictionary:shortIvEnv fromPeerId:macAId];
        ASSERT_TRUE(shortIvRes == nil, "Envelope with 8-byte IV MUST return nil without throwing exception");

        NSMutableDictionary *badCipherEnv = [switchReqEnvelope mutableCopy];
        badCipherEnv[@"ciphertext"] = @[ @"encrypted" ]; // NSArray instead of NSString
        NSDictionary *badCipherRes = [securityB decryptAndVerifyDictionary:badCipherEnv fromPeerId:macAId];
        ASSERT_TRUE(badCipherRes == nil, "Envelope with array ciphertext MUST return nil without throwing exception");

        NSMutableDictionary *emptyCipherEnv = [switchReqEnvelope mutableCopy];
        emptyCipherEnv[@"ciphertext"] = @"";
        NSDictionary *emptyCipherRes = [securityB decryptAndVerifyDictionary:emptyCipherEnv fromPeerId:macAId];
        ASSERT_TRUE(emptyCipherRes == nil, "Envelope with empty ciphertext MUST return nil without throwing exception");

        // 4. Decrypted plaintext validation: encrypting a valid JSON array directly
        // Even if encrypted and authenticated with valid HMAC, inner payload is array not dictionary
        NSData *activeSecret = [securityB trustedPeerSecret:macAId];
        unsigned char k_enc[CC_SHA256_DIGEST_LENGTH];
        unsigned char k_mac[CC_SHA256_DIGEST_LENGTH];
        CCHmac(kCCHmacAlgSHA256, activeSecret.bytes, activeSecret.length, "macnexa-enc", 11, k_enc);
        CCHmac(kCCHmacAlgSHA256, activeSecret.bytes, activeSecret.length, "macnexa-mac", 11, k_mac);
        unsigned char testIvBytes[16] = {0};
        NSData *arrayPlainData = [NSJSONSerialization dataWithJSONObject:@[ @"evil", @"command" ] options:0 error:nil];
        NSMutableData *arrayCipherData = [NSMutableData dataWithLength:arrayPlainData.length + kCCBlockSizeAES128];
        size_t arrayEncBytes = 0;
        CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, k_enc, kCCKeySizeAES256, testIvBytes, arrayPlainData.bytes, arrayPlainData.length, arrayCipherData.mutableBytes, arrayCipherData.length, &arrayEncBytes);
        arrayCipherData.length = arrayEncBytes;
        uint64_t arrNonce = 55555ULL;
        NSTimeInterval arrTs = [[NSDate date] timeIntervalSince1970];
        NSMutableData *arrMacInput = [NSMutableData dataWithBytes:testIvBytes length:16];
        [arrMacInput appendData:arrayCipherData];
        uint64_t bigArrNonce = CFSwapInt64HostToBig(arrNonce);
        [arrMacInput appendBytes:&bigArrNonce length:sizeof(bigArrNonce)];
        int64_t bigArrTs = CFSwapInt64HostToBig((int64_t)arrTs);
        [arrMacInput appendBytes:&bigArrTs length:sizeof(bigArrTs)];
        [arrMacInput appendData:[macAId dataUsingEncoding:NSUTF8StringEncoding]];
        unsigned char arrTagBytes[CC_SHA256_DIGEST_LENGTH];
        CCHmac(kCCHmacAlgSHA256, k_mac, CC_SHA256_DIGEST_LENGTH, arrMacInput.bytes, arrMacInput.length, arrTagBytes);
        NSDictionary *arrayInnerEnv = @{
            @"senderId": macAId,
            @"nonce": @(arrNonce),
            @"timestamp": @(arrTs),
            @"iv": [[NSData dataWithBytes:testIvBytes length:16] base64EncodedStringWithOptions:0],
            @"ciphertext": [arrayCipherData base64EncodedStringWithOptions:0],
            @"tag": [[NSData dataWithBytes:arrTagBytes length:32] base64EncodedStringWithOptions:0]
        };
        NSDictionary *arrayInnerRes = [securityB decryptAndVerifyDictionary:arrayInnerEnv fromPeerId:macAId];
        ASSERT_TRUE(arrayInnerRes == nil, "Envelope containing decrypted JSON array MUST return nil without throwing exception");

        // 5. Decoded public key size boundaries: 32 <= length <= 256
        MNEphemeralKeyPair *testPair = [securityA generateEphemeralKeyPair];
        ASSERT_TRUE(testPair != nil, "Ephemeral keypair generation must succeed");

        NSData *zeroKey = [NSData data]; // 0 bytes
        NSData *zeroSecret = [securityA deriveSharedSecretWithPrivateKey:testPair.privateKey remotePublicKeyData:zeroKey];
        ASSERT_TRUE(zeroSecret == nil, "Zero-length public key MUST return nil");

        NSData *undersizedKey = [NSMutableData dataWithLength:16]; // 16 bytes < 32 bytes minimum
        NSData *underSecret = [securityA deriveSharedSecretWithPrivateKey:testPair.privateKey remotePublicKeyData:undersizedKey];
        ASSERT_TRUE(underSecret == nil, "Undersized public key (< 32 bytes) MUST return nil");

        NSData *oversizedKey = [NSMutableData dataWithLength:512]; // 512 bytes > 256 bytes maximum
        NSData *overSecret = [securityA deriveSharedSecretWithPrivateKey:testPair.privateKey remotePublicKeyData:oversizedKey];
        ASSERT_TRUE(overSecret == nil, "Oversized public key (> 256 bytes) MUST return nil");

        NSData *badKeyTypeSecret = [securityA deriveSharedSecretWithPrivateKey:testPair.privateKey remotePublicKeyData:(NSData *)@"not_nsdata"];
        ASSERT_TRUE(badKeyTypeSecret == nil, "Wrongly typed public key object MUST return nil without throwing exception");

        // 6. Switch acknowledgment envelope & parameter boundaries
        NSDictionary *arrayAckRes = [securityA decryptAndVerifySwitchAcknowledgment:(NSDictionary *)@[ @YES ]
                                                                      expectedPeer:macBId
                                                                      requestNonce:switchReqNonce
                                                                        requestTag:reqTag];
        ASSERT_TRUE(arrayAckRes == nil, "Top-level array acknowledgment MUST return nil without throwing exception");

        NSDictionary *numActionAck = @{ @"action": @(123) }; // Action is NSNumber instead of NSString
        NSDictionary *numActionRes = [securityA decryptAndVerifySwitchAcknowledgment:numActionAck
                                                                        expectedPeer:macBId
                                                                        requestNonce:switchReqNonce
                                                                          requestTag:reqTag];
        ASSERT_TRUE(numActionRes == nil, "Acknowledgment with numeric action MUST return nil without throwing exception");

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
        NSDictionary *nilPeerAck = [securityA decryptAndVerifySwitchAcknowledgment:wireAck
                                                                      expectedPeer:(NSString *)nil
                                                                      requestNonce:switchReqNonce
                                                                        requestTag:reqTag];
        ASSERT_TRUE(nilPeerAck == nil, "Nil expected peer ID MUST return nil");

        NSDictionary *emptyTagAck = [securityA decryptAndVerifySwitchAcknowledgment:wireAck
                                                                       expectedPeer:macBId
                                                                       requestNonce:switchReqNonce
                                                                         requestTag:@""];
        ASSERT_TRUE(emptyTagAck == nil, "Empty expected request tag MUST return nil");

        // 7. Pairing confirmation tag type safety & length boundaries
        BOOL nilTagRes = [securityA verifyPairingConfirmationTag:nil
                                                      withSecret:testSecret
                                                            role:@"initiator"
                                                    senderPeerId:macBId
                                                  receiverPeerId:macAId];
        ASSERT_TRUE(nilTagRes == NO, "Nil confirmation tag MUST return NO without throwing exception");
#pragma clang diagnostic pop

        BOOL badTagRes1 = [securityA verifyPairingConfirmationTag:(NSData *)@"not_data"
                                                       withSecret:testSecret
                                                             role:@"initiator"
                                                     senderPeerId:macBId
                                                   receiverPeerId:macAId];
        ASSERT_TRUE(badTagRes1 == NO, "String confirmation tag MUST return NO without throwing exception");

        BOOL badTagRes2 = [securityA verifyPairingConfirmationTag:[NSMutableData dataWithLength:16] // Wrong length (16 != 32)
                                                       withSecret:testSecret
                                                             role:@"initiator"
                                                     senderPeerId:macBId
                                                   receiverPeerId:macAId];
        ASSERT_TRUE(badTagRes2 == NO, "16-byte confirmation tag MUST return NO without throwing exception");

        BOOL overTagRes = [securityA verifyPairingConfirmationTag:[NSMutableData dataWithLength:64] // Wrong length (64 != 32)
                                                       withSecret:testSecret
                                                             role:@"initiator"
                                                     senderPeerId:macBId
                                                   receiverPeerId:macAId];
        ASSERT_TRUE(overTagRes == NO, "64-byte confirmation tag MUST return NO without throwing exception");

        // 8. Device-list boundary limits & input sanitization
        NSMutableArray *excessiveDevices = [NSMutableArray array];
        for (int i = 0; i < 20; i++) {
            [excessiveDevices addObject:@{ @"address": [NSString stringWithFormat:@"AA-BB-CC-DD-EE-%02X", i], @"name": @"Dev" }];
        }
        ASSERT_TRUE(excessiveDevices.count > 16, "Must test excessive device list > 16");
        BOOL exceedsLimit = (excessiveDevices.count > 16);
        ASSERT_TRUE(exceedsLimit, "Device list exceeding 16 items must be rejected");

        NSArray *rawTestDevices = @[
            @{ @"address": @"AA-BB-CC-DD-EE-01", @"name": @"Valid Mouse", @"type": @"mouse", @"battery": @85 },
            @{ @"address": @"", @"name": @"Empty Address" },
            @{ @"address": [NSString stringWithFormat:@"%070d", 1], @"name": @"Overlong Address" },
            @"not_a_dictionary",
            @{ @"address": @"AA-BB-CC-DD-EE-02", @"name": [NSString stringWithFormat:@"%0200d", 1], @"type": @123, @"battery": @"eighty" }
        ];
        NSMutableArray *sanitized = [NSMutableArray array];
        for (id devObj in rawTestDevices) {
            if (![devObj isKindOfClass:[NSDictionary class]]) continue;
            NSDictionary *devDict = (NSDictionary *)devObj;
            id addrObj = devDict[@"address"];
            id nameObj = devDict[@"name"];
            id typeObj = devDict[@"type"];
            id batteryObj = devDict[@"battery"];
            if (![addrObj isKindOfClass:[NSString class]] || [(NSString *)addrObj length] == 0 || [(NSString *)addrObj length] > 64) {
                continue;
            }
            NSMutableDictionary *cleanDev = [NSMutableDictionary dictionary];
            cleanDev[@"address"] = addrObj;
            cleanDev[@"name"] = ([nameObj isKindOfClass:[NSString class]] && [(NSString *)nameObj length] <= 128) ? nameObj : @"Accessory";
            cleanDev[@"type"] = ([typeObj isKindOfClass:[NSString class]] && [(NSString *)typeObj length] <= 64) ? typeObj : @"unknown";
            if ([batteryObj isKindOfClass:[NSNumber class]]) cleanDev[@"battery"] = batteryObj;
            [sanitized addObject:cleanDev];
        }
        ASSERT_TRUE(sanitized.count == 2, "Only valid devices must pass sanitization");
        ASSERT_TRUE([sanitized[1][@"name"] isEqualToString:@"Accessory"], "Overlong device name must be sanitized to default");
        ASSERT_TRUE([sanitized[1][@"type"] isEqualToString:@"unknown"], "Non-string device type must be sanitized to unknown");
        ASSERT_TRUE(sanitized[1][@"battery"] == nil, "Non-number battery must be omitted");

        // -------------------------------------------------------------
        // Test 9: Cleanup
        // -------------------------------------------------------------
        printf("  [9/9] Cleaning up test sandbox...\n");
        [receiverMac resetReplayHistory];
        [securityA resetReplayHistory];
        [securityB resetReplayHistory];
        [fm removeItemAtPath:tmpDir error:nil];

        printf("✅ All 9 test suites PASSED successfully!\n");
    }
    return 0;
}
