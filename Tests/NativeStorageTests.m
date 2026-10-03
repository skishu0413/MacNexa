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
        printf("  [1/5] Testing MNFileSecretStore CRUD operations...\n");
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
        printf("  [2/5] Testing enforced POSIX permissions (0700 dir, 0600 files)...\n");
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
        printf("  [3/5] Testing safe corruption handling and file quarantine...\n");
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
        // Test 4: Injected Storage in MNSecurity
        // -------------------------------------------------------------
        printf("  [4/5] Testing injected storage interface in MNSecurity...\n");
        MockFailingSecretStore *mockStore = [[MockFailingSecretStore alloc] init];
        MNSecurity *security = [[MNSecurity alloc] initWithSecretStore:mockStore];
        ASSERT_TRUE(security.secretStore == mockStore, "Injected store must be active in MNSecurity");

        // Normal save with mock
        NSData *peerSec = [@"P256SharedSecretData32Bytes12345" dataUsingEncoding:NSUTF8StringEncoding];
        NSError *secErr = nil;
        BOOL peerSaved = [security saveTrustedPeerId:@"test-peer" name:@"MacBook Pro" secret:peerSec error:&secErr];
        ASSERT_TRUE(peerSaved, "saveTrustedPeerId must succeed with injected store");
        ASSERT_TRUE([security isPeerTrusted:@"test-peer"], "Peer should be trusted");

        // Injected failure: simulated disk write failure
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

        // Injected remove failure
        mockStore.shouldFailRemove = YES;
        NSError *rmErr = nil;
        BOOL rmFail = [security removeTrustedPeerId:@"test-peer" error:&rmErr];
        ASSERT_TRUE(!rmFail, "removeTrustedPeerId must fail when store fails");
        ASSERT_TRUE(security.lastStorageError != nil, "lastStorageError must be recorded on remove failure");

        // -------------------------------------------------------------
        // Test 5: Replay Protection & DoS Resistance (Unauthenticated Nonce Tampering)
        // -------------------------------------------------------------
        printf("  [5/6] Testing replay protection immunity against unauthenticated nonce DoS...\n");
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

        // 5. Restart behavior: Simulate receiver daemon restart by creating a new MNSecurity instance.
        // It must load persistent replay history and reject replayed packet 2 even across restarts!
        MNSecurity *restartedReceiver = [[MNSecurity alloc] initWithSecretStore:store localPeerId:receiverPeerId];
        NSDictionary *postRestartReplay = [restartedReceiver decryptAndVerifyDictionary:legitEnvelope2 fromPeerId:senderId];
        ASSERT_TRUE(postRestartReplay == nil, "Pre-restart envelope 2 must be rejected after restart (persistent replay protection)!");

        // And new envelope 3 (nonce 1002) after restart must succeed
        NSDictionary *legitCmd3 = @{ @"action": @"connectAccessory", @"target": @"mouse" };
        NSDictionary *legitEnvelope3 = [senderMac encryptDictionary:legitCmd3 forPeerId:receiverMac.localPeerId nonce:1002 timestamp:now];
        ASSERT_TRUE(legitEnvelope3 != nil, "legitEnvelope3 encryption should succeed");

        NSDictionary *decrypted3 = [restartedReceiver decryptAndVerifyDictionary:legitEnvelope3 fromPeerId:senderId];
        ASSERT_TRUE(decrypted3 != nil, "New command with nonce 1002 must succeed on restarted receiver!");
        ASSERT_TRUE([decrypted3[@"action"] isEqualToString:@"connectAccessory"], "Command 3 action must match");

        // -------------------------------------------------------------
        // Test 6: Mutual Pairing Sequence & Authenticated Confirmation Tags
        // -------------------------------------------------------------
        printf("  [6/7] Testing repaired pairing sequence & authenticated confirmation tags...\n");
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

        // 4. Persistence of Trust ONLY after confirmations succeed
        // Receiver persists trust upon verifying Initiator
        BOOL bSaved = [securityB saveTrustedPeerId:macAId name:@"Mac A" secret:secretB error:nil];
        ASSERT_TRUE(bSaved, "Receiver must save trusted peer after verification");

        // Initiator persists trust upon verifying Receiver
        BOOL aSaved = [securityA saveTrustedPeerId:macBId name:@"Mac B" secret:secretA error:nil];
        ASSERT_TRUE(aSaved, "Initiator must save trusted peer after verification");

        ASSERT_TRUE([securityA isPeerTrusted:macBId], "Mac B must now be trusted on Mac A");
        ASSERT_TRUE([securityB isPeerTrusted:macAId], "Mac A must now be trusted on Mac B");

        // -------------------------------------------------------------
        // Test 7: Authenticated Switch Acknowledgments & Request Bindings
        // -------------------------------------------------------------
        printf("  [7/8] Testing authenticated switch acknowledgments & request bindings...\n");
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

        // 3. Envelope field type validation: wrongly typed nonce, timestamp, or tag
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

        // 4. Decoded public key size boundaries: 32 <= length <= 256
        MNEphemeralKeyPair *testPair = [securityA generateEphemeralKeyPair];
        ASSERT_TRUE(testPair != nil, "Ephemeral keypair generation must succeed");

        NSData *undersizedKey = [NSMutableData dataWithLength:16]; // 16 bytes < 32 bytes minimum
        NSData *underSecret = [securityA deriveSharedSecretWithPrivateKey:testPair.privateKey remotePublicKeyData:undersizedKey];
        ASSERT_TRUE(underSecret == nil, "Undersized public key (< 32 bytes) MUST return nil");

        NSData *oversizedKey = [NSMutableData dataWithLength:512]; // 512 bytes > 256 bytes maximum
        NSData *overSecret = [securityA deriveSharedSecretWithPrivateKey:testPair.privateKey remotePublicKeyData:oversizedKey];
        ASSERT_TRUE(overSecret == nil, "Oversized public key (> 256 bytes) MUST return nil");

        NSData *badKeyTypeSecret = [securityA deriveSharedSecretWithPrivateKey:testPair.privateKey remotePublicKeyData:(NSData *)@"not_nsdata"];
        ASSERT_TRUE(badKeyTypeSecret == nil, "Wrongly typed public key object MUST return nil without throwing exception");

        // 5. Switch acknowledgment envelope type validation
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

        // 6. Pairing confirmation tag type safety
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
