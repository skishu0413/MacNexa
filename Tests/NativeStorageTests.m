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
        // Test 6: Cleanup
        // -------------------------------------------------------------
        printf("  [6/6] Cleaning up test sandbox...\n");
        [receiverMac resetReplayHistory];
        [fm removeItemAtPath:tmpDir error:nil];

        printf("✅ All 6 test suites PASSED successfully!\n");
    }
    return 0;
}
