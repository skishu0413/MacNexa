//
//  MNNetwork.m
//  MacNexa
//
//  Hardened Peer Discovery, Ephemeral ECDH Key Exchange, and Authenticated Switching.
//

#import "MNNetwork.h"
#import "MNSecurity.h"
#import "MNBluetoothManager.h"
#import <Cocoa/Cocoa.h>
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>
#import <unistd.h>

static const uint16_t kMNPort = 57842;
static NSString * const kMNServiceType = @"_macnexa._tcp.";
static const uint32_t kMNMaxFrameSize = 65536; // 64 KB maximum payload guard

@interface MNNetwork () <NSNetServiceDelegate, NSNetServiceBrowserDelegate>
@property (nonatomic, strong) NSNetService *netService;
@property (nonatomic, strong) NSNetServiceBrowser *netServiceBrowser;
@property (nonatomic, strong) NSMutableArray<NSNetService *> *resolvingServices;
@property (nonatomic, strong) NSMutableDictionary<NSString *, NSDictionary *> *peersById;
@property (nonatomic, assign) int serverSocket;
@property (nonatomic, strong) dispatch_source_t serverSource;
@property (nonatomic, strong) dispatch_queue_t netQueue;
@property (nonatomic, assign) NSTimeInterval lastPairingPromptTime;
@end

@implementation MNNetwork

+ (instancetype)shared {
    static MNNetwork *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[MNNetwork alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _resolvingServices = [NSMutableArray array];
        _peersById = [NSMutableDictionary dictionary];
        _netQueue = dispatch_queue_create("com.macnexa.network", DISPATCH_QUEUE_SERIAL);
        _serverSocket = -1;
        _lastPairingPromptTime = 0;
    }
    return self;
}

- (NSArray<NSDictionary *> *)discoveredPeers {
    return [self.peersById allValues];
}

- (void)start {
    [self startServer];
    [self startBonjour];
}

- (void)stop {
    if (self.serverSource) {
        dispatch_source_cancel(self.serverSource);
        self.serverSource = nil;
    }
    if (self.serverSocket >= 0) {
        close(self.serverSocket);
        self.serverSocket = -1;
    }
    [self.netService stop];
    [self.netServiceBrowser stop];
}

#pragma mark - Bonjour

- (void)startBonjour {
    NSString *name = [NSString stringWithFormat:@"%@ (%@)",
                      [MNSecurity shared].localPeerName,
                      [[MNSecurity shared].localPeerId substringToIndex:6]];

    self.netService = [[NSNetService alloc] initWithDomain:@"local."
                                                      type:kMNServiceType
                                                      name:name
                                                      port:kMNPort];
    self.netService.delegate = self;

    NSDictionary *txt = @{
        @"id": [[MNSecurity shared].localPeerId dataUsingEncoding:NSUTF8StringEncoding],
        @"name": [[MNSecurity shared].localPeerName dataUsingEncoding:NSUTF8StringEncoding]
    };
    [self.netService setTXTRecordData:[NSNetService dataFromTXTRecordDictionary:txt]];
    [self.netService publish];

    self.netServiceBrowser = [[NSNetServiceBrowser alloc] init];
    self.netServiceBrowser.delegate = self;
    [self.netServiceBrowser searchForServicesOfType:kMNServiceType inDomain:@"local."];
}

- (void)netServiceBrowser:(NSNetServiceBrowser *)browser didFindService:(NSNetService *)service moreComing:(BOOL)moreComing {
    if ([service.name containsString:[[MNSecurity shared].localPeerId substringToIndex:6]]) {
        return; // Skip own service
    }
    service.delegate = self;
    [self.resolvingServices addObject:service];
    [service resolveWithTimeout:5.0];
}

- (void)netServiceBrowser:(NSNetServiceBrowser *)browser didRemoveService:(NSNetService *)service moreComing:(BOOL)moreComing {
    NSString *removeKey = nil;
    for (NSString *key in self.peersById) {
        NSDictionary *info = self.peersById[key];
        if ([info[@"serviceName"] isEqualToString:service.name]) {
            removeKey = key;
            break;
        }
    }
    if (removeKey) {
        [self.peersById removeObjectForKey:removeKey];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (self.delegate) [self.delegate networkPeersDidChange];
        });
    }
}

- (void)netServiceDidResolveAddress:(NSNetService *)service {
    NSDictionary *txt = [NSNetService dictionaryFromTXTRecordData:service.TXTRecordData];
    NSString *peerId = [[NSString alloc] initWithData:txt[@"id"] encoding:NSUTF8StringEncoding];
    NSString *peerName = [[NSString alloc] initWithData:txt[@"name"] encoding:NSUTF8StringEncoding] ?: service.name;

    if (!peerId || [peerId isEqualToString:[MNSecurity shared].localPeerId]) return;

    NSString *host = service.hostName;
    NSInteger port = service.port;

    NSString *ipAddress = nil;
    for (NSData *addrData in service.addresses) {
        struct sockaddr *sa = (struct sockaddr *)addrData.bytes;
        if (sa->sa_family == AF_INET) {
            char ipStr[INET_ADDRSTRLEN];
            struct sockaddr_in *sin = (struct sockaddr_in *)sa;
            inet_ntop(AF_INET, &(sin->sin_addr), ipStr, INET_ADDRSTRLEN);
            ipAddress = [NSString stringWithUTF8String:ipStr];
            break;
        }
    }

    if (ipAddress) {
        self.peersById[peerId] = @{
            @"id": peerId,
            @"name": peerName,
            @"ip": ipAddress,
            @"host": host ?: ipAddress,
            @"port": @(port > 0 ? port : kMNPort),
            @"serviceName": service.name
        };
        dispatch_async(dispatch_get_main_queue(), ^{
            if (self.delegate) [self.delegate networkPeersDidChange];
        });
    }
}

#pragma mark - TCP Server & Hardening

- (void)setSocketTimeout:(int)sock seconds:(int)seconds {
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof(tv));
}

- (void)applySocketTimeouts:(int)sock {
    [self setSocketTimeout:sock seconds:5]; // 5 second timeout for standard operations
}

- (void)startServer {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return;

    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(kMNPort);

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(s);
        return;
    }

    if (listen(s, 5) < 0) {
        close(s);
        return;
    }

    self.serverSocket = s;
    self.serverSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, s, 0, self.netQueue);
    dispatch_source_set_event_handler(self.serverSource, ^{
        struct sockaddr_in clientAddr;
        socklen_t clientLen = sizeof(clientAddr);
        int clientSock = accept(s, (struct sockaddr *)&clientAddr, &clientLen);
        if (clientSock >= 0) {
            [self applySocketTimeouts:clientSock];
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                [self handleIncomingConnection:clientSock];
            });
        }
    });
    dispatch_resume(self.serverSource);
}

- (void)handleIncomingConnection:(int)sock {
    NSDictionary *msg = [self readMessageFromSocket:sock];
    if (!msg) {
        close(sock);
        return;
    }

    NSString *action = msg[@"action"];

    // 1. Ephemeral ECDH Pairing Key Exchange
    if ([action isEqualToString:@"pairKeyExchange"] || [action isEqualToString:@"pairRequest"]) {
        NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
        
        // Rate Limiter: Drop if pairing prompts are spammed faster than 1 per 5 seconds
        if (now - self.lastPairingPromptTime < 5.0) {
            NSDictionary *reply = @{ @"action": @"pairKeyExchangeResponse", @"accepted": @NO, @"error": @"Rate limited" };
            [self sendMessage:reply toSocket:sock];
            close(sock);
            return;
        }

        NSString *peerId = msg[@"peerId"];
        NSString *peerName = msg[@"peerName"] ?: @"Remote Mac";
        NSString *b64RemotePubKey = msg[@"pubKey"];
        NSData *remotePubKeyData = b64RemotePubKey ? [[NSData alloc] initWithBase64EncodedString:b64RemotePubKey options:0] : nil;

        if (!peerId || !remotePubKeyData) {
            close(sock);
            return;
        }

        // Generate local ephemeral ECDH keypair
        MNEphemeralKeyPair *localPair = [[MNSecurity shared] generateEphemeralKeyPair];
        if (!localPair) {
            close(sock);
            return;
        }

        // Derive shared secret: sharedSecret = ECDH(localPrivateKey, remotePublicKey)
        NSData *sharedSecret = [[MNSecurity shared] deriveSharedSecretWithPrivateKey:localPair.privateKey
                                                                remotePublicKeyData:remotePubKeyData];
        if (!sharedSecret) {
            NSDictionary *reply = @{ @"action": @"pairKeyExchangeResponse", @"accepted": @NO, @"error": @"Key derivation failed" };
            [self sendMessage:reply toSocket:sock];
            close(sock);
            return;
        }

        // Compute matching SAS verification code
        NSString *sasCode = [[MNSecurity shared] computeSASFromSecret:sharedSecret
                                                                peerA:[MNSecurity shared].localPeerId
                                                                peerB:peerId];

        // 1. Exchange public keys FIRST: Send local public key immediately back to Initiator
        NSDictionary *keyExReply = @{
            @"action": @"pairKeyExchangeResponse",
            @"accepted": @YES,
            @"peerId": [MNSecurity shared].localPeerId,
            @"peerName": [MNSecurity shared].localPeerName,
            @"pubKey": [localPair.publicKeyData base64EncodedStringWithOptions:0]
        };
        [self sendMessage:keyExReply toSocket:sock];

        // 2. Set human-scale timeout (60s) on socket while users compare codes
        [self setSocketTimeout:sock seconds:60];

        // 3. Display SAS code on Receiver so user can compare with Initiator
        self.lastPairingPromptTime = now;
        __block BOOL receiverAccepted = NO;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (self.delegate) {
                [self.delegate networkDidReceivePairingRequestFromPeer:peerName
                                                                 code:sasCode
                                                           completion:^(BOOL accepted) {
                    receiverAccepted = accepted;
                    dispatch_semaphore_signal(sem);
                }];
            } else {
                dispatch_semaphore_signal(sem);
            }
        });

        // 4. Read Initiator's authenticated confirmation from socket
        NSDictionary *initiatorConfirm = [self readMessageFromSocket:sock];
        if (!initiatorConfirm || ![initiatorConfirm[@"accepted"] boolValue]) {
            close(sock);
            return;
        }

        NSString *b64InitTag = initiatorConfirm[@"authTag"];
        NSData *initTag = b64InitTag ? [[NSData alloc] initWithBase64EncodedString:b64InitTag options:0] : nil;
        BOOL validInitTag = [[MNSecurity shared] verifyPairingConfirmationTag:initTag
                                                                   withSecret:sharedSecret
                                                                         role:@"initiator"
                                                                 senderPeerId:peerId
                                                               receiverPeerId:[MNSecurity shared].localPeerId];
        if (!validInitTag) {
            NSDictionary *errReply = @{ @"action": @"pairConfirmResponse", @"accepted": @NO, @"error": @"Cryptographic confirmation verification failed" };
            [self sendMessage:errReply toSocket:sock];
            close(sock);
            return;
        }

        // 5. Wait for Receiver user confirmation
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        if (!receiverAccepted) {
            NSDictionary *cancelReply = @{ @"action": @"pairConfirmResponse", @"accepted": @NO, @"error": @"Pairing declined by user" };
            [self sendMessage:cancelReply toSocket:sock];
            close(sock);
            return;
        }

        // 6. Persist trust ONLY after both confirmations succeed
        NSError *saveErr = nil;
        BOOL ok = [[MNSecurity shared] saveTrustedPeerId:peerId name:peerName secret:sharedSecret error:&saveErr];
        if (!ok) {
            NSLog(@"[MacNexa Network] ❌ Storage error saving trusted peer: %@", saveErr.localizedDescription);
            NSDictionary *errReply = @{
                @"action": @"pairConfirmResponse",
                @"accepted": @NO,
                @"error": [NSString stringWithFormat:@"Storage error: %@", saveErr.localizedDescription]
            };
            [self sendMessage:errReply toSocket:sock];
            close(sock);
            return;
        }

        // 7. Send Receiver's authenticated confirmation response
        NSData *recvTag = [[MNSecurity shared] computePairingConfirmationTagWithSecret:sharedSecret
                                                                                  role:@"receiver"
                                                                          senderPeerId:[MNSecurity shared].localPeerId
                                                                        receiverPeerId:peerId];
        NSDictionary *successReply = @{
            @"action": @"pairConfirmResponse",
            @"accepted": @YES,
            @"authTag": [recvTag base64EncodedStringWithOptions:0]
        };
        [self sendMessage:successReply toSocket:sock];
        close(sock);
        return;
    }

    // 2. Authenticated Encrypted Switch Request
    if ([action isEqualToString:@"encryptedEnvelope"]) {
        NSString *senderId = msg[@"senderId"];

        if (![[MNSecurity shared] isPeerTrusted:senderId]) {
            close(sock);
            return;
        }

        // Decrypt & verify constant-time HMAC-SHA256 signature + replay protection
        NSDictionary *decrypted = [[MNSecurity shared] decryptAndVerifyDictionary:msg fromPeerId:senderId];
        if (!decrypted || ![decrypted[@"action"] isEqualToString:@"requestSwitch"]) {
            close(sock);
            return;
        }

        uint64_t reqNonce = [msg[@"nonce"] unsignedLongLongValue];
        NSString *reqTag = msg[@"tag"] ?: @"";

        NSArray *devices = decrypted[@"devices"];
        NSString *peerName = [[MNSecurity shared] trustedPeerInfo:senderId][@"name"] ?: @"Remote Mac";
        dispatch_async(dispatch_get_main_queue(), ^{
            if (self.delegate) [self.delegate networkSwitchDidStartWithPeer:peerName isOutgoing:NO];
        });

        // Acquire peripherals
        [[MNBluetoothManager shared] acquireAccessories:devices completion:^(BOOL success, NSString *err) {
            // Send authenticated switch acknowledgment bound to exact requestNonce, requestTag, and peer
            NSDictionary *wireAck = [[MNSecurity shared] encryptSwitchAcknowledgment:success
                                                                               error:err
                                                                        requestNonce:reqNonce
                                                                          requestTag:reqTag
                                                                           forPeerId:senderId];
            if (wireAck) {
                [self sendMessage:wireAck toSocket:sock];
            }
            close(sock);

            dispatch_async(dispatch_get_main_queue(), ^{
                if (self.delegate) [self.delegate networkSwitchDidCompleteWithPeer:peerName success:success error:err];
            });
        }];
        return;
    }

    close(sock);
}

#pragma mark - Messaging

- (void)sendMessage:(NSDictionary *)dict toSocket:(int)sock {
    NSData *data = [NSJSONSerialization dataWithJSONObject:dict options:0 error:nil];
    if (!data || data.length > kMNMaxFrameSize) return;
    uint32_t len = htonl((uint32_t)data.length);
    send(sock, &len, 4, 0);
    send(sock, data.bytes, data.length, 0);
}

- (NSDictionary *)readMessageFromSocket:(int)sock {
    uint32_t netLen = 0;
    ssize_t r = recv(sock, &netLen, 4, MSG_WAITALL);
    if (r != 4) return nil;
    uint32_t len = ntohl(netLen);
    if (len == 0 || len > kMNMaxFrameSize) return nil; // Reject oversized payloads

    NSMutableData *data = [NSMutableData dataWithLength:len];
    r = recv(sock, data.mutableBytes, len, MSG_WAITALL);
    if (r != len) return nil;

    return [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
}

- (int)connectToPeer:(NSDictionary *)peerInfo {
    NSString *ip = peerInfo[@"ip"];
    int port = [peerInfo[@"port"] intValue];
    if (!ip) return -1;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    [self applySocketTimeouts:sock];

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, [ip UTF8String], &addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

#pragma mark - Public Actions

- (void)pairWithPeer:(NSDictionary *)peer completion:(void(^)(BOOL success, NSString * _Nullable error))completion {
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int sock = [self connectToPeer:peer];
        if (sock < 0) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, @"Could not connect to peer");
            });
            return;
        }

        // Generate ephemeral ECDH keypair
        MNEphemeralKeyPair *localPair = [[MNSecurity shared] generateEphemeralKeyPair];
        if (!localPair) {
            close(sock);
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, @"Failed to generate cryptographic keypair");
            });
            return;
        }

        NSString *targetPeerId = peer[@"id"];

        // 1. Exchange public keys FIRST (raw secret is NEVER transmitted!)
        NSDictionary *req = @{
            @"action": @"pairKeyExchange",
            @"peerId": [MNSecurity shared].localPeerId,
            @"peerName": [MNSecurity shared].localPeerName,
            @"pubKey": [localPair.publicKeyData base64EncodedStringWithOptions:0]
        };
        [self sendMessage:req toSocket:sock];

        // Wait for peer's public key response (machine-to-machine, automated)
        NSDictionary *resp = [self readMessageFromSocket:sock];
        if (!resp || ![resp[@"accepted"] boolValue] || !resp[@"pubKey"]) {
            close(sock);
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, resp[@"error"] ?: @"Pairing key exchange was declined or timed out");
            });
            return;
        }

        NSData *remotePubKeyData = [[NSData alloc] initWithBase64EncodedString:resp[@"pubKey"] options:0];
        NSData *sharedSecret = [[MNSecurity shared] deriveSharedSecretWithPrivateKey:localPair.privateKey
                                                                remotePublicKeyData:remotePubKeyData];
        if (!sharedSecret) {
            close(sock);
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, @"Cryptographic key exchange derivation failed");
            });
            return;
        }

        NSString *remotePeerId = resp[@"peerId"] ?: targetPeerId;
        NSString *remotePeerName = resp[@"peerName"] ?: peer[@"name"];

        // 2. Both sides calculate matching SAS verification code
        NSString *sasCode = [[MNSecurity shared] computeSASFromSecret:sharedSecret
                                                                peerA:[MNSecurity shared].localPeerId
                                                                peerB:remotePeerId];

        // 3. Set human-scale timeout (60 seconds) while users compare codes
        [self setSocketTimeout:sock seconds:60];

        // 4. Prompt Initiator user to verify SAS code
        __block BOOL initiatorAccepted = NO;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);
        dispatch_async(dispatch_get_main_queue(), ^{
            if (self.delegate) {
                [self.delegate networkDidReceivePairingRequestFromPeer:remotePeerName
                                                                 code:sasCode
                                                           completion:^(BOOL accepted) {
                    initiatorAccepted = accepted;
                    dispatch_semaphore_signal(sem);
                }];
            } else {
                dispatch_semaphore_signal(sem);
            }
        });
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);

        if (!initiatorAccepted) {
            NSDictionary *cancelMsg = @{ @"action": @"pairConfirm", @"accepted": @NO };
            [self sendMessage:cancelMsg toSocket:sock];
            close(sock);
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, @"Pairing cancelled by user");
            });
            return;
        }

        // 5. Send authenticated confirmation to Receiver
        NSData *initTag = [[MNSecurity shared] computePairingConfirmationTagWithSecret:sharedSecret
                                                                                  role:@"initiator"
                                                                          senderPeerId:[MNSecurity shared].localPeerId
                                                                        receiverPeerId:remotePeerId];
        NSDictionary *confirmMsg = @{
            @"action": @"pairConfirm",
            @"accepted": @YES,
            @"authTag": [initTag base64EncodedStringWithOptions:0]
        };
        [self sendMessage:confirmMsg toSocket:sock];

        // 6. Wait for Receiver's authenticated confirmation
        NSDictionary *confirmResp = [self readMessageFromSocket:sock];
        close(sock);

        if (!confirmResp || ![confirmResp[@"accepted"] boolValue]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, confirmResp[@"error"] ?: @"Pairing was declined by the remote Mac or timed out");
            });
            return;
        }

        NSString *b64RecvTag = confirmResp[@"authTag"];
        NSData *recvTag = b64RecvTag ? [[NSData alloc] initWithBase64EncodedString:b64RecvTag options:0] : nil;
        BOOL validRecvTag = [[MNSecurity shared] verifyPairingConfirmationTag:recvTag
                                                                   withSecret:sharedSecret
                                                                         role:@"receiver"
                                                                 senderPeerId:remotePeerId
                                                               receiverPeerId:[MNSecurity shared].localPeerId];
        if (!validRecvTag) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, @"Pairing confirmation failed cryptographic authentication");
            });
            return;
        }

        // 7. Persist trust ONLY after required confirmations succeed
        NSError *saveErr = nil;
        BOOL ok = [[MNSecurity shared] saveTrustedPeerId:remotePeerId
                                                    name:remotePeerName
                                                  secret:sharedSecret
                                                   error:&saveErr];
        dispatch_async(dispatch_get_main_queue(), ^{
            if (ok) {
                if (completion) completion(YES, nil);
            } else {
                NSString *errMsg = [NSString stringWithFormat:@"Storage Error: %@\n%@",
                                    saveErr.localizedDescription,
                                    saveErr.localizedRecoverySuggestion ?: @""];
                if (completion) completion(NO, errMsg);
            }
        });
    });
}

- (void)switchToPeer:(NSString *)peerId completion:(void(^)(BOOL success, NSString * _Nullable error))completion {
    NSDictionary *trusted = [[MNSecurity shared] trustedPeerInfo:peerId];
    if (!trusted) {
        if (completion) completion(NO, @"Peer is not trusted");
        return;
    }

    NSDictionary *peerInfo = self.peersById[peerId];
    if (!peerInfo) {
        if (completion) completion(NO, @"Peer is currently offline or unreachable on local network");
        return;
    }

    NSString *peerName = trusted[@"name"] ?: peerInfo[@"name"] ?: @"Remote Mac";
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.delegate) [self.delegate networkSwitchDidStartWithPeer:peerName isOutgoing:YES];
    });

    NSArray *devices = [[MNBluetoothManager shared] fetchConnectedAccessories];
    if (devices.count == 0) {
        devices = [[MNBluetoothManager shared] rememberedAccessories];
    }

    // Step 1: Release accessories locally
    [[MNBluetoothManager shared] releaseAccessories:devices completion:^(BOOL relSuccess, NSString *relErr) {
        if (!relSuccess) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (self.delegate) [self.delegate networkSwitchDidCompleteWithPeer:peerName success:NO error:relErr];
                if (completion) completion(NO, relErr);
            });
            return;
        }

        // Step 2: Send AES-256 + HMAC authenticated encrypted payload
        dispatch_async(self.netQueue, ^{
            int sock = [self connectToPeer:peerInfo];
            if (sock < 0) {
                // Rollback: try to reconnect locally
                [[MNBluetoothManager shared] acquireAccessories:devices completion:^(BOOL s, NSString *e) {}];
                dispatch_async(dispatch_get_main_queue(), ^{
                    if (self.delegate) [self.delegate networkSwitchDidCompleteWithPeer:peerName success:NO error:@"Failed to connect to peer over network"];
                    if (completion) completion(NO, @"Failed to connect to peer over network");
                });
                return;
            }

            uint64_t nonce = [[MNSecurity shared] nextOutgoingNonce];
            NSTimeInterval ts = [[NSDate date] timeIntervalSince1970];

            NSDictionary *innerPayload = @{
                @"action": @"requestSwitch",
                @"devices": devices
            };

            NSDictionary *envelope = [[MNSecurity shared] encryptDictionary:innerPayload
                                                                  forPeerId:peerId
                                                                      nonce:nonce
                                                                  timestamp:ts];
            if (!envelope) {
                close(sock);
                [[MNBluetoothManager shared] acquireAccessories:devices completion:^(BOOL s, NSString *e) {}];
                dispatch_async(dispatch_get_main_queue(), ^{
                    if (completion) completion(NO, @"Payload encryption failed");
                });
                return;
            }

            NSString *requestTag = envelope[@"tag"] ?: @"";

            NSMutableDictionary *wireMsg = [envelope mutableCopy];
            wireMsg[@"action"] = @"encryptedEnvelope";

            [self sendMessage:wireMsg toSocket:sock];

            // Read authenticated switch acknowledgment from receiver
            NSDictionary *wireAck = [self readMessageFromSocket:sock];
            close(sock);

            // Decrypt and authenticate acknowledgment, verifying bindings to peer, session, and exact request
            NSDictionary *decryptedAck = [[MNSecurity shared] decryptAndVerifySwitchAcknowledgment:wireAck
                                                                                      expectedPeer:peerId
                                                                                      requestNonce:nonce
                                                                                        requestTag:requestTag];
            if (!decryptedAck) {
                // Unauthenticated, plain, tampered, or mismatched acknowledgment! Rollback!
                [[MNBluetoothManager shared] acquireAccessories:devices completion:^(BOOL s, NSString *e) {}];
                dispatch_async(dispatch_get_main_queue(), ^{
                    NSString *failErr = @"Unauthenticated switch acknowledgment or request binding mismatch";
                    if (self.delegate) [self.delegate networkSwitchDidCompleteWithPeer:peerName success:NO error:failErr];
                    if (completion) completion(NO, failErr);
                });
                return;
            }

            BOOL success = [decryptedAck[@"success"] boolValue];
            NSString *err = (decryptedAck[@"error"] && decryptedAck[@"error"] != [NSNull null]) ? decryptedAck[@"error"] : nil;

            if (!success) {
                // Remote peer failed to acquire: Rollback!
                [[MNBluetoothManager shared] acquireAccessories:devices completion:^(BOOL s, NSString *e) {}];
            }

            dispatch_async(dispatch_get_main_queue(), ^{
                if (self.delegate) [self.delegate networkSwitchDidCompleteWithPeer:peerName success:success error:err];
                if (completion) completion(success, err);
            });
        });
    }];
}

@end
