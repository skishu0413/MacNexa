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
    if (!msg || ![msg isKindOfClass:[NSDictionary class]]) {
        close(sock);
        return;
    }

    id actionObj = msg[@"action"];
    if (![actionObj isKindOfClass:[NSString class]]) {
        close(sock);
        return;
    }
    NSString *action = (NSString *)actionObj;

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

        id peerIdObj = msg[@"peerId"];
        id peerNameObj = msg[@"peerName"];
        id pubKeyObj = msg[@"pubKey"];

        if (![peerIdObj isKindOfClass:[NSString class]] || [(NSString *)peerIdObj length] == 0 || [(NSString *)peerIdObj length] > 256 ||
            ![pubKeyObj isKindOfClass:[NSString class]] || [(NSString *)pubKeyObj length] == 0) {
            close(sock);
            return;
        }

        NSString *peerId = (NSString *)peerIdObj;
        NSString *peerName = ([peerNameObj isKindOfClass:[NSString class]] && [(NSString *)peerNameObj length] > 0 && [(NSString *)peerNameObj length] <= 256) ? (NSString *)peerNameObj : @"Remote Mac";

        NSData *remotePubKeyData = [[NSData alloc] initWithBase64EncodedString:(NSString *)pubKeyObj options:0];
        // Validate decoded key size: P-256 public key is 65 bytes (uncompressed), 33 bytes (compressed), or 91 bytes (X.509)
        if (!remotePubKeyData || remotePubKeyData.length < 32 || remotePubKeyData.length > 256) {
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
        if (!initiatorConfirm || ![initiatorConfirm isKindOfClass:[NSDictionary class]]) {
            close(sock);
            return;
        }

        id initAccepted = initiatorConfirm[@"accepted"];
        if (![initAccepted isKindOfClass:[NSNumber class]] || ![initAccepted boolValue]) {
            close(sock);
            return;
        }

        id b64InitTag = initiatorConfirm[@"authTag"];
        if (![b64InitTag isKindOfClass:[NSString class]] || [(NSString *)b64InitTag length] == 0) {
            close(sock);
            return;
        }

        NSData *initTag = [[NSData alloc] initWithBase64EncodedString:(NSString *)b64InitTag options:0];
        if (!initTag || initTag.length != 32) {
            NSDictionary *errReply = @{ @"action": @"pairConfirmResponse", @"accepted": @NO, @"error": @"Invalid confirmation tag size" };
            [self sendMessage:errReply toSocket:sock];
            close(sock);
            return;
        }

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
        id senderIdObj = msg[@"senderId"];
        if (![senderIdObj isKindOfClass:[NSString class]] || [(NSString *)senderIdObj length] == 0 || [(NSString *)senderIdObj length] > 256) {
            close(sock);
            return;
        }
        NSString *senderId = (NSString *)senderIdObj;

        if (![[MNSecurity shared] isPeerTrusted:senderId]) {
            close(sock);
            return;
        }

        // Decrypt & verify constant-time HMAC-SHA256 signature + replay protection
        NSDictionary *decrypted = [[MNSecurity shared] decryptAndVerifyDictionary:msg fromPeerId:senderId];
        if (!decrypted || ![decrypted isKindOfClass:[NSDictionary class]]) {
            close(sock);
            return;
        }

        id decActionObj = decrypted[@"action"];
        if (![decActionObj isKindOfClass:[NSString class]] || ![decActionObj isEqualToString:@"requestSwitch"]) {
            close(sock);
            return;
        }

        id nonceObj = msg[@"nonce"];
        id tagObj = msg[@"tag"];
        if (![nonceObj isKindOfClass:[NSNumber class]] || ![tagObj isKindOfClass:[NSString class]] || [(NSString *)tagObj length] == 0) {
            close(sock);
            return;
        }

        uint64_t reqNonce = [nonceObj unsignedLongLongValue];
        NSString *reqTag = (NSString *)tagObj;

        // Device-list limits & field validation:
        id rawDevices = decrypted[@"devices"];
        if (![rawDevices isKindOfClass:[NSArray class]]) {
            close(sock);
            return;
        }
        NSArray *deviceArray = (NSArray *)rawDevices;
        // Limit: maximum 16 devices
        if (deviceArray.count > 16) {
            NSLog(@"[MacNexa Network] ⚠️ Switch request exceeded maximum device count (%lu > 16)", (unsigned long)deviceArray.count);
            close(sock);
            return;
        }

        // Validate each device entry
        NSMutableArray *sanitizedDevices = [NSMutableArray arrayWithCapacity:deviceArray.count];
        for (id devObj in deviceArray) {
            if (![devObj isKindOfClass:[NSDictionary class]]) {
                continue;
            }
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
            if ([batteryObj isKindOfClass:[NSNumber class]]) {
                cleanDev[@"battery"] = batteryObj;
            }
            [sanitizedDevices addObject:cleanDev];
        }

        NSArray *devices = [sanitizedDevices copy];
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
    if (!dict || ![dict isKindOfClass:[NSDictionary class]]) return;
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

    id json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if (![json isKindOfClass:[NSDictionary class]]) {
        return nil;
    }
    return (NSDictionary *)json;
}

- (int)connectToPeer:(NSDictionary *)peerInfo {
    if (!peerInfo || ![peerInfo isKindOfClass:[NSDictionary class]]) return -1;
    id ipObj = peerInfo[@"ip"];
    id portObj = peerInfo[@"port"];
    if (![ipObj isKindOfClass:[NSString class]] || (![portObj isKindOfClass:[NSNumber class]] && ![portObj isKindOfClass:[NSString class]])) return -1;
    NSString *ip = (NSString *)ipObj;
    int port = [portObj intValue];
    if (port <= 0 || port > 65535) return -1;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    [self applySocketTimeouts:sock];

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, [ip UTF8String], &addr.sin_addr) <= 0) {
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    return sock;
}

#pragma mark - Public Actions

- (void)pairWithPeer:(NSDictionary *)peer completion:(void(^)(BOOL success, NSString * _Nullable error))completion {
    if (!peer || ![peer isKindOfClass:[NSDictionary class]]) {
        if (completion) completion(NO, @"Invalid peer configuration");
        return;
    }

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

        id peerIdObj = peer[@"id"];
        NSString *targetPeerId = ([peerIdObj isKindOfClass:[NSString class]]) ? (NSString *)peerIdObj : @"";

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
        if (!resp || ![resp isKindOfClass:[NSDictionary class]]) {
            close(sock);
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, @"Malformed response from peer");
            });
            return;
        }

        id respAccepted = resp[@"accepted"];
        id respPubKey = resp[@"pubKey"];
        if (![respAccepted isKindOfClass:[NSNumber class]] || ![respAccepted boolValue] ||
            ![respPubKey isKindOfClass:[NSString class]] || [(NSString *)respPubKey length] == 0) {
            id errObj = resp[@"error"];
            NSString *errMsg = [errObj isKindOfClass:[NSString class]] ? (NSString *)errObj : @"Pairing key exchange was declined or timed out";
            close(sock);
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, errMsg);
            });
            return;
        }

        NSData *remotePubKeyData = [[NSData alloc] initWithBase64EncodedString:(NSString *)respPubKey options:0];
        // Validate decoded key size: P-256 public key is 65 bytes (uncompressed), 33 bytes (compressed), or 91 bytes (X.509)
        if (!remotePubKeyData || remotePubKeyData.length < 32 || remotePubKeyData.length > 256) {
            close(sock);
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, @"Invalid public key received from peer");
            });
            return;
        }

        NSData *sharedSecret = [[MNSecurity shared] deriveSharedSecretWithPrivateKey:localPair.privateKey
                                                                remotePublicKeyData:remotePubKeyData];
        if (!sharedSecret) {
            close(sock);
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, @"Cryptographic key exchange derivation failed");
            });
            return;
        }

        id respPeerId = resp[@"peerId"];
        id respPeerName = resp[@"peerName"];
        NSString *remotePeerId = ([respPeerId isKindOfClass:[NSString class]] && [(NSString *)respPeerId length] > 0 && [(NSString *)respPeerId length] <= 256) ? (NSString *)respPeerId : targetPeerId;
        NSString *remotePeerName = ([respPeerName isKindOfClass:[NSString class]] && [(NSString *)respPeerName length] > 0 && [(NSString *)respPeerName length] <= 256) ? (NSString *)respPeerName : (peer[@"name"] ?: @"Remote Mac");

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

        if (!confirmResp || ![confirmResp isKindOfClass:[NSDictionary class]]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, @"Invalid confirmation response from peer");
            });
            return;
        }

        id confAccepted = confirmResp[@"accepted"];
        if (![confAccepted isKindOfClass:[NSNumber class]] || ![confAccepted boolValue]) {
            id errObj = confirmResp[@"error"];
            NSString *errMsg = [errObj isKindOfClass:[NSString class]] ? (NSString *)errObj : @"Pairing was declined by the remote Mac or timed out";
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, errMsg);
            });
            return;
        }

        id b64RecvTag = confirmResp[@"authTag"];
        if (![b64RecvTag isKindOfClass:[NSString class]] || [(NSString *)b64RecvTag length] == 0) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, @"Malformed confirmation authTag");
            });
            return;
        }

        NSData *recvTag = [[NSData alloc] initWithBase64EncodedString:(NSString *)b64RecvTag options:0];
        if (!recvTag || recvTag.length != 32) {
            dispatch_async(dispatch_get_main_queue(), ^{
                if (completion) completion(NO, @"Invalid confirmation tag size");
            });
            return;
        }

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
    if (!peerId || ![peerId isKindOfClass:[NSString class]] || peerId.length == 0) {
        if (completion) completion(NO, @"Invalid peer identifier");
        return;
    }

    NSDictionary *trusted = [[MNSecurity shared] trustedPeerInfo:peerId];
    if (!trusted || ![trusted isKindOfClass:[NSDictionary class]]) {
        if (completion) completion(NO, @"Peer is not trusted");
        return;
    }

    NSDictionary *peerInfo = self.peersById[peerId];
    if (!peerInfo || ![peerInfo isKindOfClass:[NSDictionary class]]) {
        if (completion) completion(NO, @"Peer is currently offline or unreachable on local network");
        return;
    }

    NSString *peerName = trusted[@"name"] ?: peerInfo[@"name"] ?: @"Remote Mac";
    dispatch_async(dispatch_get_main_queue(), ^{
        if (self.delegate) [self.delegate networkSwitchDidStartWithPeer:peerName isOutgoing:YES];
    });

    NSArray *devices = [[MNBluetoothManager shared] fetchConnectedAccessories];
    if (![devices isKindOfClass:[NSArray class]] || devices.count == 0) {
        devices = [[MNBluetoothManager shared] rememberedAccessories];
    }
    if (![devices isKindOfClass:[NSArray class]]) {
        devices = @[];
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

            if (!wireAck || ![wireAck isKindOfClass:[NSDictionary class]]) {
                // Rollback!
                [[MNBluetoothManager shared] acquireAccessories:devices completion:^(BOOL s, NSString *e) {}];
                dispatch_async(dispatch_get_main_queue(), ^{
                    NSString *failErr = @"Invalid or empty response from peer";
                    if (self.delegate) [self.delegate networkSwitchDidCompleteWithPeer:peerName success:NO error:failErr];
                    if (completion) completion(NO, failErr);
                });
                return;
            }

            // Decrypt and authenticate acknowledgment, verifying bindings to peer, session, and exact request
            NSDictionary *decryptedAck = [[MNSecurity shared] decryptAndVerifySwitchAcknowledgment:wireAck
                                                                                      expectedPeer:peerId
                                                                                      requestNonce:nonce
                                                                                        requestTag:requestTag];
            if (!decryptedAck || ![decryptedAck isKindOfClass:[NSDictionary class]]) {
                // Unauthenticated, plain, tampered, or mismatched acknowledgment! Rollback!
                [[MNBluetoothManager shared] acquireAccessories:devices completion:^(BOOL s, NSString *e) {}];
                dispatch_async(dispatch_get_main_queue(), ^{
                    NSString *failErr = @"Unauthenticated switch acknowledgment or request binding mismatch";
                    if (self.delegate) [self.delegate networkSwitchDidCompleteWithPeer:peerName success:NO error:failErr];
                    if (completion) completion(NO, failErr);
                });
                return;
            }

            id succObj = decryptedAck[@"success"];
            BOOL success = [succObj isKindOfClass:[NSNumber class]] ? [succObj boolValue] : NO;
            id errObj = decryptedAck[@"error"];
            NSString *err = ([errObj isKindOfClass:[NSString class]] && [(NSString *)errObj length] > 0) ? (NSString *)errObj : nil;

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
