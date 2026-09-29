//
//  MNNetwork.h
//  MacNexa
//
//  Cross-version peer discovery via Bonjour and secure TCP messaging.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@protocol MNNetworkDelegate <NSObject>
- (void)networkPeersDidChange;
- (void)networkDidReceivePairingRequestFromPeer:(NSString *)peerName
                                          code:(NSString *)code
                                    completion:(void(^)(BOOL accepted))completion;
- (void)networkSwitchDidStartWithPeer:(NSString *)peerName isOutgoing:(BOOL)isOutgoing;
- (void)networkSwitchDidCompleteWithPeer:(NSString *)peerName success:(BOOL)success error:(nullable NSString *)error;
@end

@interface MNNetwork : NSObject

+ (instancetype)shared;

@property (nonatomic, weak) id<MNNetworkDelegate> delegate;
@property (nonatomic, readonly) NSArray<NSDictionary *> *discoveredPeers;

- (void)start;
- (void)stop;

// Initiate pairing with a discovered peer
- (void)pairWithPeer:(NSDictionary *)peer completion:(void(^)(BOOL success, NSString * _Nullable error))completion;

// Trigger handoff of accessories to a trusted peer
- (void)switchToPeer:(NSString *)peerId completion:(void(^)(BOOL success, NSString * _Nullable error))completion;

@end

NS_ASSUME_NONNULL_END
