//
//  MNBluetoothManager.h
//  MacNexa
//
//  Hardware Bluetooth accessory management: discovery, battery monitoring,
//  silent pairing, and connection handoff for Apple Magic Keyboard and Trackpad.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@protocol MNBluetoothManagerDelegate <NSObject>
- (void)bluetoothAccessoriesDidChange;
@end

@interface MNBluetoothManager : NSObject

+ (instancetype)shared;

@property (nonatomic, weak) id<MNBluetoothManagerDelegate> delegate;
@property (nonatomic, readonly) BOOL isMockMode;

// Returns currently connected Apple Magic accessories with battery percentage
- (NSArray<NSDictionary<NSString *, id> *> *)fetchConnectedAccessories;

// Returns remembered accessories (with last known battery percentage)
- (NSArray<NSDictionary<NSString *, id> *> *)rememberedAccessories;

// Re-connect to all remembered accessories
- (void)reconnectAccessories:(nullable void(^)(BOOL success))completion;

// Releases (unpairs & disconnects) specified devices locally for handoff to another Mac
- (void)releaseAccessories:(NSArray<NSDictionary *> *)accessories
                completion:(void(^)(BOOL success, NSString * _Nullable error))completion;

// Acquires (silently pairs & connects) specified devices received from another Mac
- (void)acquireAccessories:(NSArray<NSDictionary *> *)accessories
                completion:(void(^)(BOOL success, NSString * _Nullable error))completion;

@end

NS_ASSUME_NONNULL_END
