//
//  MNBluetoothManager.m
//  MacNexa
//

#import "MNBluetoothManager.h"
#import <IOBluetooth/IOBluetooth.h>
#import <IOBluetooth/objc/IOBluetoothDevice.h>
#import <IOBluetooth/objc/IOBluetoothDevicePair.h>
#import <IOKit/IOKitLib.h>

static NSString * const kMNRememberedAccessoriesKey = @"com.macnexa.remembered_accessories";
static NSString * const kMNLastBatteryPrefix = @"com.macnexa.last_battery.";

@interface MNSilentPairDelegate : NSObject <IOBluetoothDevicePairDelegate>
@property (nonatomic, copy) void (^completion)(BOOL success);
@end

@implementation MNSilentPairDelegate
- (void)devicePairingUserConfirmationRequest:(id)sender numericValue:(BluetoothNumericValue)numericValue {
    if ([sender respondsToSelector:@selector(replyUserConfirmation:)]) {
        [sender performSelector:@selector(replyUserConfirmation:) withObject:(id)kCFBooleanTrue];
    }
}

- (void)devicePairingFinished:(id)sender error:(IOReturn)error {
    if (self.completion) {
        self.completion(error == kIOReturnSuccess);
    }
}
@end

@interface MNBluetoothManager ()
@property (nonatomic, assign) BOOL isMockMode;
@property (nonatomic, strong) NSMutableArray<NSDictionary *> *mockDevices;
@property (nonatomic, strong) dispatch_queue_t btQueue;
@property (nonatomic, strong) NSMutableArray<MNSilentPairDelegate *> *activeDelegates;
@end

@implementation MNBluetoothManager

+ (instancetype)shared {
    static MNBluetoothManager *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[MNBluetoothManager alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _isMockMode = (getenv("MACNEXA_USE_MOCK_BLUETOOTH") != NULL);
        _btQueue = dispatch_queue_create("com.macnexa.bluetooth", DISPATCH_QUEUE_SERIAL);
        _activeDelegates = [NSMutableArray array];

        if (_isMockMode) {
            _mockDevices = [NSMutableArray arrayWithArray:@[
                @{ @"address": @"00-11-22-33-44-55", @"name": @"Mock Magic Keyboard", @"type": @"keyboard", @"connected": @YES, @"battery": @88 },
                @{ @"address": @"00-11-22-33-44-66", @"name": @"Mock Magic Trackpad", @"type": @"trackpad", @"connected": @YES, @"battery": @94 }
            ]];
        }
    }
    return self;
}

- (NSString *)detectDeviceType:(NSString *)name {
    NSString *lower = [name lowercaseString];
    if ([lower containsString:@"keyboard"]) return @"keyboard";
    if ([lower containsString:@"trackpad"]) return @"trackpad";
    if ([lower containsString:@"mouse"]) return @"mouse";
    return @"peripheral";
}

#pragma mark - Battery Extraction

static NSInteger MNExtractDeviceBattery(IOBluetoothDevice *dev, NSString *address) {
    if (!dev) return -1;
    
    // 1. Check IOBluetoothDevice batteryPercentSingle / batteryPercentCombined
    SEL s1 = NSSelectorFromString(@"batteryPercentSingle");
    if ([dev respondsToSelector:s1]) {
        unsigned char (*fn)(id, SEL) = (unsigned char (*)(id, SEL))[dev methodForSelector:s1];
        unsigned char val = fn(dev, s1);
        if (val > 0 && val <= 100) return (NSInteger)val;
    }

    SEL s2 = NSSelectorFromString(@"batteryPercentCombined");
    if ([dev respondsToSelector:s2]) {
        unsigned char (*fn)(id, SEL) = (unsigned char (*)(id, SEL))[dev methodForSelector:s2];
        unsigned char val = fn(dev, s2);
        if (val > 0 && val <= 100) return (NSInteger)val;
    }

    // 2. Query IOKit AppleDeviceManagementHIDEventService
    io_iterator_t iterator;
    CFDictionaryRef matchingDict = IOServiceMatching("AppleDeviceManagementHIDEventService");
    if (IOServiceGetMatchingServices(kIOMainPortDefault, matchingDict, &iterator) == KERN_SUCCESS) {
        io_object_t service;
        NSString *cleanTarget = [[address stringByReplacingOccurrencesOfString:@"-" withString:@":"] lowercaseString];
        while ((service = IOIteratorNext(iterator))) {
            CFTypeRef addrRef = IORegistryEntryCreateCFProperty(service, CFSTR("DeviceAddress"), kCFAllocatorDefault, 0);
            if (addrRef) {
                NSString *addrStr = [(__bridge id)addrRef lowercaseString];
                if ([addrStr containsString:cleanTarget] || [cleanTarget containsString:addrStr]) {
                    CFTypeRef battRef = IORegistryEntryCreateCFProperty(service, CFSTR("BatteryPercent"), kCFAllocatorDefault, 0);
                    if (!battRef) {
                        battRef = IORegistryEntryCreateCFProperty(service, CFSTR("BatteryPercentCombined"), kCFAllocatorDefault, 0);
                    }
                    if (battRef) {
                        NSInteger batt = [(__bridge NSNumber *)battRef integerValue];
                        CFRelease(battRef);
                        CFRelease(addrRef);
                        IOObjectRelease(service);
                        IOObjectRelease(iterator);
                        if (batt > 0 && batt <= 100) return batt;
                        break;
                    }
                }
                CFRelease(addrRef);
            }
            IOObjectRelease(service);
        }
        IOObjectRelease(iterator);
    }

    // 3. Fallback to cached battery from NSUserDefaults
    NSString *cacheKey = [kMNLastBatteryPrefix stringByAppendingString:address ?: @""];
    NSInteger cached = [[NSUserDefaults standardUserDefaults] integerForKey:cacheKey];
    if (cached > 0 && cached <= 100) {
        return cached;
    }

    return -1;
}

- (void)saveRememberedDevices:(NSArray<NSDictionary *> *)devices {
    NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
    NSMutableDictionary *current = [[defaults dictionaryForKey:kMNRememberedAccessoriesKey] mutableCopy] ?: [NSMutableDictionary dictionary];
    for (NSDictionary *dev in devices) {
        NSString *addr = dev[@"address"];
        if (addr) {
            current[addr] = dev;
            NSNumber *batt = dev[@"battery"];
            if (batt && [batt integerValue] > 0) {
                [defaults setInteger:[batt integerValue] forKey:[kMNLastBatteryPrefix stringByAppendingString:addr]];
            }
        }
    }
    [defaults setObject:current forKey:kMNRememberedAccessoriesKey];
    [defaults synchronize];
}

- (NSArray<NSDictionary<NSString *, id> *> *)rememberedAccessories {
    NSDictionary *saved = [[NSUserDefaults standardUserDefaults] dictionaryForKey:kMNRememberedAccessoriesKey];
    if (!saved || saved.count == 0) {
        return [self fetchConnectedAccessories];
    }
    return [saved allValues];
}

- (NSArray<NSDictionary<NSString *, id> *> *)fetchConnectedAccessories {
    if (self.isMockMode) {
        return [self.mockDevices copy];
    }

    NSMutableArray<NSDictionary<NSString *, id> *> *found = [NSMutableArray array];
    NSArray *paired = [IOBluetoothDevice pairedDevices] ?: @[];
    NSArray *recent = [IOBluetoothDevice recentDevices:0] ?: @[];

    NSMutableSet<NSString *> *seen = [NSMutableSet set];
    NSMutableArray *allDevices = [NSMutableArray arrayWithArray:paired];
    for (IOBluetoothDevice *dev in recent) {
        if (![allDevices containsObject:dev]) {
            [allDevices addObject:dev];
        }
    }

    for (IOBluetoothDevice *dev in allDevices) {
        NSString *addr = [dev addressString];
        if (!addr || [seen containsObject:addr]) continue;

        NSString *name = [dev name] ?: [dev addressString];
        NSString *lower = [name lowercaseString];
        BOOL isRelevant = [lower containsString:@"keyboard"] ||
                          [lower containsString:@"trackpad"] ||
                          [lower containsString:@"mouse"] ||
                          [lower containsString:@"magic"];

        if (isRelevant) {
            [seen addObject:addr];
            BOOL connected = [dev isConnected];
            NSInteger battery = MNExtractDeviceBattery(dev, addr);

            NSMutableDictionary *item = [NSMutableDictionary dictionaryWithDictionary:@{
                @"address": addr,
                @"name": name,
                @"type": [self detectDeviceType:name],
                @"connected": @(connected)
            }];

            if (battery > 0 && battery <= 100) {
                item[@"battery"] = @(battery);
            }

            [found addObject:item];
        }
    }

    [self saveRememberedDevices:found];
    return found;
}

- (void)reconnectAccessories:(nullable void(^)(BOOL success))completion {
    if (self.isMockMode) {
        if (self.delegate) [self.delegate bluetoothAccessoriesDidChange];
        if (completion) completion(YES);
        return;
    }

    NSArray *devices = [self rememberedAccessories];
    [self acquireAccessories:devices completion:^(BOOL success, NSString * _Nullable error) {
        if (completion) completion(success);
    }];
}

- (void)releaseAccessories:(NSArray<NSDictionary *> *)accessories
                completion:(void(^)(BOOL success, NSString * _Nullable error))completion {
    if (self.isMockMode) {
        for (NSMutableDictionary *d in self.mockDevices) {
            d[@"connected"] = @NO;
        }
        if (self.delegate) [self.delegate bluetoothAccessoriesDidChange];
        if (completion) completion(YES, nil);
        return;
    }

    dispatch_async(self.btQueue, ^{
        [self saveRememberedDevices:accessories];

        for (NSDictionary *info in accessories) {
            NSString *addr = info[@"address"];
            if (!addr) continue;

            IOBluetoothDevice *device = [IOBluetoothDevice deviceWithAddressString:addr];
            if (device) {
                // 1. Close connection
                if ([device isConnected]) {
                    [device closeConnection];
                    [NSThread sleepForTimeInterval:0.2];
                }

                // 2. Unpair Apple accessory so it becomes discoverable by the other Mac
                SEL removeSel = NSSelectorFromString(@"remove");
                if ([device respondsToSelector:removeSel]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
                    [device performSelector:removeSel];
#pragma clang diagnostic pop
                }
            }
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            if (self.delegate) [self.delegate bluetoothAccessoriesDidChange];
            if (completion) completion(YES, nil);
        });
    });
}

- (void)acquireAccessories:(NSArray<NSDictionary *> *)accessories
                completion:(void(^)(BOOL success, NSString * _Nullable error))completion {
    if (self.isMockMode) {
        for (NSMutableDictionary *d in self.mockDevices) {
            d[@"connected"] = @YES;
        }
        if (self.delegate) [self.delegate bluetoothAccessoriesDidChange];
        if (completion) completion(YES, nil);
        return;
    }

    dispatch_async(self.btQueue, ^{
        for (NSDictionary *info in accessories) {
            NSString *addr = info[@"address"];
            if (!addr) continue;

            IOBluetoothDevice *device = [IOBluetoothDevice deviceWithAddressString:addr];
            if (!device) {
                continue;
            }

            // Initiate pairing if not paired
            if (![device isPaired]) {
                dispatch_semaphore_t sema = dispatch_semaphore_create(0);
                MNSilentPairDelegate *pairDelegate = [[MNSilentPairDelegate alloc] init];
                [self.activeDelegates addObject:pairDelegate];

                pairDelegate.completion = ^(BOOL success) {
                    dispatch_semaphore_signal(sema);
                };

                IOBluetoothDevicePair *pair = [IOBluetoothDevicePair pairWithDevice:device];
                [pair setDelegate:pairDelegate];
                [pair start];

                // Wait up to 5 seconds for pairing
                dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
            }

            // Open connection
            if (![device isConnected]) {
                [device openConnection];
                [NSThread sleepForTimeInterval:0.3];
            }
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            if (self.delegate) [self.delegate bluetoothAccessoriesDidChange];
            if (completion) completion(YES, nil);
        });
    });
}

@end
