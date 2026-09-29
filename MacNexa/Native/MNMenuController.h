//
//  MNMenuController.h
//  MacNexa
//
//  Status bar menu controller and pairing dialog presenter.
//

#import <Cocoa/Cocoa.h>
#import "MNBluetoothManager.h"
#import "MNNetwork.h"

NS_ASSUME_NONNULL_BEGIN

@interface MNMenuController : NSObject <MNBluetoothManagerDelegate, MNNetworkDelegate>

+ (instancetype)shared;
- (void)setupMenu;

@end

NS_ASSUME_NONNULL_END
