//
//  main.m
//  MacNexa
//
//  Universal Native Entry Point - compatible across all macOS versions
//  (macOS 12, 13 Ventura, 14 Sonoma, 15 Sequoia, 16+ Tahoe)
//

#import <Cocoa/Cocoa.h>
#import "MNMenuController.h"
#import "MNNetwork.h"
#import "MNBluetoothManager.h"
#import "MNSecurity.h"

@interface MNAppDelegate : NSObject <NSApplicationDelegate>
@end

@implementation MNAppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    NSLog(@"[MacNexa] Starting MacNexa Universal Engine...");
    NSLog(@"[MacNexa] Local Node ID: %@", [MNSecurity shared].localPeerId);
    NSLog(@"[MacNexa] Local Machine Name: %@", [MNSecurity shared].localPeerName);

    // 1. Setup Status Bar Menu
    [[MNMenuController shared] setupMenu];

    // 2. Discover Accessories
    NSArray *connected = [[MNBluetoothManager shared] fetchConnectedAccessories];
    NSLog(@"[MacNexa] Detected %lu connected Magic accessory/accessories", (unsigned long)connected.count);

    // 3. Start Bonjour & TCP Listener
    [[MNNetwork shared] start];
    NSLog(@"[MacNexa] Network engine started (Bonjour + TCP port 57842)");
}

- (void)applicationWillTerminate:(NSNotification *)notification {
    NSLog(@"[MacNexa] Shutting down network engine...");
    [[MNNetwork shared] stop];
}

@end

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyAccessory];

        MNAppDelegate *delegate = [[MNAppDelegate alloc] init];
        [app setDelegate:delegate];

        [app run];
    }
    return 0;
}
