//
//  MNMenuController.m
//  MacNexa
//

#import "MNMenuController.h"
#import "MNSecurity.h"
#import "MNBluetoothManager.h"
#import "MNNetwork.h"

@interface MNMenuController () <NSMenuDelegate>
@property (nonatomic, strong) NSStatusItem *statusItem;
@property (nonatomic, strong) NSMenu *menu;
@property (nonatomic, copy) NSString *currentStatusText;
@end

@implementation MNMenuController

+ (instancetype)shared {
    static MNMenuController *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[MNMenuController alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _currentStatusText = @"Ready";
        [MNBluetoothManager shared].delegate = self;
        [MNNetwork shared].delegate = self;
    }
    return self;
}

- (void)setupMenu {
    self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
    self.statusItem.button.toolTip = @"MacNexa - Seamless Magic Accessory Switcher";

    if (@available(macOS 11.0, *)) {
        NSImage *img = [NSImage imageWithSystemSymbolName:@"keyboard" accessibilityDescription:@"MacNexa"];
        if (img) {
            [img setTemplate:YES];
            self.statusItem.button.image = img;
            self.statusItem.button.title = @"";
        } else {
            self.statusItem.button.title = @"⌨️";
        }
    } else {
        self.statusItem.button.title = @"⌨️";
    }

    self.menu = [[NSMenu alloc] initWithTitle:@"MacNexa"];
    self.menu.delegate = self;
    self.statusItem.menu = self.menu;

    [self rebuildMenu];
}

- (void)menuWillOpen:(NSMenu *)menu {
    [self rebuildMenu];
}

- (void)rebuildMenu {
    [self.menu removeAllItems];

    // Status Header
    NSMenuItem *header = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"MacNexa: %@", self.currentStatusText]
                                                    action:nil
                                             keyEquivalent:@""];
    header.enabled = NO;
    [self.menu addItem:header];
    [self.menu addItem:[NSMenuItem separatorItem]];

    // Storage Error Warning Banner (if any)
    if ([MNSecurity shared].lastStorageError) {
        NSError *err = [MNSecurity shared].lastStorageError;
        NSString *warnTitle = [NSString stringWithFormat:@"⚠️ Storage Warning: %@", err.localizedDescription];
        if (warnTitle.length > 45) {
            warnTitle = [[warnTitle substringToIndex:42] stringByAppendingString:@"..."];
        }
        NSMenuItem *warnItem = [[NSMenuItem alloc] initWithTitle:warnTitle
                                                          action:@selector(handleStorageWarningAlert)
                                                   keyEquivalent:@""];
        warnItem.target = self;
        [self.menu addItem:warnItem];
        [self.menu addItem:[NSMenuItem separatorItem]];
    }

    // 1. Connected Accessories with Battery Percentage
    NSArray *connected = [[MNBluetoothManager shared] fetchConnectedAccessories];
    if (connected.count == 0) {
        connected = [[MNBluetoothManager shared] rememberedAccessories];
    }

    NSUInteger activeCount = 0;
    for (NSDictionary *d in connected) {
        if ([d[@"connected"] boolValue]) activeCount++;
    }

    NSMenuItem *accHeader = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"Accessories (%lu active):", (unsigned long)activeCount]
                                                       action:nil
                                                keyEquivalent:@""];
    accHeader.enabled = NO;
    [self.menu addItem:accHeader];

    if (connected.count == 0) {
        NSMenuItem *none = [[NSMenuItem alloc] initWithTitle:@"  No Magic accessories found" action:nil keyEquivalent:@""];
        none.enabled = NO;
        [self.menu addItem:none];
    } else {
        for (NSDictionary *dev in connected) {
            NSString *icon = [dev[@"type"] isEqualToString:@"keyboard"] ? @"⌨️" : @"🖱️";
            BOOL isConn = [dev[@"connected"] boolValue];
            NSNumber *batt = dev[@"battery"];

            NSString *battStr = @"";
            if (batt && [batt integerValue] > 0) {
                NSInteger b = [batt integerValue];
                NSString *bIcon = (b < 20) ? @"🪫" : @"🔋";
                battStr = [NSString stringWithFormat:@"  %@ %ld%%", bIcon, (long)b];
            }

            NSString *statusStr = isConn ? @"" : @" (Disconnected)";
            NSString *title = [NSString stringWithFormat:@"  %@ %@%@%@", icon, dev[@"name"], battStr, statusStr];

            NSMenuItem *devItem = [[NSMenuItem alloc] initWithTitle:title action:nil keyEquivalent:@""];
            devItem.enabled = NO;
            [self.menu addItem:devItem];
        }

        NSMenuItem *reconnItem = [[NSMenuItem alloc] initWithTitle:@"  ⚡ Connect / Reconnect Accessories"
                                                            action:@selector(handleReconnectAccessories)
                                                     keyEquivalent:@""];
        reconnItem.target = self;
        [self.menu addItem:reconnItem];
    }

    [self.menu addItem:[NSMenuItem separatorItem]];

    // 2. Switch to Paired Macs
    NSArray<NSDictionary *> *trusted = [[MNSecurity shared] allTrustedPeers];
    NSMenuItem *switchHeader = [[NSMenuItem alloc] initWithTitle:@"Switch to:" action:nil keyEquivalent:@""];
    switchHeader.enabled = NO;
    [self.menu addItem:switchHeader];

    if (trusted.count == 0) {
        NSMenuItem *noPeers = [[NSMenuItem alloc] initWithTitle:@"  No paired Macs yet" action:nil keyEquivalent:@""];
        noPeers.enabled = NO;
        [self.menu addItem:noPeers];
    } else {
        for (NSDictionary *peer in trusted) {
            NSString *peerId = peer[@"id"];
            NSString *peerName = peer[@"name"];

            // Check if online via Bonjour
            BOOL isOnline = NO;
            for (NSDictionary *discovered in [MNNetwork shared].discoveredPeers) {
                if ([discovered[@"id"] isEqualToString:peerId]) {
                    isOnline = YES;
                    break;
                }
            }

            NSString *title = [NSString stringWithFormat:@"  🔄 Switch to %@%@", peerName, isOnline ? @" (Online)" : @" (Offline)"];
            NSMenuItem *peerItem = [[NSMenuItem alloc] initWithTitle:title
                                                              action:@selector(handleSwitchToPeer:)
                                                       keyEquivalent:@""];
            peerItem.target = self;
            peerItem.representedObject = peerId;
            peerItem.enabled = isOnline;

            // Submenu with quick switch and unpair/forget options
            NSMenu *peerSubmenu = [[NSMenu alloc] initWithTitle:peerName];
            NSMenuItem *subSwitch = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"Switch Peripherals to %@", peerName]
                                                               action:@selector(handleSwitchToPeer:)
                                                        keyEquivalent:@""];
            subSwitch.target = self;
            subSwitch.representedObject = peerId;
            subSwitch.enabled = isOnline;
            [peerSubmenu addItem:subSwitch];

            NSMenuItem *unpairAction = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"Unpair / Forget %@", peerName]
                                                                  action:@selector(handleUnpairPeer:)
                                                           keyEquivalent:@""];
            unpairAction.target = self;
            unpairAction.representedObject = peerId;
            [peerSubmenu addItem:unpairAction];

            peerItem.submenu = peerSubmenu;
            [self.menu addItem:peerItem];
        }
    }

    [self.menu addItem:[NSMenuItem separatorItem]];

    // 3. Discovered Macs to Pair
    NSArray<NSDictionary *> *discovered = [MNNetwork shared].discoveredPeers;
    NSMutableArray<NSDictionary *> *unpaired = [NSMutableArray array];
    for (NSDictionary *d in discovered) {
        if (![[MNSecurity shared] isPeerTrusted:d[@"id"]]) {
            [unpaired addObject:d];
        }
    }

    NSMenuItem *pairSubmenuItem = [[NSMenuItem alloc] initWithTitle:@"Pair New Mac" action:nil keyEquivalent:@""];
    NSMenu *pairMenu = [[NSMenu alloc] initWithTitle:@"Pair New Mac"];

    if (unpaired.count == 0) {
        NSMenuItem *searching = [[NSMenuItem alloc] initWithTitle:@"Searching for nearby Macs..." action:nil keyEquivalent:@""];
        searching.enabled = NO;
        [pairMenu addItem:searching];
    } else {
        for (NSDictionary *p in unpaired) {
            NSMenuItem *pItem = [[NSMenuItem alloc] initWithTitle:[NSString stringWithFormat:@"Pair with %@", p[@"name"]]
                                                           action:@selector(handlePairWithPeer:)
                                                    keyEquivalent:@""];
            pItem.target = self;
            pItem.representedObject = p;
            [pairMenu addItem:pItem];
        }
    }
    pairSubmenuItem.submenu = pairMenu;
    [self.menu addItem:pairSubmenuItem];

    [self.menu addItem:[NSMenuItem separatorItem]];

    // 4. Refresh & Quit
    NSMenuItem *refreshItem = [[NSMenuItem alloc] initWithTitle:@"Refresh Devices & Network"
                                                         action:@selector(handleRefresh)
                                                  keyEquivalent:@"r"];
    refreshItem.target = self;
    [self.menu addItem:refreshItem];

    NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:@"Quit MacNexa"
                                                      action:@selector(handleQuit)
                                               keyEquivalent:@"q"];
    quitItem.target = self;
    [self.menu addItem:quitItem];
}

#pragma mark - Actions

- (void)handleSwitchToPeer:(NSMenuItem *)sender {
    NSString *peerId = sender.representedObject;
    if (!peerId) return;

    self.currentStatusText = @"Switching...";

    [[MNNetwork shared] switchToPeer:peerId completion:^(BOOL success, NSString * _Nullable error) {
        self.currentStatusText = success ? @"Switch Completed!" : @"Switch Failed";
        [self rebuildMenu];

        if (!success && error) {
            NSAlert *alert = [[NSAlert alloc] init];
            alert.messageText = @"MacNexa Switch Failed";
            alert.informativeText = error;
            [alert runModal];
        }
    }];
}

- (void)handlePairWithPeer:(NSMenuItem *)sender {
    NSDictionary *peer = sender.representedObject;
    if (!peer) return;

    [[MNNetwork shared] pairWithPeer:peer completion:^(BOOL success, NSString * _Nullable error) {
        if (success) {
            NSAlert *alert = [[NSAlert alloc] init];
            alert.messageText = @"Pairing Successful!";
            alert.informativeText = [NSString stringWithFormat:@"You are now securely paired with %@. You can switch accessories at any time!", peer[@"name"]];
            [alert runModal];
        } else if (error) {
            NSAlert *alert = [[NSAlert alloc] init];
            alert.messageText = @"Pairing Failed";
            alert.informativeText = error;
            [alert runModal];
        }
        [self rebuildMenu];
    }];
}

- (void)handleReconnectAccessories {
    self.currentStatusText = @"Connecting accessories...";
    [self rebuildMenu];

    [[MNBluetoothManager shared] reconnectAccessories:^(BOOL success) {
        self.currentStatusText = success ? @"Ready" : @"Connection Failed";
        [self rebuildMenu];
    }];
}

- (void)handleRefresh {
    [[MNBluetoothManager shared] fetchConnectedAccessories];
    [self rebuildMenu];
}

- (void)handleUnpairPeer:(NSMenuItem *)sender {
    NSString *peerId = sender.representedObject;
    if (!peerId) return;

    NSDictionary *info = [[MNSecurity shared] trustedPeerInfo:peerId];
    NSString *peerName = info[@"name"] ?: @"Mac";

    [NSApp activateIgnoringOtherApps:YES];
    NSAlert *confirmAlert = [[NSAlert alloc] init];
    confirmAlert.messageText = [NSString stringWithFormat:@"Unpair %@?", peerName];
    confirmAlert.informativeText = @"MacNexa will securely delete the stored cryptographic keys for this device. You will need to pair again to switch peripherals.";
    [confirmAlert addButtonWithTitle:@"Unpair"];
    [confirmAlert addButtonWithTitle:@"Cancel"];

    if ([confirmAlert runModal] == NSAlertFirstButtonReturn) {
        NSError *unpairError = nil;
        BOOL ok = [[MNSecurity shared] removeTrustedPeerId:peerId error:&unpairError];
        if (!ok) {
            NSAlert *errAlert = [[NSAlert alloc] init];
            errAlert.messageText = @"Unpairing Storage Error";
            errAlert.informativeText = [NSString stringWithFormat:@"Could not delete secret from disk: %@\n\n%@",
                                        unpairError.localizedDescription,
                                        unpairError.localizedRecoverySuggestion ?: @""];
            [errAlert runModal];
        } else {
            [self rebuildMenu];
        }
    }
}

- (void)handleStorageWarningAlert {
    NSError *err = [MNSecurity shared].lastStorageError;
    if (!err) return;

    [NSApp activateIgnoringOtherApps:YES];
    NSAlert *alert = [[NSAlert alloc] init];
    alert.messageText = @"MacNexa Storage Warning";
    alert.informativeText = [NSString stringWithFormat:@"%@\n\nSuggestion:\n%@",
                             err.localizedDescription,
                             err.localizedRecoverySuggestion ?: @"Check disk permissions or re-pair devices."];
    [alert addButtonWithTitle:@"Dismiss"];
    [alert addButtonWithTitle:@"Open Storage Folder"];

    NSInteger resp = [alert runModal];
    if (resp == NSAlertSecondButtonReturn) {
        NSString *dir = [@"~/Library/Application Support/MacNexa" stringByExpandingTildeInPath];
        [[NSWorkspace sharedWorkspace] openURL:[NSURL fileURLWithPath:dir]];
    }
    [[MNSecurity shared] clearLastStorageError];
    [self rebuildMenu];
}

- (void)handleQuit {
    [NSApp terminate:nil];
}

#pragma mark - Delegate Callbacks

- (void)bluetoothAccessoriesDidChange {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self rebuildMenu];
    });
}

- (void)networkPeersDidChange {
    dispatch_async(dispatch_get_main_queue(), ^{
        [self rebuildMenu];
    });
}

- (void)networkDidReceivePairingRequestFromPeer:(NSString *)peerName
                                          code:(NSString *)code
                                    completion:(void(^)(BOOL accepted))completion {
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSApp activateIgnoringOtherApps:YES];

        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = @"MacNexa Security Verification";
        alert.informativeText = [NSString stringWithFormat:
            @"Pairing verification for: %@\n\n"
            @"Do the 6 digits match on both screens?\n\n"
            @"       [  %@  ]\n\n"
            @"Click Confirm to establish a secure, encrypted trust relationship.",
            peerName, code];
        [alert addButtonWithTitle:@"Confirm & Trust"];
        [alert addButtonWithTitle:@"Cancel"];

        NSInteger response = [alert runModal];
        completion(response == NSAlertFirstButtonReturn);
        [self rebuildMenu];
    });
}

- (void)networkSwitchDidStartWithPeer:(NSString *)peerName isOutgoing:(BOOL)isOutgoing {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.currentStatusText = isOutgoing ?
            [NSString stringWithFormat:@"Sending to %@...", peerName] :
            [NSString stringWithFormat:@"Receiving from %@...", peerName];
        [self rebuildMenu];
    });
}

- (void)networkSwitchDidCompleteWithPeer:(NSString *)peerName success:(BOOL)success error:(nullable NSString *)error {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.currentStatusText = success ? @"Ready" : @"Switch Failed";
        [self rebuildMenu];
    });
}

@end
