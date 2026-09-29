# MacNexa Bluetooth & Hardware Handoff Specification

Apple Magic peripherals (Magic Keyboard, Magic Trackpad, and Magic Mouse) do not natively support multi-host Bluetooth pairing. When paired to one Mac, an accessory will not accept pairing or connection requests from another Mac until its pairing bond is cleared.

This document describes how MacNexa programmatically orchestrates the silent release, unpairing, and acquisition of Apple accessories without requiring physical Lightning/USB-C cables or manual Bluetooth dialogs.

---

## 1. Peripheral Lifecycle Architecture

```
Current Host Mac                                               Target Host Mac
────────────────                                               ───────────────
1. Fetch Connected Devices
   [IOBluetoothDevice pairedDevices]
   Extract Battery via IOKit
               │
               ▼
2. Drop Active Connection
   [device closeConnection]
               │
               ▼
3. Unpair Apple Accessory
   [device performSelector:@"remove"]
   (Device enters discoverable advertising)
               │
               ▼
4. Send Encrypted Handoff Frame ──────────────────────────────> 5. Receive Handover Payload
                                                                   Target extracts MAC addresses
                                                                               │
                                                                               ▼
                                                                6. Initiate Silent Pairing
                                                                   IOBluetoothDevicePair
                                                                   replyUserConfirmation(YES)
                                                                               │
                                                                               ▼
                                                                7. Establish HID Connection
                                                                   [device openConnection]
```

---

## 2. Technical Mechanisms

### 2.1. Accessory Unpairing (`remove`)
To make an Apple Magic accessory discoverable by another Mac without physical user interaction (such as toggling the hardware power switch or connecting a cable), MacNexa invokes the private selector:
```objc
SEL removeSel = NSSelectorFromString(@"remove");
if ([device respondsToSelector:removeSel]) {
    [device performSelector:removeSel];
}
```
This clears the link key from the local Bluetooth controller's persistent NVRAM database and signals the peripheral to re-enter discoverable pairing mode.

### 2.2. Persistent Device Cache (`com.macnexa.remembered_accessories`)
Because unpairing removes the device from `[IOBluetoothDevice pairedDevices]`, MacNexa automatically caches device metadata (MAC address, device name, device type, last known battery level) in `NSUserDefaults`:
- When switching back, the Mac can immediately re-address the device by MAC string:
  ```objc
  IOBluetoothDevice *device = [IOBluetoothDevice deviceWithAddressString:savedAddress];
  ```

### 2.3. Silent Secure Simple Pairing (SSP)
Normally, pairing an unbonded accessory causes macOS to display a system notification or numeric confirmation dialog. MacNexa eliminates these prompts by implementing an `IOBluetoothDevicePairDelegate`:
```objc
@interface MNSilentPairDelegate : NSObject <IOBluetoothDevicePairDelegate>
@end

@implementation MNSilentPairDelegate
- (void)devicePairingUserConfirmationRequest:(id)sender numericValue:(BluetoothNumericValue)numericValue {
    // Automatically reply YES to confirm Bluetooth SSP silently
    if ([sender respondsToSelector:@selector(replyUserConfirmation:)]) {
        [sender performSelector:@selector(replyUserConfirmation:) withObject:(id)kCFBooleanTrue];
    }
}
@end
```

### 2.4. Real-Time Battery Monitoring
MacNexa continuously monitors battery percentages using a dual-layered approach:
1. **IOBluetooth Device Methods**:
   Calls `batteryPercentSingle` and `batteryPercentCombined` on `IOBluetoothDevice`.
2. **IOKit HID Event Service**:
   Inspects `AppleDeviceManagementHIDEventService` matching on `DeviceAddress` and extracts `BatteryPercent` / `BatteryPercentCombined`.
3. **Battery Caching**:
   Last observed battery levels are cached in `NSUserDefaults` (`com.macnexa.last_battery.<address>`) so percentages remain visible even during momentary disconnects.

---

## 3. Supported Devices

| Device | Model Numbers | Detection Type | Silent Handoff Supported |
| :--- | :--- | :--- | :--- |
| **Magic Keyboard** | A1644, A2449, A2450 (with Touch ID) | `keyboard` | Yes |
| **Magic Keyboard with Numeric Keypad** | A1843, A2520 (with Touch ID) | `keyboard` | Yes |
| **Magic Trackpad** | A1535, A3123 (USB-C) | `trackpad` | Yes |
| **Magic Mouse** | A1657, A3122 (USB-C) | `mouse` | Yes |

---

## 4. Hardware Verification & Diagnostics

To check currently connected Bluetooth accessories and battery status from the command line:

```bash
# View live MacNexa console logs:
./run.sh --logs

# View macOS Bluetooth profile details:
system_profiler SPBluetoothDataType
```
