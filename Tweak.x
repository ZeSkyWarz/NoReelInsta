#import <substrate.h>
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <dlfcn.h>
#import "InstagramHeaders.h"
#import "Utils.h"
#import "fishhook.h"

// ============================================
// NoReelInsta - Fixed & Sideload-Safe Version
// 1. Fixes Sideload Login Crash (CloudKit, Keychain, AppGroup)
// 2. Removes Reels tab from navigation bar safely
// 3. Disables Reels auto-scrolling / doomscrolling
// ============================================

#define ALWAYS_HIDE_REELS_TAB YES
#define ALWAYS_DISABLE_SCROLLING YES

// ============================================
// PART 1: SIDELOAD LOGIN & ENTITLEMENTS FIX
// Fixes crash on login when sideloaded via Sideloadly / AltStore
// ============================================

static NSString *sKeychainAccessGroup = nil;
static NSURL *sFakeGroupContainerURL = nil;

static void ensureDirectoryExists(NSURL *url) {
    if (!url) return;
    if (![url checkResourceIsReachableAndReturnError:nil]) {
        [[NSFileManager defaultManager] createDirectoryAtURL:url
                                 withIntermediateDirectories:YES
                                                  attributes:nil
                                                       error:nil];
    }
}

static NSURL *getFakeGroupContainerURL(NSString *groupIdentifier) {
    if (!sFakeGroupContainerURL) {
        NSString *docs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES).firstObject;
        if (docs) {
            sFakeGroupContainerURL = [NSURL fileURLWithPath:[docs stringByAppendingPathComponent:@"FakeGroupContainers"] isDirectory:YES];
        }
    }
    NSString *identifier = groupIdentifier.length > 0 ? groupIdentifier : @"default.group";
    NSURL *fakeURL = [sFakeGroupContainerURL URLByAppendingPathComponent:identifier isDirectory:YES];
    ensureDirectoryExists(fakeURL);
    ensureDirectoryExists([fakeURL URLByAppendingPathComponent:@"Library" isDirectory:YES]);
    ensureDirectoryExists([fakeURL URLByAppendingPathComponent:@"Library/Caches" isDirectory:YES]);
    ensureDirectoryExists([fakeURL URLByAppendingPathComponent:@"Library/Preferences" isDirectory:YES]);
    return fakeURL;
}

// Rebind SecItem* functions to replace Facebook's keychain access group with the sideloaded app's own access group
static OSStatus (*orig_SecItemAdd)(CFDictionaryRef attributes, CFTypeRef *result);
static OSStatus (*orig_SecItemCopyMatching)(CFDictionaryRef query, CFTypeRef *result);
static OSStatus (*orig_SecItemUpdate)(CFDictionaryRef query, CFDictionaryRef attributesToUpdate);
static OSStatus (*orig_SecItemDelete)(CFDictionaryRef query);

static CFDictionaryRef patchSecDictionary(CFDictionaryRef dict) {
    if (!dict) return NULL;
    if (!sKeychainAccessGroup) return CFRetain(dict);
    NSDictionary *nsDict = (__bridge NSDictionary *)dict;
    if (nsDict[(__bridge id)kSecAttrAccessGroup]) {
        NSMutableDictionary *mutableDict = [nsDict mutableCopy];
        mutableDict[(__bridge id)kSecAttrAccessGroup] = sKeychainAccessGroup;
        return CFBridgingRetain(mutableDict);
    }
    return CFRetain(dict);
}

static OSStatus hooked_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    CFDictionaryRef patched = patchSecDictionary(attributes);
    OSStatus status = orig_SecItemAdd(patched, result);
    if (patched && attributes) CFRelease(patched);
    return status;
}

static OSStatus hooked_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    CFDictionaryRef patched = patchSecDictionary(query);
    OSStatus status = orig_SecItemCopyMatching(patched, result);
    if (patched && query) CFRelease(patched);
    return status;
}

static OSStatus hooked_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    CFDictionaryRef patchedQuery = patchSecDictionary(query);
    CFDictionaryRef patchedAttrs = patchSecDictionary(attributesToUpdate);
    OSStatus status = orig_SecItemUpdate(patchedQuery, patchedAttrs);
    if (patchedQuery && query) CFRelease(patchedQuery);
    if (patchedAttrs && attributesToUpdate) CFRelease(patchedAttrs);
    return status;
}

static OSStatus hooked_SecItemDelete(CFDictionaryRef query) {
    CFDictionaryRef patched = patchSecDictionary(query);
    OSStatus status = orig_SecItemDelete(patched);
    if (patched && query) CFRelease(patched);
    return status;
}

static void initKeychainFix(void) {
    NSDictionary *dummyItem = @{
        (__bridge id)kSecClass : (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrAccount : @"sideload_dummy_account",
        (__bridge id)kSecAttrService : @"sideload_dummy_service",
        (__bridge id)kSecReturnAttributes : @YES,
    };

    CFTypeRef result = NULL;
    OSStatus ret = SecItemCopyMatching((__bridge CFDictionaryRef)dummyItem, &result);
    if (ret == errSecItemNotFound) {
        ret = SecItemAdd((__bridge CFDictionaryRef)dummyItem, &result);
    }
    if (ret == errSecSuccess && result) {
        NSDictionary *resultDict = (__bridge NSDictionary *)result;
        sKeychainAccessGroup = [resultDict[(__bridge id)kSecAttrAccessGroup] copy];
        CFRelease(result);
    }

    struct rebinding rebindings[] = {
        {"SecItemAdd", (void *)hooked_SecItemAdd, (void **)&orig_SecItemAdd},
        {"SecItemCopyMatching", (void *)hooked_SecItemCopyMatching, (void **)&orig_SecItemCopyMatching},
        {"SecItemUpdate", (void *)hooked_SecItemUpdate, (void **)&orig_SecItemUpdate},
        {"SecItemDelete", (void *)hooked_SecItemDelete, (void **)&orig_SecItemDelete},
    };
    rebind_symbols(rebindings, 4);
}

// CloudKit & Sandbox Container Hooks (prevents IGCloudIDValidation SIGTRAP crash on login)
%hook CKContainer
- (id)_initWithContainerIdentifier:(id)arg1 {
    return nil;
}
- (id)_setupWithContainerID:(id)arg1 options:(id)arg2 {
    return nil;
}
%end

%hook CKEntitlements
- (id)initWithEntitlementsDict:(NSDictionary *)dict {
    if ([dict isKindOfClass:[NSDictionary class]]) {
        NSMutableDictionary *mDict = [dict mutableCopy];
        [mDict removeObjectForKey:@"com.apple.developer.icloud-container-environment"];
        [mDict removeObjectForKey:@"com.apple.developer.icloud-services"];
        return %orig([mDict copy]);
    }
    return %orig(dict);
}
%end

%hook NSFileManager
- (NSURL *)containerURLForSecurityApplicationGroupIdentifier:(NSString *)groupIdentifier {
    return getFakeGroupContainerURL(groupIdentifier);
}
%end

%hook NSUserDefaults
- (id)_initWithSuiteName:(NSString *)suiteName container:(NSURL *)container {
    if ([suiteName isKindOfClass:[NSString class]] && [suiteName hasPrefix:@"group"]) {
        NSURL *customContainer = getFakeGroupContainerURL(suiteName);
        if (customContainer) {
            return %orig(suiteName, customContainer);
        }
    }
    return %orig(suiteName, container);
}
%end

%hook FBSDKKeychainStore
- (NSString *)accessGroup {
    return sKeychainAccessGroup ?: %orig;
}
%end

%hook FBKeychainItemController
- (NSString *)accessGroup {
    return sKeychainAccessGroup ?: %orig;
}
%end

%hook UICKeyChainStore
- (NSString *)accessGroup {
    return sKeychainAccessGroup ?: %orig;
}
%end

// ============================================
// PART 2: REMOVE REELS TAB FROM NAVIGATION BAR
// ============================================

BOOL isReelsTabHidden(id surface) {
    if (!surface) return NO;
    if ([surface respondsToSelector:@selector(tabStringFromSurfaceIntent)]) {
        NSString *tabStr = [surface tabStringFromSurfaceIntent];
        if ([tabStr isKindOfClass:[NSString class]] && [tabStr isEqualToString:@"CLIPS"]) {
            return ALWAYS_HIDE_REELS_TAB;
        }
    }
    return NO;
}

NSArray *filterSurfacesWithoutReels(NSArray *surfaces) {
    if (![surfaces isKindOfClass:[NSArray class]]) return surfaces;
    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:surfaces.count];
    for (id surface in surfaces) {
        if (!isReelsTabHidden(surface)) {
            [filtered addObject:surface];
        }
    }
    if (filtered.count == 0 && surfaces.count > 0) {
        return surfaces;
    }
    return [filtered copy];
}

%hook IGTabBarControllerSwipeCoordinator
- (id)initWithSurfaces:(id)surfaces parentViewController:(id)controller enableHaptics:(_Bool)haptics launcherSet:(id)set {
    return %orig(filterSurfacesWithoutReels(surfaces), controller, haptics, set);
}
%end

static void removeReelsFromTabBarSurfaces(id self) {
    NSArray *_tabBarSurfaces = [SCIUtils getIvarForObj:self name:@"_tabBarSurfaces"];
    if ([_tabBarSurfaces isKindOfClass:[NSArray class]] && _tabBarSurfaces.count > 0) {
        NSArray *filtered = filterSurfacesWithoutReels(_tabBarSurfaces);
        if (filtered.count != _tabBarSurfaces.count) {
            [SCIUtils setIvarForObj:self name:@"_tabBarSurfaces" value:filtered];
        }
    }
}

%hook IGTabBarController
- (void)_initializeAndConfigureBarButtonsIfNeeded {
    removeReelsFromTabBarSurfaces(self);
    %orig;
    removeReelsFromTabBarSurfaces(self);
}

- (void)_createAndConfigureReelsButtonIfNeeded {
    removeReelsFromTabBarSurfaces(self);
    if (ALWAYS_HIDE_REELS_TAB) {
        return;
    }
    %orig;
}

- (void)_layoutTabBar {
    removeReelsFromTabBarSurfaces(self);
    %orig;
}

- (id)_buttonForTabBarSurface:(id)surface {
    if (isReelsTabHidden(surface)) {
        return nil;
    }
    return %orig(surface);
}
%end

// ============================================
// PART 3: DISABLE REELS AUTO-SCROLLING
// ============================================

%hook IGUnifiedVideoCollectionView
- (void)didMoveToWindow {
    %orig;
    if (ALWAYS_DISABLE_SCROLLING) {
        self.scrollEnabled = NO;
    }
}

- (void)setScrollEnabled:(BOOL)arg1 {
    if (ALWAYS_DISABLE_SCROLLING) {
        return %orig(NO);
    }
    return %orig(arg1);
}
%end

%hook _TtC19IGSundialAutoScroll19IGSundialAutoScroll
- (void)setIsEnabled:(BOOL)enabled {
    if (ALWAYS_DISABLE_SCROLLING) {
        %orig(NO);
    } else {
        %orig(enabled);
    }
}
%end

// ============================================
// PART 4: SAFE TESTFLIGHT NAG SUPPRESSION
// ============================================

%hook IGCoreRootTestFlightNagPlugin
- (void)showTestFlightNagIfNeeded { return; }
- (void)checkForTestFlightNag { return; }
- (void)presentTestFlightUpdateNag { return; }
- (void)presentTestFlightUpdateNagWithTitle:(NSString *)title message:(NSString *)message { return; }
%end

%hook IGTestFlightNagController
- (void)presentUpdateNag { return; }
- (void)presentNagWithTitle:(NSString *)title message:(NSString *)message { return; }
%end

%hook IGTestFlightUpdateNagController
- (void)presentNag { return; }
- (void)showUpdateNag { return; }
%end

%ctor {
    // Ensure InstagramAppCoreFramework is loaded if present
    NSString *coreFwPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"Frameworks/InstagramAppCoreFramework.framework/InstagramAppCoreFramework"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:coreFwPath]) {
        dlopen([coreFwPath UTF8String], RTLD_NOW);
    }
    initKeychainFix();
    %init;
}
