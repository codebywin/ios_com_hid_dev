//
//  Tweak.x - com.hid.dev (HideDeveloperMode)
//  Tương thích: iOS 16.0 - 16.7.x (RootHide Dopamine / Rootless)
//  Chức năng: Đánh lừa 100% các lớp phòng thủ của ngân hàng (ACB, Techcombank, VNeID...)
//             rằng Chế độ nhà phát triển (Developer Mode) đã TẮT HOÀN TOÀN (0)
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <substrate.h>
#import <dlfcn.h>
#import <CoreFoundation/CoreFoundation.h>
#import <sys/stat.h>
#import <unistd.h>
#import <errno.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"

// ============================================================================
// 1. C Hooks: AMFI (Apple Mobile File Integrity) APIs
// ============================================================================

static int (*orig_amfi_get_developer_mode_status)(void) = NULL;
static int fake_amfi_get_developer_mode_status(void) {
    return 0; // Luôn trả về 0: Developer Mode ĐÃ TẮT
}

static int (*orig_amfi_developer_mode_status)(void) = NULL;
static int fake_amfi_developer_mode_status(void) {
    return 0;
}

static int (*orig_amfi_developer_mode_enabled)(void) = NULL;
static int fake_amfi_developer_mode_enabled(void) {
    return 0;
}

// ============================================================================
// 2. C Hooks: POSIX File System (Chống quét file plist bằng C mức thấp)
// ============================================================================

static int (*orig_access)(const char *path, int mode) = NULL;
static int fake_access(const char *path, int mode) {
    if (path && strstr(path, "com.apple.security.developer-mode")) {
        errno = ENOENT;
        return -1;
    }
    return orig_access ? orig_access(path, mode) : -1;
}

static int (*orig_stat)(const char *path, struct stat *buf) = NULL;
static int fake_stat(const char *path, struct stat *buf) {
    if (path && strstr(path, "com.apple.security.developer-mode")) {
        errno = ENOENT;
        return -1;
    }
    return orig_stat ? orig_stat(path, buf) : -1;
}

static int (*orig_lstat)(const char *path, struct stat *buf) = NULL;
static int fake_lstat(const char *path, struct stat *buf) {
    if (path && strstr(path, "com.apple.security.developer-mode")) {
        errno = ENOENT;
        return -1;
    }
    return orig_lstat ? orig_lstat(path, buf) : -1;
}

// ============================================================================
// 3. C Hooks: CoreFoundation Preferences (CFPreferences)
// ============================================================================

static CFPropertyListRef (*orig_CFPreferencesCopyAppValue)(CFStringRef key, CFStringRef applicationID) = NULL;
static CFPropertyListRef fake_CFPreferencesCopyAppValue(CFStringRef key, CFStringRef applicationID) {
    if (applicationID && CFStringCompare(applicationID, CFSTR("com.apple.security.developer-mode"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
        return (CFPropertyListRef)kCFBooleanFalse;
    }
    if (key && (CFStringCompare(key, CFSTR("DeveloperModeStatus"), kCFCompareCaseInsensitive) == kCFCompareEqualTo ||
                CFStringCompare(key, CFSTR("developer-mode-status"), kCFCompareCaseInsensitive) == kCFCompareEqualTo)) {
        return (CFPropertyListRef)kCFBooleanFalse;
    }
    return orig_CFPreferencesCopyAppValue ? orig_CFPreferencesCopyAppValue(key, applicationID) : NULL;
}

static CFPropertyListRef (*orig_CFPreferencesCopyValue)(CFStringRef key, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName) = NULL;
static CFPropertyListRef fake_CFPreferencesCopyValue(CFStringRef key, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName) {
    if (applicationID && CFStringCompare(applicationID, CFSTR("com.apple.security.developer-mode"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
        return (CFPropertyListRef)kCFBooleanFalse;
    }
    if (key && (CFStringCompare(key, CFSTR("DeveloperModeStatus"), kCFCompareCaseInsensitive) == kCFCompareEqualTo ||
                CFStringCompare(key, CFSTR("developer-mode-status"), kCFCompareCaseInsensitive) == kCFCompareEqualTo)) {
        return (CFPropertyListRef)kCFBooleanFalse;
    }
    return orig_CFPreferencesCopyValue ? orig_CFPreferencesCopyValue(key, applicationID, userName, hostName) : NULL;
}

static Boolean (*orig_CFPreferencesGetAppBooleanValue)(CFStringRef key, CFStringRef applicationID, Boolean *keyExistsAndHasValidFormat) = NULL;
static Boolean fake_CFPreferencesGetAppBooleanValue(CFStringRef key, CFStringRef applicationID, Boolean *keyExistsAndHasValidFormat) {
    if (applicationID && CFStringCompare(applicationID, CFSTR("com.apple.security.developer-mode"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
        if (keyExistsAndHasValidFormat) *keyExistsAndHasValidFormat = true;
        return false;
    }
    if (key && (CFStringCompare(key, CFSTR("DeveloperModeStatus"), kCFCompareCaseInsensitive) == kCFCompareEqualTo ||
                CFStringCompare(key, CFSTR("developer-mode-status"), kCFCompareCaseInsensitive) == kCFCompareEqualTo)) {
        if (keyExistsAndHasValidFormat) *keyExistsAndHasValidFormat = true;
        return false;
    }
    return orig_CFPreferencesGetAppBooleanValue ? orig_CFPreferencesGetAppBooleanValue(key, applicationID, keyExistsAndHasValidFormat) : false;
}

static CFIndex (*orig_CFPreferencesGetAppIntegerValue)(CFStringRef key, CFStringRef applicationID, Boolean *keyExistsAndHasValidFormat) = NULL;
static CFIndex fake_CFPreferencesGetAppIntegerValue(CFStringRef key, CFStringRef applicationID, Boolean *keyExistsAndHasValidFormat) {
    if (applicationID && CFStringCompare(applicationID, CFSTR("com.apple.security.developer-mode"), kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
        if (keyExistsAndHasValidFormat) *keyExistsAndHasValidFormat = true;
        return 0;
    }
    if (key && (CFStringCompare(key, CFSTR("DeveloperModeStatus"), kCFCompareCaseInsensitive) == kCFCompareEqualTo ||
                CFStringCompare(key, CFSTR("developer-mode-status"), kCFCompareCaseInsensitive) == kCFCompareEqualTo)) {
        if (keyExistsAndHasValidFormat) *keyExistsAndHasValidFormat = true;
        return 0;
    }
    return orig_CFPreferencesGetAppIntegerValue ? orig_CFPreferencesGetAppIntegerValue(key, applicationID, keyExistsAndHasValidFormat) : 0;
}

// ============================================================================
// 4. C Hooks: Security Framework (Spoof get-task-allow / Chống phát hiện debug)
// ============================================================================

static CFTypeRef (*orig_SecTaskCopyValueForEntitlement)(void *task, CFStringRef entitlement, CFErrorRef *error) = NULL;
static CFTypeRef fake_SecTaskCopyValueForEntitlement(void *task, CFStringRef entitlement, CFErrorRef *error) {
    if (entitlement && CFEqual(entitlement, CFSTR("get-task-allow"))) {
        if (error) *error = NULL;
        return (CFTypeRef)kCFBooleanFalse;
    }
    return orig_SecTaskCopyValueForEntitlement ? orig_SecTaskCopyValueForEntitlement(task, entitlement, error) : NULL;
}

// ============================================================================
// 5. Objective-C Hooks: NSFileManager & NSUserDefaults
// ============================================================================

%hook NSFileManager

- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path && [path containsString:@"com.apple.security.developer-mode"]) {
        return NO;
    }
    return %orig;
}

- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDirectory {
    if (path && [path containsString:@"com.apple.security.developer-mode"]) {
        if (isDirectory) *isDirectory = NO;
        return NO;
    }
    return %orig;
}

%end

%hook NSUserDefaults

- (id)objectForKey:(NSString *)defaultName {
    if (defaultName && ([defaultName localizedCaseInsensitiveContainsString:@"developer-mode"] ||
                        [defaultName localizedCaseInsensitiveContainsString:@"DeveloperModeStatus"])) {
        return @(NO);
    }
    return %orig;
}

- (BOOL)boolForKey:(NSString *)defaultName {
    if (defaultName && ([defaultName localizedCaseInsensitiveContainsString:@"developer-mode"] ||
                        [defaultName localizedCaseInsensitiveContainsString:@"DeveloperModeStatus"])) {
        return NO;
    }
    return %orig;
}

- (NSInteger)integerForKey:(NSString *)defaultName {
    if (defaultName && ([defaultName localizedCaseInsensitiveContainsString:@"developer-mode"] ||
                        [defaultName localizedCaseInsensitiveContainsString:@"DeveloperModeStatus"])) {
        return 0;
    }
    return %orig;
}

%end

// ============================================================================
// 6. Constructor Khởi Tạo An Toàn
// ============================================================================

%ctor {
    @autoreleasepool {
        NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
        // Tuyệt đối không hook vào SpringBoard / Daemons hệ thống để đảm bảo tính ổn định
        if (!bundleID || 
            [bundleID hasPrefix:@"com.apple.springboard"] ||
            [bundleID hasPrefix:@"com.apple.backboardd"] ||
            [bundleID hasPrefix:@"com.apple.mediaserverd"]) {
            return;
        }

        // 1. Hook AMFI APIs trong libSystem & libamfi
        void *libamfi = dlopen("/usr/lib/libamfi.dylib", RTLD_NOW | RTLD_GLOBAL);
        if (!libamfi) {
            libamfi = dlopen("/System/Library/PrivateFrameworks/AppleMobileFileIntegrity.framework/AppleMobileFileIntegrity", RTLD_NOW | RTLD_GLOBAL);
        }

        void *sym1 = dlsym(RTLD_DEFAULT, "amfi_get_developer_mode_status");
        if (!sym1 && libamfi) sym1 = dlsym(libamfi, "amfi_get_developer_mode_status");
        if (sym1) {
            MSHookFunction(sym1, (void *)&fake_amfi_get_developer_mode_status, (void **)&orig_amfi_get_developer_mode_status);
        }

        void *sym2 = dlsym(RTLD_DEFAULT, "amfi_developer_mode_status");
        if (!sym2 && libamfi) sym2 = dlsym(libamfi, "amfi_developer_mode_status");
        if (sym2) {
            MSHookFunction(sym2, (void *)&fake_amfi_developer_mode_status, (void **)&orig_amfi_developer_mode_status);
        }

        void *sym3 = dlsym(RTLD_DEFAULT, "amfi_developer_mode_enabled");
        if (!sym3 && libamfi) sym3 = dlsym(libamfi, "amfi_developer_mode_enabled");
        if (sym3) {
            MSHookFunction(sym3, (void *)&fake_amfi_developer_mode_enabled, (void **)&orig_amfi_developer_mode_enabled);
        }

        // 2. Hook POSIX File System APIs
        void *symAccess = dlsym(RTLD_DEFAULT, "access");
        if (symAccess) {
            MSHookFunction(symAccess, (void *)&fake_access, (void **)&orig_access);
        }

        void *symStat = dlsym(RTLD_DEFAULT, "stat");
        if (!symStat) symStat = dlsym(RTLD_DEFAULT, "stat$INODE64");
        if (symStat) {
            MSHookFunction(symStat, (void *)&fake_stat, (void **)&orig_stat);
        }

        void *symLstat = dlsym(RTLD_DEFAULT, "lstat");
        if (!symLstat) symLstat = dlsym(RTLD_DEFAULT, "lstat$INODE64");
        if (symLstat) {
            MSHookFunction(symLstat, (void *)&fake_lstat, (void **)&orig_lstat);
        }

        // 3. Hook CoreFoundation Preferences
        void *symPref = dlsym(RTLD_DEFAULT, "CFPreferencesCopyAppValue");
        if (symPref) {
            MSHookFunction(symPref, (void *)&fake_CFPreferencesCopyAppValue, (void **)&orig_CFPreferencesCopyAppValue);
        }

        void *symPrefVal = dlsym(RTLD_DEFAULT, "CFPreferencesCopyValue");
        if (symPrefVal) {
            MSHookFunction(symPrefVal, (void *)&fake_CFPreferencesCopyValue, (void **)&orig_CFPreferencesCopyValue);
        }

        void *symPrefBool = dlsym(RTLD_DEFAULT, "CFPreferencesGetAppBooleanValue");
        if (symPrefBool) {
            MSHookFunction(symPrefBool, (void *)&fake_CFPreferencesGetAppBooleanValue, (void **)&orig_CFPreferencesGetAppBooleanValue);
        }

        void *symPrefInt = dlsym(RTLD_DEFAULT, "CFPreferencesGetAppIntegerValue");
        if (symPrefInt) {
            MSHookFunction(symPrefInt, (void *)&fake_CFPreferencesGetAppIntegerValue, (void **)&orig_CFPreferencesGetAppIntegerValue);
        }

        // 4. Hook Security Entitlements (get-task-allow)
        void *symSecTask = dlsym(RTLD_DEFAULT, "SecTaskCopyValueForEntitlement");
        if (symSecTask) {
            MSHookFunction(symSecTask, (void *)&fake_SecTaskCopyValueForEntitlement, (void **)&orig_SecTaskCopyValueForEntitlement);
        }
    }
}
