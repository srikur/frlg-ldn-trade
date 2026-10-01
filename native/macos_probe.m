// Native macOS LDN feasibility probe. Queries only; no capture or radio setters.
// Build: make mac-probe
// Run:   ./build/macos-probe --interface en0 [--private]
// A BPF permission error is inconclusive. Rerun with sudo in a local terminal.
#import <Foundation/Foundation.h>
#import <CoreWLAN/CoreWLAN.h>
#import <IOKit/IOKitLib.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <errno.h>
#include <net/if.h>
#include <pcap/pcap.h>
#include <sys/utsname.h>
#include <unistd.h>

static NSString *stringProperty(io_registry_entry_t entry, CFStringRef key) {
    id value = CFBridgingRelease(IORegistryEntryCreateCFProperty(
        entry, key, kCFAllocatorDefault, 0));
    return [value isKindOfClass:NSString.class] ? value : nil;
}

// Follow the selected interface, rather than guessing from installed drivers.
// Report class/bundle names only, never addresses, serials, SSIDs, or IPs.
static NSArray *driverAncestry(const char *interface) {
    NSMutableArray *result = [NSMutableArray array];
    io_registry_entry_t entry = IOServiceGetMatchingService(kIOMainPortDefault,
        IOBSDNameMatching(kIOMainPortDefault, 0, interface));
    for (unsigned depth = 0; entry && depth < 16; ++depth) {
        NSString *userClass = stringProperty(entry, CFSTR("IOUserClass"));
        NSString *bundle = stringProperty(entry, CFSTR("CFBundleIdentifier"));
        NSString *server = stringProperty(entry, CFSTR("IOUserServerName"));
        NSString *identity = [NSString stringWithFormat:@"%@ %@ %@",
            userClass ?: @"", bundle ?: @"", server ?: @""];
        BOOL wireless = NO;
        for (NSString *term in @[@"WLAN", @"80211", @"Centauri"]) {
            if ([identity rangeOfString:term options:NSCaseInsensitiveSearch].location != NSNotFound)
                wireless = YES;
        }
        if (wireless) {
            NSMutableDictionary *item = [NSMutableDictionary dictionary];
            if (userClass) item[@"user_class"] = userClass;
            if (bundle) item[@"bundle"] = bundle;
            if (server) item[@"server"] = server;
            [result addObject:item];
        }
        io_registry_entry_t parent = IO_OBJECT_NULL;
        kern_return_t status = IORegistryEntryGetParentEntry(entry, kIOServicePlane, &parent);
        IOObjectRelease(entry);
        entry = status == KERN_SUCCESS ? parent : IO_OBJECT_NULL;
    }
    if (entry) IOObjectRelease(entry);
    return result;
}

static NSDictionary *monitorQuery(const char *interface) {
    char error[PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = pcap_create(interface, error);
    if (!handle) return @{@"status": @"error", @"error": @(error)};
    // Does not call pcap_set_rfmon, pcap_activate, pcap_next, or pcap_inject.
    int code = pcap_can_set_rfmon(handle);
    NSString *status = code == 1 ? @"advertised" : code == 0 ? @"not_advertised" : @"error";
    NSDictionary *result = @{
        @"status": status, @"can_set_rfmon": @(code),
        @"error": code < 0 ? @(pcap_geterr(handle)) : @"",
        @"meaning": @"An advertised mode does not prove usable reception or transmission."
    };
    pcap_close(handle);
    return result;
}

// Only test Open/Bind/Close using the established Apple80211 handle ABI.
// Bind selects an interface for this handle; it does not associate to an AP.
// No generic Get, Set, scan, key lookup, or association request is issued.
static NSDictionary *privateQuery(NSString *interface) {
    const char *path = "/System/Library/PrivateFrameworks/Apple80211.framework/Apple80211";
    void *library = dlopen(path, RTLD_LAZY | RTLD_LOCAL);
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    result[@"apple80211_loaded"] = @(library != NULL);
    if (library) {
        int (*openHandle)(void **) = dlsym(library, "Apple80211Open");
        int (*bindHandle)(void *, CFStringRef) = dlsym(library, "Apple80211BindToInterface");
        int (*closeHandle)(void *) = dlsym(library, "Apple80211Close");
        NSMutableArray *symbols = [NSMutableArray array];
        for (NSString *name in @[@"Apple80211Open", @"Apple80211BindToInterface",
                @"Apple80211Close", @"Apple80211Get", @"Apple80211Set", @"Apple80211Associate"]) {
            if (dlsym(library, name.UTF8String)) [symbols addObject:name];
        }
        result[@"exported_symbols"] = symbols;
        if (openHandle && bindHandle && closeHandle) {
            void *handle = NULL;
            int status = openHandle(&handle);
            result[@"open_status"] = @(status);
            if (status == 0 && handle) {
                errno = 0;
                int bindStatus = bindHandle(handle, (__bridge CFStringRef)interface);
                int bindErrno = errno;
                result[@"bind_status"] = @(bindStatus);
                // Diagnostic only: private APIs do not promise errno semantics.
                // Capture it immediately, before Close or Foundation can change it.
                result[@"errno_after_bind"] = @(bindErrno);
                result[@"errno_after_bind_message"] = @(strerror(bindErrno));
                result[@"errno_meaning"] = @"Saved immediately after Bind; private API errno behavior is undocumented and this may reflect an internal fallback.";
                result[@"close_status"] = @(closeHandle(handle));
            }
        }
    }
    // Keep framework handles loaded while inspecting runtime metadata.
    // No CoreWiFi objects are instantiated and no listed selectors are called.
    void *coreWiFi = dlopen("/System/Library/PrivateFrameworks/CoreWiFi.framework/CoreWiFi",
        RTLD_LAZY | RTLD_LOCAL);
    result[@"corewifi_loaded"] = @(coreWiFi != NULL);
    NSMutableDictionary *classes = [NSMutableDictionary dictionary];
    for (NSString *name in @[@"CWInterface", @"CWFInterface", @"CWFAssocParameters"]) {
        Class cls = NSClassFromString(name);
        unsigned count = 0;
        Method *methods = class_copyMethodList(cls, &count);
        NSMutableArray *selectors = [NSMutableArray array];
        for (unsigned i = 0; i < count; ++i) {
            NSString *selector = NSStringFromSelector(method_getName(methods[i]));
            for (NSString *term in @[@"actionFrame", @"cipher", @"pairwise", @"WEPKey", @"monitorMode"])
                if ([selector rangeOfString:term options:NSCaseInsensitiveSearch].location != NSNotFound) {
                    [selectors addObject:selector];
                    break;
                }
        }
        free(methods);
        classes[name] = @{@"present": @(cls != Nil), @"selected_instance_methods": selectors};
    }
    result[@"runtime_metadata"] = classes;
    result[@"meaning"] = @"Symbol presence and a successful bind do not prove permission to set keys or send frames.";
    return result;
}

static void usage(FILE *stream) {
    fprintf(stream, "Usage: macos-probe [--interface en0] [--private]\n"
        "Queries monitor capability and driver identity without activating capture.\n"
        "--private also probes Apple80211 Open/Bind/Close and runtime metadata.\n"
        "No scan, association, key access, radio changes, or transmission.\n"
        "Exit 0: monitor query completed (inspect result); 2: inconclusive; 64: arguments.\n");
}

int main(int argc, const char **argv) {
    @autoreleasepool {
        NSString *interface = nil;
        BOOL includePrivate = NO;
        for (int i = 1; i < argc; ++i) {
            if (!strcmp(argv[i], "--private")) includePrivate = YES;
            else if (!strcmp(argv[i], "--interface") && i + 1 < argc)
                interface = @(argv[++i]);
            else if (!strcmp(argv[i], "--help")) { usage(stdout); return 0; }
            else { usage(stderr); return 64; }
        }
        NSArray *interfaces = [[[CWWiFiClient sharedWiFiClient] interfaceNames]
            sortedArrayUsingSelector:@selector(compare:)] ?: @[];
        BOOL assumedInterface = interface == nil && interfaces.count == 0;
        if (!interface) interface = interfaces.firstObject ?: @"en0";
        NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:
            @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-."];
        if (interface.length == 0 || interface.length >= IFNAMSIZ ||
                [interface rangeOfCharacterFromSet:allowed.invertedSet].location != NSNotFound) {
            fprintf(stderr, "Invalid interface name.\n");
            return 64;
        }
        struct utsname system = {0};
        uname(&system);
        NSDictionary *monitor = monitorQuery(interface.UTF8String);
        NSMutableDictionary *report = [@{
            @"schema_version": @2,
            @"os": NSProcessInfo.processInfo.operatingSystemVersionString,
            @"architecture": @(system.machine),
            @"running_as_root": @(geteuid() == 0),
            @"interface": interface,
            @"interface_assumed": @(assumedInterface),
            @"corewlan_interfaces": interfaces,
            @"driver_ancestry": driverAncestry(interface.UTF8String),
            @"pcap_version": @(pcap_lib_version()),
            @"monitor_query": monitor,
            @"capture_activated": @NO,
            @"transmission_tested": @NO,
            @"ldn_compatibility": @"unproven"
        } mutableCopy];
        if (includePrivate) report[@"private_api_query"] = privateQuery(interface);
        NSError *error = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:report
            options:NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys error:&error];
        if (!json) {
            fprintf(stderr, "JSON serialization failed.\n");
            return 2;
        }
        fwrite(json.bytes, 1, json.length, stdout);
        fputc('\n', stdout);
        return [monitor[@"status"] isEqualToString:@"error"] ? 2 : 0;
    }
}
