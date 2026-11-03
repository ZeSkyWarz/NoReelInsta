#import "Utils.h"
#include <objc/runtime.h>

@implementation SCIUtils

+ (id)getIvarForObj:(id)obj name:(NSString *)name {
    if (!obj || !name) return nil;
    Ivar ivar = class_getInstanceVariable(object_getClass(obj), [name UTF8String]);
    if (!ivar) return nil;
    return object_getIvar(obj, ivar);
}

+ (void)setIvarForObj:(id)obj name:(NSString *)name value:(id)value {
    if (!obj || !name) return;
    Ivar ivar = class_getInstanceVariable(object_getClass(obj), [name UTF8String]);
    if (!ivar) return;
    object_setIvarWithStrongDefault(obj, ivar, value);
}

@end
