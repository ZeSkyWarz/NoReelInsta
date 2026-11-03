#import <Foundation/Foundation.h>
#include <objc/NSObject.h>
#import <UIKit/UIKit.h>

// Classes for Reels tab removal
@interface IGMainAppSurfaceIntent : NSObject
- (NSString *)tabStringFromSurfaceIntent;
@end

@interface IGTabBarController : UIViewController
@end

@interface IGTabBarControllerSwipeCoordinator : NSObject
- (id)initWithSurfaces:(id)surfaces parentViewController:(id)controller enableHaptics:(BOOL)haptics launcherSet:(id)set;
@end

// Classes for Reels scrolling
@interface IGUnifiedVideoCollectionView : UIScrollView
@end

@interface IGSundialAutoScroll : NSObject
- (void)setIsEnabled:(BOOL)enabled;
@end

// Safe TestFlight nag suppression (only specific plugin classes)
@interface IGTestFlightNagController : NSObject
- (void)presentUpdateNag;
- (void)presentNagWithTitle:(NSString *)title message:(NSString *)message;
@end

@interface IGCoreRootTestFlightNagPlugin : NSObject
- (void)showTestFlightNagIfNeeded;
- (void)checkForTestFlightNag;
- (void)presentTestFlightUpdateNag;
- (void)presentTestFlightUpdateNagWithTitle:(NSString *)title message:(NSString *)message;
@end

@interface IGTestFlightUpdateNagController : NSObject
- (void)presentNag;
- (void)showUpdateNag;
@end
