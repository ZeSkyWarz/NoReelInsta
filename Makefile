TARGET := iphone:clang:16.5:15.0
INSTALL_TARGET_PROCESSES = Instagram
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = NoReelInsta

# Fichiers source
$(TWEAK_NAME)_FILES = Tweak.x Utils.m fishhook.c

# Désactiver ARC uniquement pour fishhook.c
fishhook.c_CFLAGS = -fno-objc-arc

# Frameworks nécessaires
$(TWEAK_NAME)_FRAMEWORKS = UIKit Foundation CoreGraphics Security

# Options de compilation
$(TWEAK_NAME)_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
