// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Error domain for faults raised *inside* Apple's DeviceCheck framework.
///
/// DeviceCheck occasionally raises an Objective-C `NSException` rather than
/// returning an `NSError` — see the `DCAppAttestController` /
/// `DCDeviceMetadataDaemonConnection` unrecognized-selector crash observed on
/// iOS 18. Swift's `try`/`catch` cannot catch an `NSException`, so a throw
/// inside a DeviceCheck call terminates the *host app*. These wrappers put an
/// Objective-C exception barrier directly around each DeviceCheck call and
/// convert any exception into an `NSError` in this domain.
extern NSString *const PSPAppAttestErrorDomain;

/// `userInfo` keys carrying the original exception details, so the Swift layer
/// can log something actionable rather than just "something blew up".
extern NSString *const PSPAppAttestExceptionNameKey;
extern NSString *const PSPAppAttestExceptionReasonKey;
extern NSString *const PSPAppAttestExceptionCallStackKey;

typedef NS_ENUM(NSInteger, PSPAppAttestErrorCode) {
    /// Apple's DeviceCheck framework raised an Objective-C exception.
    PSPAppAttestErrorFrameworkFault = 1,
    /// App Attest is not available on this OS version.
    PSPAppAttestErrorUnavailable = 2,
};

/// Completion shape used inside the barrier. Exactly one of the two arguments
/// is non-nil.
typedef void (^PSPFinishBlock)(id _Nullable value, NSError *_Nullable error);

/// A unit of work run inside the exception barrier. Must call `finish`, either
/// synchronously or from a completion handler.
typedef void (^PSPBarrieredBody)(PSPFinishBlock finish);

/// Exception-safe wrappers around `DCAppAttestService`.
///
/// Every method here is a thin pass-through: normal `NSError`s from DeviceCheck
/// (including `DCError`, which bridges back to Swift's `DCError` unchanged) are
/// forwarded untouched. Only an `NSException` is translated.
///
/// The barrier lives in Objective-C on purpose. Catching the exception here
/// means the stack unwind never passes through a Swift frame, which is not set
/// up for Objective-C exception unwinding.
NS_SWIFT_NAME(AppAttestShim)
@interface PSPAppAttestShim : NSObject

/// `DCAppAttestService.shared.isSupported`, or `nil` if the support check
/// itself faulted inside DeviceCheck. (Apple's own support checks have been
/// reported to crash in production.)
///
/// The nil case is deliberately distinct from `@NO`: "this device doesn't
/// support App Attest" is permanent and worth acting on, whereas "DeviceCheck
/// blew up while answering" says nothing about the device and must be retried.
/// Collapsing the two would strand a perfectly capable device as unsupported.
@property (class, readonly, nullable) NSNumber *supportState;

+ (void)generateKeyWithCompletion:(void (^)(NSString *_Nullable keyId,
                                            NSError *_Nullable error))completion
    NS_SWIFT_NAME(generateKey(completion:));

+ (void)attestKey:(NSString *)keyId
   clientDataHash:(NSData *)clientDataHash
       completion:(void (^)(NSData *_Nullable attestationObject,
                            NSError *_Nullable error))completion
    NS_SWIFT_NAME(attestKey(_:clientDataHash:completion:));

+ (void)generateAssertion:(NSString *)keyId
           clientDataHash:(NSData *)clientDataHash
               completion:(void (^)(NSData *_Nullable assertion,
                                    NSError *_Nullable error))completion
    NS_SWIFT_NAME(generateAssertion(_:clientDataHash:completion:));

/// Runs an arbitrary block inside the same exception barrier the DeviceCheck
/// wrappers above use.
///
/// This is the primitive the rest of this class is built on. It is exposed so
/// the barrier's behaviour can be tested directly — Apple's framework cannot be
/// made to fault on demand.
+ (void)performBarriered:(PSPBarrieredBody)body
              completion:(void (^)(id _Nullable value,
                                   NSError *_Nullable error))completion
    NS_SWIFT_NAME(performBarriered(_:completion:));

@end

NS_ASSUME_NONNULL_END
