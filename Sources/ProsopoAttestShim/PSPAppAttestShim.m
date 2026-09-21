// Copyright 2021-2026 Prosopo (UK) Ltd.
// Licensed under the Apache License, Version 2.0

#import "PSPAppAttestShim.h"

#import <DeviceCheck/DeviceCheck.h>

NSString *const PSPAppAttestErrorDomain = @"io.prosopo.protect.appattest";
NSString *const PSPAppAttestExceptionNameKey = @"PSPAppAttestExceptionName";
NSString *const PSPAppAttestExceptionReasonKey = @"PSPAppAttestExceptionReason";
NSString *const PSPAppAttestExceptionCallStackKey = @"PSPAppAttestExceptionCallStack";

static NSError *PSPErrorFromException(NSException *exception, NSString *operation) {
    NSMutableDictionary<NSErrorUserInfoKey, id> *userInfo = [NSMutableDictionary dictionary];

    NSString *name = exception.name ?: @"NSException";
    NSString *reason = exception.reason ?: @"(no reason given)";
    userInfo[NSLocalizedDescriptionKey] =
        [NSString stringWithFormat:@"DeviceCheck raised %@ during %@: %@", name, operation, reason];
    userInfo[PSPAppAttestExceptionNameKey] = name;
    userInfo[PSPAppAttestExceptionReasonKey] = reason;

    NSArray<NSString *> *symbols = exception.callStackSymbols;
    if (symbols.count > 0) {
        userInfo[PSPAppAttestExceptionCallStackKey] = symbols;
    }

    return [NSError errorWithDomain:PSPAppAttestErrorDomain
                               code:PSPAppAttestErrorFrameworkFault
                           userInfo:userInfo];
}

static NSError *PSPUnavailableError(NSString *operation) {
    return [NSError errorWithDomain:PSPAppAttestErrorDomain
                               code:PSPAppAttestErrorUnavailable
                           userInfo:@{
                               NSLocalizedDescriptionKey: [NSString
                                   stringWithFormat:@"App Attest is unavailable on this OS version (%@)", operation]
                           }];
}

/// Runs `body` inside an Objective-C exception barrier.
///
/// `body` is handed a `finish` block and is expected to call it — either
/// directly, or from a DeviceCheck completion handler later on. If `body`
/// instead raises an `NSException`, the exception is caught here, in an
/// Objective-C frame, and converted to an `NSError`. It never reaches the
/// Swift caller as an exception, and the stack unwind never passes through a
/// Swift frame (which is not set up for Objective-C exception unwinding).
///
/// `finish` runs at most once. If DeviceCheck ever both invokes its completion
/// handler *and* throws, the second call is dropped: the Swift layer resumes a
/// `CheckedContinuation` from it, and resuming twice traps. Turning a
/// recoverable framework fault into a different fatal error would defeat the
/// whole point of the barrier.
static void PSPPerformBarriered(NSString *operation,
                                PSPBarrieredBody body,
                                PSPFinishBlock completion) {
    NSObject *token = [NSObject new];
    __block BOOL finished = NO;
    PSPFinishBlock finish = ^(id _Nullable value, NSError *_Nullable error) {
        @synchronized (token) {
            if (finished) {
                return;
            }
            finished = YES;
        }
        completion(value, error);
    };

    @try {
        body(finish);
    } @catch (NSException *exception) {
        finish(nil, PSPErrorFromException(exception, operation));
    }
}

@implementation PSPAppAttestShim

+ (nullable NSNumber *)supportState {
    if (@available(iOS 14.0, macOS 11.0, tvOS 15.0, *)) {
        @try {
            return @(DCAppAttestService.sharedService.isSupported);
        } @catch (NSException *exception) {
            NSLog(@"[Prosopo] DeviceCheck raised %@ during isSupported: %@", exception.name, exception.reason);
            return nil;
        }
    }
    return @NO;
}

+ (void)generateKeyWithCompletion:(void (^)(NSString *_Nullable, NSError *_Nullable))completion {
    PSPPerformBarriered(
        @"generateKey",
        ^(PSPFinishBlock finish) {
            if (@available(iOS 14.0, macOS 11.0, tvOS 15.0, *)) {
                [DCAppAttestService.sharedService
                    generateKeyWithCompletionHandler:^(NSString *_Nullable keyId, NSError *_Nullable error) {
                        finish(keyId, error);
                    }];
            } else {
                finish(nil, PSPUnavailableError(@"generateKey"));
            }
        },
        ^(id _Nullable value, NSError *_Nullable error) {
            completion(value, error);
        });
}

+ (void)attestKey:(NSString *)keyId
   clientDataHash:(NSData *)clientDataHash
       completion:(void (^)(NSData *_Nullable, NSError *_Nullable))completion {
    PSPPerformBarriered(
        @"attestKey",
        ^(PSPFinishBlock finish) {
            if (@available(iOS 14.0, macOS 11.0, tvOS 15.0, *)) {
                [DCAppAttestService.sharedService
                             attestKey:keyId
                        clientDataHash:clientDataHash
                     completionHandler:^(NSData *_Nullable attestationObject, NSError *_Nullable error) {
                         finish(attestationObject, error);
                     }];
            } else {
                finish(nil, PSPUnavailableError(@"attestKey"));
            }
        },
        ^(id _Nullable value, NSError *_Nullable error) {
            completion(value, error);
        });
}

+ (void)generateAssertion:(NSString *)keyId
           clientDataHash:(NSData *)clientDataHash
               completion:(void (^)(NSData *_Nullable, NSError *_Nullable))completion {
    PSPPerformBarriered(
        @"generateAssertion",
        ^(PSPFinishBlock finish) {
            if (@available(iOS 14.0, macOS 11.0, tvOS 15.0, *)) {
                // The iOS 18 crash throws *synchronously*, inside this call,
                // before the completion handler is ever scheduled — the
                // Crashlytics frames run DCAppAttestController →
                // DCAppAttestService → caller with nothing in between. That is
                // exactly what the surrounding @try catches.
                [DCAppAttestService.sharedService
                     generateAssertion:keyId
                        clientDataHash:clientDataHash
                     completionHandler:^(NSData *_Nullable assertion, NSError *_Nullable error) {
                         finish(assertion, error);
                     }];
            } else {
                finish(nil, PSPUnavailableError(@"generateAssertion"));
            }
        },
        ^(id _Nullable value, NSError *_Nullable error) {
            completion(value, error);
        });
}

+ (void)performBarriered:(PSPBarrieredBody)body
              completion:(void (^)(id _Nullable, NSError *_Nullable))completion {
    PSPPerformBarriered(@"performBarriered", body, completion);
}

@end
