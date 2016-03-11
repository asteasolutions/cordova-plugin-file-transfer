/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
 */

#import <Cordova/CDV.h>
#import "CDVFileTransfer.h"
#import "CDVLocalFilesystem.h"

#import <AssetsLibrary/ALAsset.h>
#import <AssetsLibrary/ALAssetRepresentation.h>
#import <AssetsLibrary/ALAssetsLibrary.h>
#import <CFNetwork/CFNetwork.h>

#ifndef DLog
#ifdef DEBUG
    #define DLog(fmt, ...) NSLog((@"%s [Line %d] " fmt), __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
    #define DLog(...)
#endif
#endif

@interface CDVFileTransfer ()
// Sets the requests headers for the request.
- (void)applyRequestHeaders:(NSDictionary*)headers toRequest:(NSMutableURLRequest*)req;
@end


@implementation CDVFileTransfer
@synthesize activeTransfers;

- (void)pluginInitialize {
    activeTransfers = [[NSMutableDictionary alloc] init];
}

- (NSString*)escapePathComponentForUrlString:(NSString*)urlString
{
    NSRange schemeAndHostRange = [urlString rangeOfString:@"://.*?/" options:NSRegularExpressionSearch];

    if (schemeAndHostRange.length == 0) {
        return urlString;
    }

    NSInteger schemeAndHostEndIndex = NSMaxRange(schemeAndHostRange);
    NSString* schemeAndHost = [urlString substringToIndex:schemeAndHostEndIndex];
    NSString* pathComponent = [urlString substringFromIndex:schemeAndHostEndIndex];
    pathComponent = [pathComponent stringByAddingPercentEscapesUsingEncoding:NSUTF8StringEncoding];

    return [schemeAndHost stringByAppendingString:pathComponent];
}

- (void)applyRequestHeaders:(NSDictionary*)headers toRequest:(NSMutableURLRequest*)req
{
    [req setValue:@"XMLHttpRequest" forHTTPHeaderField:@"X-Requested-With"];

    NSString* userAgent = [self.commandDelegate userAgent];
    if (userAgent) {
        [req setValue:userAgent forHTTPHeaderField:@"User-Agent"];
    }

    for (NSString* headerName in headers) {
        id value = [headers objectForKey:headerName];
        if (!value || (value == [NSNull null])) {
            value = @"null";
        }

        // First, remove an existing header if one exists.
        [req setValue:nil forHTTPHeaderField:headerName];

        if (![value isKindOfClass:[NSArray class]]) {
            value = [NSArray arrayWithObject:value];
        }

        // Then, append all header values.
        for (id __strong subValue in value) {
            // Convert from an NSNumber -> NSString.
            if ([subValue respondsToSelector:@selector(stringValue)]) {
                subValue = [subValue stringValue];
            }
            if ([subValue isKindOfClass:[NSString class]]) {
                [req addValue:subValue forHTTPHeaderField:headerName];
            }
        }
    }
}

- (void)pause:(CDVInvokedUrlCommand*)command
{
    NSString* objectId = [command argumentAtIndex:0];

    @synchronized (activeTransfers) {
        CDVFileTransferDelegate* delegate = activeTransfers[objectId];
        if (delegate != nil) {
            [delegate cancelTransfer:delegate.connection];
            CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:[self createFileTransferError:CONNECTION_PAUSED AndSource:delegate.source AndTarget:delegate.target]];
            [self.commandDelegate sendPluginResult:result callbackId:delegate.callbackId];
        }
    }
}

- (void)download:(CDVInvokedUrlCommand*)command
{
    DLog(@"File Transfer downloading file...");
    NSString* source = [command argumentAtIndex:0];
    NSString* target = [command argumentAtIndex:1];
    BOOL trustAllHosts = [[command argumentAtIndex:2 withDefault:[NSNumber numberWithBool:NO]] boolValue]; // allow self-signed certs
    NSString* objectId = [command argumentAtIndex:3];
    NSDictionary* headers = [command argumentAtIndex:4 withDefault:nil];

    CDVPluginResult* result = nil;
    CDVFileTransferError errorCode = 0;

    NSURL* targetURL;

    if ([target hasPrefix:@"/"]) {
        /* Backwards-compatibility:
         * Check here to see if it looks like the user passed in a raw filesystem path. (Perhaps they had the path saved, and were previously using it with the old version of File). If so, normalize it by removing empty path segments, and check with File to see if any of the installed filesystems will handle it. If so, then we will end up with a filesystem url to use for the remainder of this operation.
         */
        target = [target stringByReplacingOccurrencesOfString:@"//" withString:@"/"];
        targetURL = [[self.commandDelegate getCommandInstance:@"File"] fileSystemURLforLocalPath:target].url;
    } else {
        targetURL = [NSURL URLWithString:target];
    }

    NSURL* sourceURL = [NSURL URLWithString:source];

    if (!sourceURL) {
        errorCode = INVALID_URL_ERR;
        NSLog(@"File Transfer Error: Invalid server URL %@", source);
    } else if (![targetURL isFileURL]) {
        CDVFilesystemURL *fsURL = [CDVFilesystemURL fileSystemURLWithString:target];
        if (!fsURL) {
           errorCode = FILE_NOT_FOUND_ERR;
           NSLog(@"File Transfer Error: Invalid file path or URL %@", target);
        }
    }

    if (errorCode > 0) {
        result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:[self createFileTransferError:errorCode AndSource:source AndTarget:target]];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
        return;
    }

    NSMutableURLRequest* req = [NSMutableURLRequest requestWithURL:sourceURL];
    [self applyRequestHeaders:headers toRequest:req];

    // if target file exists continue downloading
    if ([[NSFileManager defaultManager] fileExistsAtPath:[targetURL path]]) {
        unsigned long long fileSize = [[NSFileManager defaultManager] attributesOfItemAtPath:[targetURL path] error:nil].fileSize;
        NSString* rangeHeaderValue = [NSString stringWithFormat:@"bytes=%llu-", fileSize];
        [req addValue:rangeHeaderValue forHTTPHeaderField:@"Range"];
    }

    CDVFileTransferDelegate* delegate = [[CDVFileTransferDelegate alloc] init];
    delegate.command = self;
    delegate.callbackId = command.callbackId;
    delegate.objectId = objectId;
    delegate.source = source;
    delegate.target = [targetURL absoluteString];
    delegate.targetURL = targetURL;
    delegate.trustAllHosts = trustAllHosts;
    delegate.filePlugin = [self.commandDelegate getCommandInstance:@"File"];
    delegate.backgroundTaskID = [[UIApplication sharedApplication] beginBackgroundTaskWithExpirationHandler:^{
        [delegate cancelTransfer:delegate.connection];
    }];

    delegate.connection = [[NSURLConnection alloc] initWithRequest:req delegate:delegate startImmediately:NO];

    if (self.queue == nil) {
        self.queue = [[NSOperationQueue alloc] init];
    }
    [delegate.connection setDelegateQueue:self.queue];

    @synchronized (activeTransfers) {
        activeTransfers[delegate.objectId] = delegate;
    }
    // Downloads can take time
    // sending this to a new thread calling the download_async method
    dispatch_async(
                   dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, (unsigned long)NULL),
                   ^(void) { [delegate.connection start];}
                   );
}

- (NSMutableDictionary*)createFileTransferError:(int)code AndSource:(NSString*)source AndTarget:(NSString*)target
{
    NSMutableDictionary* result = [NSMutableDictionary dictionaryWithCapacity:3];

    [result setObject:[NSNumber numberWithInt:code] forKey:@"code"];
    if (source != nil) {
        [result setObject:source forKey:@"source"];
    }
    if (target != nil) {
        [result setObject:target forKey:@"target"];
    }
    NSLog(@"FileTransferError %@", result);

    return result;
}

- (NSMutableDictionary*)createFileTransferError:(int)code
                                      AndSource:(NSString*)source
                                      AndTarget:(NSString*)target
                                  AndHttpStatus:(int)httpStatus
                                        AndBody:(NSString*)body
{
    NSMutableDictionary* result = [NSMutableDictionary dictionaryWithCapacity:5];

    [result setObject:[NSNumber numberWithInt:code] forKey:@"code"];
    if (source != nil) {
        [result setObject:source forKey:@"source"];
    }
    if (target != nil) {
        [result setObject:target forKey:@"target"];
    }
    [result setObject:[NSNumber numberWithInt:httpStatus] forKey:@"http_status"];
    if (body != nil) {
        [result setObject:body forKey:@"body"];
    }
    NSLog(@"FileTransferError %@", result);

    return result;
}

- (void)onReset {
    @synchronized (activeTransfers) {
        while ([activeTransfers count] > 0) {
            CDVFileTransferDelegate* delegate = [activeTransfers allValues][0];
            [delegate cancelTransfer:delegate.connection];
        }
    }
}

@end

@interface CDVFileTransferEntityLengthRequest : NSObject {
    NSURLConnection* _connection;
    CDVFileTransferDelegate* __weak _originalDelegate;
}

- (CDVFileTransferEntityLengthRequest*)initWithOriginalRequest:(NSURLRequest*)originalRequest andDelegate:(CDVFileTransferDelegate*)originalDelegate;

@end

@implementation CDVFileTransferEntityLengthRequest

- (CDVFileTransferEntityLengthRequest*)initWithOriginalRequest:(NSURLRequest*)originalRequest andDelegate:(CDVFileTransferDelegate*)originalDelegate
{
    if (self) {
        DLog(@"Requesting entity length for GZIPped content...");

        NSMutableURLRequest* req = [originalRequest mutableCopy];
        [req setHTTPMethod:@"HEAD"];
        [req setValue:@"identity" forHTTPHeaderField:@"Accept-Encoding"];

        _originalDelegate = originalDelegate;
        _connection = [NSURLConnection connectionWithRequest:req delegate:self];
    }
    return self;
}

- (void)connection:(NSURLConnection*)connection didReceiveResponse:(NSURLResponse*)response
{
    DLog(@"HEAD request returned; content-length is %lld", [response expectedContentLength]);
    [_originalDelegate updateBytesExpected:[response expectedContentLength]];
}

- (void)connection:(NSURLConnection*)connection didReceiveData:(NSData*)data
{}

- (void)connectionDidFinishLoading:(NSURLConnection*)connection
{}

@end

@implementation CDVFileTransferDelegate

@synthesize callbackId, connection = _connection, source, target, responseData, responseHeaders, command, bytesTransfered, bytesExpected, responseCode, objectId, targetFileHandle, filePlugin;

- (void)connectionDidFinishLoading:(NSURLConnection*)connection
{
    NSString* downloadResponse = nil;
    CDVPluginResult* result = nil;

    NSLog(@"File Transfer Finished with response code %d", self.responseCode);

    if (self.targetFileHandle) {
        [self.targetFileHandle closeFile];
        self.targetFileHandle = nil;
        DLog(@"File Transfer Download success");

        result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:[self.filePlugin makeEntryForURL:self.targetURL]];
    } else {
        downloadResponse = [[NSString alloc] initWithData:self.responseData encoding:NSUTF8StringEncoding];
        if (downloadResponse == nil) {
            downloadResponse = [[NSString alloc] initWithData: self.responseData encoding:NSISOLatin1StringEncoding];
        }

        CDVFileTransferError errorCode = self.responseCode == 404 ? FILE_NOT_FOUND_ERR
            : (self.responseCode == 304 ? NOT_MODIFIED : CONNECTION_ERR);
        result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:[command createFileTransferError:errorCode AndSource:source AndTarget:target AndHttpStatus:self.responseCode AndBody:downloadResponse]];
    }

    [self.command.commandDelegate sendPluginResult:result callbackId:callbackId];

    // remove connection for activeTransfers
    @synchronized (command.activeTransfers) {
        [command.activeTransfers removeObjectForKey:objectId];
        // remove background id task in case our upload was done in the background
        [[UIApplication sharedApplication] endBackgroundTask:self.backgroundTaskID];
        self.backgroundTaskID = UIBackgroundTaskInvalid;
    }
}

- (void)cancelTransfer:(NSURLConnection*)connection
{
    [connection cancel];
    @synchronized (self.command.activeTransfers) {
        CDVFileTransferDelegate* delegate = self.command.activeTransfers[self.objectId];
        [self.command.activeTransfers removeObjectForKey:self.objectId];
        [[UIApplication sharedApplication] endBackgroundTask:delegate.backgroundTaskID];
        delegate.backgroundTaskID = UIBackgroundTaskInvalid;
    }
}

- (void)cancelTransferWithError:(NSURLConnection*)connection errorMessage:(NSString*)errorMessage
{
    CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_IO_EXCEPTION messageAsDictionary:[self.command createFileTransferError:FILE_NOT_FOUND_ERR AndSource:self.source AndTarget:self.target AndHttpStatus:self.responseCode AndBody:errorMessage]];

    NSLog(@"File Transfer Error: %@", errorMessage);
    [self cancelTransfer:connection];
    [self.command.commandDelegate sendPluginResult:result callbackId:callbackId];
}

- (NSString *)targetFilePath
{
    NSString *path = nil;
    CDVFilesystemURL *sourceURL = [CDVFilesystemURL fileSystemURLWithString:self.target];
    if (sourceURL && sourceURL.fileSystemName != nil) {
        // This requires talking to the current CDVFile plugin
        NSObject<CDVFileSystem> *fs = [self.filePlugin filesystemForURL:sourceURL];
        path = [fs filesystemPathForURL:sourceURL];
    } else {
        // Extract the path part out of a file: URL.
        path = [self.target hasPrefix:@"/"] ? [self.target copy] : [(NSURL *)[NSURL URLWithString:self.target] path];
    }
    return path;
}

- (void)connection:(NSURLConnection*)connection didReceiveResponse:(NSURLResponse*)response
{
    NSError* __autoreleasing error = nil;

    self.mimeType = [response MIMEType];
    self.targetFileHandle = nil;

    // required for iOS 4.3, for some reason; response is
    // a plain NSURLResponse, not the HTTP subclass
    if ([response isKindOfClass:[NSHTTPURLResponse class]]) {
        NSHTTPURLResponse* httpResponse = (NSHTTPURLResponse*)response;

        self.responseCode = (int)[httpResponse statusCode];
        self.bytesExpected = [response expectedContentLength];
        self.responseHeaders = [httpResponse allHeaderFields];
        if (self.responseCode == 200 && self.bytesExpected == NSURLResponseUnknownLength) {
            // Kick off HEAD request to server to get real length
            // bytesExpected will be updated when that response is returned
            self.entityLengthRequest = [[CDVFileTransferEntityLengthRequest alloc] initWithOriginalRequest:connection.currentRequest andDelegate:self];
        }
    } else if ([response.URL isFileURL]) {
        NSDictionary* attr = [[NSFileManager defaultManager] attributesOfItemAtPath:[response.URL path] error:nil];
        self.responseCode = 200;
        self.bytesExpected = [attr[NSFileSize] longLongValue];
    } else {
        self.responseCode = 200;
        self.bytesExpected = NSURLResponseUnknownLength;
    }
    if (self.responseCode >= 200 && self.responseCode < 300) {
        // Download response is okay; begin streaming output to file
        NSString *filePath = [self targetFilePath];
        if (filePath == nil) {
            // We couldn't find the asset.  Send the appropriate error.
            [self cancelTransferWithError:connection errorMessage:[NSString stringWithFormat:@"Could not create target file"]];
            return;
        }

        NSString* parentPath = [filePath stringByDeletingLastPathComponent];

        // create parent directories if needed
        if ([[NSFileManager defaultManager] createDirectoryAtPath:parentPath withIntermediateDirectories:YES attributes:nil error:&error] == NO) {
            if (error) {
                [self cancelTransferWithError:connection errorMessage:[NSString stringWithFormat:@"Could not create path to save downloaded file: %@", [error localizedDescription]]];
            } else {
                [self cancelTransferWithError:connection errorMessage:@"Could not create path to save downloaded file"];
            }
            return;
        }
        // open target file for writing
        self.targetFileHandle = [NSFileHandle fileHandleForWritingAtPath:filePath];
        if (self.targetFileHandle != nil) {
            [self.targetFileHandle seekToEndOfFile];
        } else {
            // create target file
            if ([[NSFileManager defaultManager] createFileAtPath:filePath contents:nil attributes:nil] == NO) {
                [self cancelTransferWithError:connection errorMessage:@"Could not create target file"];
                return;
            }
            self.targetFileHandle = [NSFileHandle fileHandleForWritingAtPath:filePath];
        }

        if (self.targetFileHandle == nil) {
            [self cancelTransferWithError:connection errorMessage:@"Could not open target file for writing"];
        } else {
            self.fileSize = [[NSFileManager defaultManager] attributesOfItemAtPath:filePath error:nil].fileSize;
        }
        DLog(@"Streaming to file %@", filePath);
    }
}

- (void)connection:(NSURLConnection*)connection didFailWithError:(NSError*)error
{
    NSString* body = [[NSString alloc] initWithData:self.responseData encoding:NSUTF8StringEncoding];
    CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsDictionary:[command createFileTransferError:CONNECTION_ERR AndSource:source AndTarget:target AndHttpStatus:self.responseCode AndBody:body]];

    NSLog(@"File Transfer Error: %@", [error localizedDescription]);

    [self cancelTransfer:connection];
    [self.command.commandDelegate sendPluginResult:result callbackId:callbackId];
}

- (void)connection:(NSURLConnection*)connection didReceiveData:(NSData*)data
{
    self.bytesTransfered += data.length;
    if (self.targetFileHandle) {
        [self.targetFileHandle writeData:data];
    } else {
        [self.responseData appendData:data];
    }
    [self updateProgress];
}

- (void)updateBytesExpected:(long long)newBytesExpected
{
    DLog(@"Updating bytesExpected to %lld", newBytesExpected);
    self.bytesExpected = newBytesExpected;
    [self updateProgress];
}

- (void)updateProgress
{
    BOOL lengthComputable = (self.bytesExpected != NSURLResponseUnknownLength);
    // If the response is GZipped, and we have an outstanding HEAD request to get
    // the length, then hold off on sending progress events.
    if (!lengthComputable && (self.entityLengthRequest != nil)) {
        return;
    }

    NSMutableDictionary* downloadProgress = [NSMutableDictionary dictionaryWithCapacity:3];
    [downloadProgress setObject:[NSNumber numberWithBool:lengthComputable] forKey:@"lengthComputable"];
    [downloadProgress setObject:[NSNumber numberWithLongLong:self.bytesTransfered + self.fileSize] forKey:@"loaded"];
    [downloadProgress setObject:[NSNumber numberWithLongLong:self.bytesExpected + self.fileSize] forKey:@"total"];
    CDVPluginResult* result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:downloadProgress];
    [result setKeepCallbackAsBool:true];
    [self.command.commandDelegate sendPluginResult:result callbackId:callbackId];
}

- (void)connection:(NSURLConnection*)connection didSendBodyData:(NSInteger)bytesWritten totalBytesWritten:(NSInteger)totalBytesWritten totalBytesExpectedToWrite:(NSInteger)totalBytesExpectedToWrite
{
    self.bytesTransfered = totalBytesWritten;
}

// for self signed certificates
- (void)connection:(NSURLConnection*)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge*)challenge
{
    if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        if (self.trustAllHosts) {
            NSURLCredential* credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
            [challenge.sender useCredential:credential forAuthenticationChallenge:challenge];
        }
        [challenge.sender continueWithoutCredentialForAuthenticationChallenge:challenge];
    } else {
        [challenge.sender performDefaultHandlingForAuthenticationChallenge:challenge];
    }
}

- (id)init
{
    if ((self = [super init])) {
        self.responseData = [NSMutableData data];
        self.targetFileHandle = nil;
    }
    return self;
}

@end
