#import <Foundation/Foundation.h>
#import <Hopper/HopperTool.h>
#import <Hopper/HPBasicBlock.h>
#import <Hopper/HPDisassembledFile.h>
#import <Hopper/HPDocument.h>
#import <Hopper/HPHopperServices.h>
#import <Hopper/HPProcedure.h>
#import <dispatch/dispatch.h>
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

@protocol HopperAgentPluginService
- (NSDictionary *)hopperCurrentDocument;
- (NSDictionary *)hopperProcedures:(NSNumber *)maxResults;
@end

@class HopperMCPAgent;

static NSDictionary *HopperMCPErrorResponse(NSString *code, NSString *message);
static BOOL HopperMCPWriteAll(int fd, const void *bytes, size_t length);
static BOOL HopperMCPWriteJsonLine(int fd, NSDictionary *payload);
static NSData *HopperMCPReadLineData(int fd);
static NSDictionary *HopperMCPDecodeJsonObject(NSData *data);
static void *HopperMCPPrivateSocketServerMain(void *context);
static id HopperMCPCallObject(id target, SEL selector);

@interface HopperMCPAgent : NSObject <HopperTool, HopperAgentPluginService>
@end

@implementation HopperMCPAgent {
    NSObject<HPHopperServices> *_services;
    NSString *_socketPath;
    NSString *_serviceName;
    NSConnection *_connection;
    NSString *_privateSocketPath;
    BOOL _privateSocketServerStarted;
    BOOL _documentDiagnosticsLogged;
}

- (instancetype)initWithHopperServices:(NSObject<HPHopperServices> *)services {
    self = [super init];
    if (self != nil) {
        _services = services;
        _privateSocketPath = [self configuredPrivateSocketPath];
        _socketPath = _privateSocketPath.length > 0 ? _privateSocketPath : [self configuredSocketPath];
        _serviceName = [self serviceNameForSocketPath:_socketPath];
        if (_privateSocketPath.length > 0) {
            [self startPrivateSocketServerIfNeeded];
        } else {
            [self startServiceIfNeeded];
        }
    }
    return self;
}

- (NSArray<NSDictionary<NSString *, id> *> *)toolMenuDescription {
    return @[
        @{ HPM_TITLE: @"Hopper MCP: Start Agent", HPM_SELECTOR: @"startAgent:" },
        @{ HPM_TITLE: @"Hopper MCP: Log Bridge Info", HPM_SELECTOR: @"showBridgeInfo:" },
    ];
}

- (void)startAgent:(id)sender {
    (void)sender;
    if (_privateSocketPath.length > 0) {
        [self startPrivateSocketServerIfNeeded];
    } else {
        [self startServiceIfNeeded];
    }
    [_services logMessage:[NSString stringWithFormat:
        @"Hopper MCP bridge ready: mode=%@ service=%@ socket=%@",
        _privateSocketPath.length > 0 ? @"private_socket" : @"plugin_service",
        _serviceName,
        _socketPath]];
}

- (void)showBridgeInfo:(id)sender {
    (void)sender;
    [_services logMessage:[NSString stringWithFormat:
        @"Hopper MCP bridge info: mode=%@ service=%@ socket=%@",
        _privateSocketPath.length > 0 ? @"private_socket" : @"plugin_service",
        _serviceName,
        _socketPath]];
}

+ (int)sdkVersion {
    return HOPPER_CURRENT_SDK_VERSION;
}

- (NSObject<HPHopperUUID> *)pluginUUID {
    return [_services UUIDWithString:@"8c8ef89f-86c1-4599-83c6-bc4d31c9e57c"];
}

- (HopperPluginType)pluginType {
    return Plugin_Tool;
}

- (NSString *)pluginName {
    return @"HopperMCPAgent";
}

- (NSString *)pluginDescription {
    return @"Foundation bridge service for hopper-mcp";
}

- (NSString *)pluginAuthor {
    return @"hopper-mcp contributors";
}

- (NSString *)pluginCopyright {
    return @"Copyright 2026 hopper-mcp contributors";
}

- (NSString *)pluginVersion {
    return @"0.1.0";
}

- (NSArray<NSString *> *)commandLineIdentifiers {
    return @[ @"HopperMCPAgent" ];
}

- (NSString *)configuredPrivateSocketPath {
    NSString *envPath = [NSProcessInfo processInfo].environment[@"HOPPER_MCP_PRIVATE_AGENT_SOCKET"];
    return [envPath isKindOfClass:[NSString class]] && envPath.length > 0 ? envPath : nil;
}

- (NSString *)configuredSocketPath {
    NSString *envPath = [NSProcessInfo processInfo].environment[@"HOPPER_MCP_PLUGIN_SOCKET"];
    if ([envPath isKindOfClass:[NSString class]] && envPath.length > 0) {
        return envPath;
    }

    NSFileManager *manager = [NSFileManager defaultManager];
    NSURL *base = [[manager URLsForDirectory:NSApplicationSupportDirectory
                                   inDomains:NSUserDomainMask] firstObject];
    if (base == nil) {
        base = [NSURL fileURLWithPath:[@"~/Library/Application Support" stringByExpandingTildeInPath]
                         isDirectory:YES];
    }
    NSURL *dir = [base URLByAppendingPathComponent:@"hopper-mcp" isDirectory:YES];
    [manager createDirectoryAtURL:dir withIntermediateDirectories:YES attributes:nil error:nil];
    return [[dir URLByAppendingPathComponent:@"hopper-plugin.sock"] path];
}

- (NSString *)serviceNameForSocketPath:(NSString *)socketPath {
    NSMutableString *sanitized = [NSMutableString string];
    for (NSUInteger i = 0; i < socketPath.length; i += 1) {
        unichar ch = [socketPath characterAtIndex:i];
        if ([[NSCharacterSet alphanumericCharacterSet] characterIsMember:ch]) {
            [sanitized appendFormat:@"%C", ch];
        } else {
            [sanitized appendString:@"-"];
        }
    }
    while (sanitized.length > 0 && [sanitized hasSuffix:@"-"]) {
        [sanitized deleteCharactersInRange:NSMakeRange(sanitized.length - 1, 1)];
    }
    if (sanitized.length == 0) {
        [sanitized appendString:@"default"];
    }
    if (sanitized.length > 80) {
        [sanitized deleteCharactersInRange:NSMakeRange(80, sanitized.length - 80)];
    }
    return [NSString stringWithFormat:@"dev.hopper-mcp.plugin.%@", sanitized];
}

- (void)startServiceIfNeeded {
    if (_connection != nil && _connection.isValid) return;
    _connection = [NSConnection serviceConnectionWithName:_serviceName rootObject:self];
    if (_connection == nil) {
        [_services logMessage:[NSString stringWithFormat:
            @"Hopper MCP failed to publish service %@ for %@",
            _serviceName, _socketPath]];
        return;
    }
    [_services logMessage:[NSString stringWithFormat:
        @"Hopper MCP bridge published service %@ for %@",
        _serviceName, _socketPath]];
}

- (void)startPrivateSocketServerIfNeeded {
    if (_privateSocketServerStarted || _privateSocketPath.length == 0) return;
    _privateSocketServerStarted = YES;
    pthread_t thread;
    int rc = pthread_create(&thread, NULL, HopperMCPPrivateSocketServerMain, (__bridge_retained void *)self);
    if (rc != 0) {
        _privateSocketServerStarted = NO;
        [_services logMessage:[NSString stringWithFormat:
            @"Hopper MCP failed to start private socket server for %@: %s",
            _privateSocketPath, strerror(rc)]];
        return;
    }
    pthread_detach(thread);
    [_services logMessage:[NSString stringWithFormat:
        @"Hopper MCP private socket server starting for %@",
        _privateSocketPath]];
}

- (NSDictionary *)hopperCurrentDocument {
    if ([NSThread isMainThread]) {
        return [self hopperCurrentDocumentUnlocked];
    }
    __block NSDictionary *payload = nil;
    dispatch_sync(dispatch_get_main_queue(), ^{
        payload = [self hopperCurrentDocumentUnlocked];
    });
    return payload;
}

- (NSDictionary *)hopperCurrentDocumentUnlocked {
    NSObject<HPDocument> *document = [self resolvedDocument];
    if (document == nil) {
        return [self errorWithCode:@"no_document" message:@"Hopper has no current document"];
    }
    NSString *path = [self documentPath:document];
    NSString *name = [self documentDisplayName:document];
    if (name.length == 0 && path.length > 0) name = path.lastPathComponent;
    if (name.length == 0) name = @"current";
    NSString *documentId = path.length > 0 ? path : name;
    return @{
        @"documentId": documentId,
        @"name": name,
    };
}

- (NSDictionary *)hopperProcedures:(NSNumber *)maxResults {
    if ([NSThread isMainThread]) {
        return [self hopperProceduresUnlocked:maxResults];
    }
    __block NSDictionary *payload = nil;
    dispatch_sync(dispatch_get_main_queue(), ^{
        payload = [self hopperProceduresUnlocked:maxResults];
    });
    return payload;
}

- (NSDictionary *)hopperProceduresUnlocked:(NSNumber *)maxResults {
    NSObject<HPDocument> *document = [self resolvedDocument];
    if (document == nil) {
        return [self errorWithCode:@"no_document" message:@"Hopper has no current document"];
    }
    NSObject<HPDisassembledFile> *file = [document disassembledFile];
    if (file == nil) {
        return [self errorWithCode:@"no_disassembled_file"
                           message:@"current document has no disassembled file"];
    }

    NSUInteger max = [maxResults isKindOfClass:[NSNumber class]] ? maxResults.unsignedIntegerValue : 0;
    NSMutableArray *procedures = [NSMutableArray array];
    NSArray<NSNumber *> *addresses = [file allNamedAddresses];
    NSUInteger matched = 0;
    for (NSNumber *addressNumber in addresses) {
        Address address = addressNumber.unsignedLongLongValue;
        if (![file hasProcedureAt:address]) continue;
        matched += 1;
        if (max != 0 && procedures.count >= max) continue;
        NSObject<HPProcedure> *procedure = [file procedureAt:address];
        NSString *name = [file nameForVirtualAddress:address];
        NSNumber *size = [self sizeForProcedure:procedure];
        [procedures addObject:@{
            @"addr": [NSString stringWithFormat:@"0x%llx", (unsigned long long)address],
            @"name": name ?: [NSNull null],
            @"size": size ?: [NSNull null],
        }];
    }
    return @{
        @"procedures": procedures,
        @"truncated": @(max != 0 && matched > max),
    };
}

- (NSNumber *)sizeForProcedure:(NSObject<HPProcedure> *)procedure {
    if (procedure == nil) return nil;
    Address start = [procedure entryPoint];
    Address end = start;
    NSUInteger count = [procedure basicBlockCount];
    for (NSUInteger i = 0; i < count; i += 1) {
        NSObject<HPBasicBlock> *block = [procedure basicBlockAtIndex:i];
        if (block != nil && [block to] > end) end = [block to];
    }
    if (end <= start) return nil;
    return @(end - start + 1);
}

- (NSString *)configuredPrivateTargetPath {
    NSString *envPath = [NSProcessInfo processInfo].environment[@"HOPPER_MCP_PRIVATE_TARGET"];
    return [envPath isKindOfClass:[NSString class]] && envPath.length > 0 ? envPath : nil;
}

- (NSObject<HPDocument> *)resolvedDocument {
    NSObject<HPDocument> *current = [_services currentDocument];
    if ([self documentHasResolvedFile:current]) {
        NSString *targetPath = [self configuredPrivateTargetPath];
        if (targetPath.length == 0 || [self document:current matchesTargetPath:targetPath]) {
            return current;
        }
    }

    NSArray *documents = [self openDocuments];
    NSString *targetPath = [self configuredPrivateTargetPath];
    if (targetPath.length > 0) {
        for (id document in documents) {
            if ([self document:document matchesTargetPath:targetPath]) {
                return document;
            }
        }
        if (!_documentDiagnosticsLogged) {
            _documentDiagnosticsLogged = YES;
            NSMutableArray *summaries = [NSMutableArray array];
            for (id document in documents) {
                [summaries addObject:[self documentSummary:document]];
            }
            [_services logMessage:[NSString stringWithFormat:
                @"Hopper MCP target %@ not matched; current=%@ openDocuments=%@",
                targetPath,
                [self documentSummary:current],
                summaries]];
        }
    }

    for (id document in documents) {
        if ([self documentHasResolvedFile:document]) return document;
    }
    return current ?: (documents.count > 0 ? documents[0] : nil);
}

- (NSArray *)openDocuments {
    Class controllerClass = NSClassFromString(@"NSDocumentController");
    if (controllerClass == Nil) return @[];
    id controller = HopperMCPCallObject(controllerClass, @selector(sharedDocumentController));
    id documents = HopperMCPCallObject(controller, @selector(documents));
    return [documents isKindOfClass:[NSArray class]] ? documents : @[];
}

- (BOOL)documentHasResolvedFile:(NSObject<HPDocument> *)document {
    return [self documentPath:document].length > 0;
}

- (BOOL)document:(NSObject<HPDocument> *)document matchesTargetPath:(NSString *)targetPath {
    if (![targetPath isKindOfClass:[NSString class]] || targetPath.length == 0) return NO;
    NSString *path = [self documentPath:document];
    if (path.length > 0 && [path isEqualToString:targetPath]) return YES;
    NSString *name = [self documentDisplayName:document];
    return name.length > 0 && [name isEqualToString:targetPath.lastPathComponent];
}

- (NSString *)documentPath:(NSObject<HPDocument> *)document {
    if (document == nil) return nil;
    NSObject<HPDisassembledFile> *file = [document disassembledFile];
    NSString *path = [file originalFilePath];
    if ([path isKindOfClass:[NSString class]] && path.length > 0) return path;

    id url = HopperMCPCallObject(document, @selector(fileURL));
    if ([url isKindOfClass:[NSURL class]]) {
        NSString *urlPath = [(NSURL *)url path];
        if (urlPath.length > 0) return urlPath;
    }

    id fileName = HopperMCPCallObject(document, @selector(fileName));
    return [fileName isKindOfClass:[NSString class]] && [fileName length] > 0 ? fileName : nil;
}

- (NSString *)documentDisplayName:(NSObject<HPDocument> *)document {
    if (document == nil) return nil;
    id displayName = HopperMCPCallObject(document, @selector(displayName));
    return [displayName isKindOfClass:[NSString class]] && [displayName length] > 0 ? displayName : nil;
}

- (NSString *)documentSummary:(NSObject<HPDocument> *)document {
    if (document == nil) return @"<nil>";
    NSString *name = [self documentDisplayName:document] ?: @"<no-display-name>";
    NSString *path = [self documentPath:document] ?: @"<no-path>";
    NSString *hasFile = [document disassembledFile] != nil ? @"yes" : @"no";
    return [NSString stringWithFormat:@"{name=%@ path=%@ disassembledFile=%@}", name, path, hasFile];
}

- (NSDictionary *)hopperStatusPayload {
    return @{
        @"backendMode": @"injected_private",
        @"readiness": @"ready",
        @"hopperVersion": [NSNull null],
        @"hopperBuild": [NSNull null],
        @"capabilities": @{
            @"currentDocument": @YES,
            @"procedures": @YES,
            @"writes": @NO,
            @"privateApi": @YES,
            @"injected": @YES,
            @"status": @YES,
        },
        @"unsupportedReason": [NSNull null],
    };
}

- (NSDictionary *)privateSocketResponseForRequest:(NSDictionary *)request {
    NSString *type = request[@"type"];
    if (![type isKindOfClass:[NSString class]]) {
        return HopperMCPErrorResponse(@"invalid_request", @"request type is required");
    }

    if ([type isEqualToString:@"handshake"]) {
        NSNumber *wireVersion = request[@"wireVersion"];
        if (![wireVersion isKindOfClass:[NSNumber class]] || wireVersion.intValue != 1) {
            return @{
                @"type": @"handshake",
                @"accepted": @NO,
                @"wireVersion": @1,
                @"agentVersion": @"hopper-plugin-0.1.0",
                @"hopperVersion": [NSNull null],
                @"capabilities": @{
                    @"currentDocument": @NO,
                    @"procedures": @NO,
                    @"writes": @NO,
                },
                @"unsupportedReason": @"unsupported wire version",
            };
        }
        return @{
            @"type": @"handshake",
            @"accepted": @YES,
            @"wireVersion": @1,
            @"agentVersion": @"hopper-plugin-0.1.0",
            @"hopperVersion": [NSNull null],
            @"capabilities": [self hopperStatusPayload][@"capabilities"],
            @"unsupportedReason": [NSNull null],
        };
    }

    if ([type isEqualToString:@"status"]) {
        NSMutableDictionary *response = [[self hopperStatusPayload] mutableCopy];
        response[@"type"] = @"status";
        return response;
    }

    if ([type isEqualToString:@"debug_documents"]) {
        NSMutableArray *documents = [NSMutableArray array];
        for (id document in [self openDocuments]) {
            [documents addObject:[self documentSummary:document]];
        }
        return @{
            @"type": @"debug_documents",
            @"serviceCurrentDocument": [self documentSummary:[_services currentDocument]],
            @"resolvedDocument": [self documentSummary:[self resolvedDocument]],
            @"documents": documents,
        };
    }

    if ([type isEqualToString:@"current_document"]) {
        NSDictionary *payload = [self hopperCurrentDocument];
        NSString *code = payload[@"code"];
        NSString *message = payload[@"message"];
        if ([code isKindOfClass:[NSString class]] && [message isKindOfClass:[NSString class]]) {
            return HopperMCPErrorResponse(code, message);
        }
        return @{
            @"type": @"current_document",
            @"documentId": payload[@"documentId"] ?: [NSNull null],
            @"name": payload[@"name"] ?: [NSNull null],
        };
    }

    if ([type isEqualToString:@"list_procedures"]) {
        NSDictionary *payload = [self hopperProcedures:[request[@"maxResults"] isKindOfClass:[NSNumber class]] ? request[@"maxResults"] : nil];
        NSString *code = payload[@"code"];
        NSString *message = payload[@"message"];
        if ([code isKindOfClass:[NSString class]] && [message isKindOfClass:[NSString class]]) {
            return HopperMCPErrorResponse(code, message);
        }
        return @{
            @"type": @"procedures",
            @"procedures": payload[@"procedures"] ?: @[],
            @"truncated": payload[@"truncated"] ?: @NO,
        };
    }

    return HopperMCPErrorResponse(@"unsupported_request", @"unsupported private backend request");
}

- (void)servePrivateSocketClient:(int)clientFd {
    while (1) {
        @autoreleasepool {
            NSData *line = HopperMCPReadLineData(clientFd);
            if (line == nil) return;
            NSDictionary *request = HopperMCPDecodeJsonObject(line);
            NSDictionary *response = request != nil
                ? [self privateSocketResponseForRequest:request]
                : HopperMCPErrorResponse(@"invalid_request", @"request must be valid JSON");
            if (!HopperMCPWriteJsonLine(clientFd, response)) {
                return;
            }
        }
    }
}

- (void)runPrivateSocketServer {
    const char *socketPath = [_privateSocketPath fileSystemRepresentation];
    if (socketPath == NULL || socketPath[0] == '\0') {
        [_services logMessage:@"Hopper MCP private socket path is not configured"];
        return;
    }

    size_t socketPathLength = strlen(socketPath);
    if (socketPathLength >= sizeof(((struct sockaddr_un *)NULL)->sun_path)) {
        [_services logMessage:[NSString stringWithFormat:
            @"Hopper MCP private socket path is too long: %@",
            _privateSocketPath]];
        return;
    }

    unlink(socketPath);
    int serverFd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (serverFd < 0) {
        [_services logMessage:[NSString stringWithFormat:
            @"Hopper MCP private socket() failed for %@: %s",
            _privateSocketPath, strerror(errno)]];
        return;
    }

    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, socketPath, socketPathLength + 1);
    socklen_t addressLength = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + socketPathLength + 1);
    if (bind(serverFd, (struct sockaddr *)&address, addressLength) != 0) {
        [_services logMessage:[NSString stringWithFormat:
            @"Hopper MCP private bind failed for %@: %s",
            _privateSocketPath, strerror(errno)]];
        close(serverFd);
        return;
    }
    if (listen(serverFd, 8) != 0) {
        [_services logMessage:[NSString stringWithFormat:
            @"Hopper MCP private listen failed for %@: %s",
            _privateSocketPath, strerror(errno)]];
        close(serverFd);
        unlink(socketPath);
        return;
    }

    [_services logMessage:[NSString stringWithFormat:
        @"Hopper MCP private socket server listening on %@",
        _privateSocketPath]];
    while (1) {
        int clientFd = accept(serverFd, NULL, NULL);
        if (clientFd < 0) {
            if (errno == EINTR) continue;
            [_services logMessage:[NSString stringWithFormat:
                @"Hopper MCP private accept failed for %@: %s",
                _privateSocketPath, strerror(errno)]];
            break;
        }
        [self servePrivateSocketClient:clientFd];
        close(clientFd);
    }

    close(serverFd);
    unlink(socketPath);
}

- (NSDictionary *)errorWithCode:(NSString *)code message:(NSString *)message {
    return @{
        @"code": code,
        @"message": message,
    };
}

@end

static NSDictionary *HopperMCPErrorResponse(NSString *code, NSString *message) {
    return @{
        @"type": @"error",
        @"code": code,
        @"message": message,
    };
}

static BOOL HopperMCPWriteAll(int fd, const void *bytes, size_t length) {
    const char *cursor = bytes;
    size_t remaining = length;
    while (remaining > 0) {
        ssize_t written = write(fd, cursor, remaining);
        if (written < 0) {
            if (errno == EINTR) continue;
            return NO;
        }
        cursor += written;
        remaining -= (size_t)written;
    }
    return YES;
}

static BOOL HopperMCPWriteJsonLine(int fd, NSDictionary *payload) {
    NSError *error = nil;
    NSData *json = [NSJSONSerialization dataWithJSONObject:payload options:0 error:&error];
    if (json == nil) return NO;
    NSMutableData *line = [json mutableCopy];
    uint8_t newline = '\n';
    [line appendBytes:&newline length:1];
    return HopperMCPWriteAll(fd, line.bytes, line.length);
}

static NSData *HopperMCPReadLineData(int fd) {
    NSMutableData *buffer = [NSMutableData data];
    char byte = 0;
    while (1) {
        ssize_t count = read(fd, &byte, 1);
        if (count == 0) return nil;
        if (count < 0) {
            if (errno == EINTR) continue;
            return nil;
        }
        if (byte == '\n') return buffer;
        [buffer appendBytes:&byte length:1];
    }
}

static NSDictionary *HopperMCPDecodeJsonObject(NSData *data) {
    NSError *error = nil;
    id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    return [object isKindOfClass:[NSDictionary class]] ? object : nil;
}

static id HopperMCPCallObject(id target, SEL selector) {
    if (target == nil || ![target respondsToSelector:selector]) return nil;
    typedef id (*Fn)(id, SEL);
    Fn fn = (Fn)[target methodForSelector:selector];
    return fn == NULL ? nil : fn(target, selector);
}

static void *HopperMCPPrivateSocketServerMain(void *context) {
    @autoreleasepool {
        HopperMCPAgent *agent = CFBridgingRelease(context);
        [agent runPrivateSocketServer];
    }
    return NULL;
}
