#import "provider.hh"

#import "injector.hh"

#include <csignal>
#include <cstdio>
#include <cstring>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

@protocol HopperAgentPluginService
- (NSDictionary *)hopperCurrentDocument;
- (NSDictionary *)hopperProcedures:(NSNumber *)maxResults;
@end

namespace {

NSString *const kOfficialProtocolVersion = @"2025-03-26";

NSString *ToNSString(const std::string &value) {
  return [[NSString alloc] initWithBytes:value.data()
                                  length:value.size()
                                encoding:NSUTF8StringEncoding];
}

NSDictionary *ErrorResponse(NSString *code, NSString *message) {
  return @{
    @"type" : @"error",
    @"code" : code,
    @"message" : message,
  };
}

NSString *MessageOrFallback(NSString **error, NSString *fallback) {
  return error != nullptr && *error != nil ? *error : fallback;
}

NSDictionary *ProcedureObject(const Procedure &procedure) {
  return @{
    @"addr" : ToNSString(procedure.addr),
    @"name" : ToNSString(procedure.name),
    @"size" : @(procedure.size.value_or(0)),
  };
}

bool WriteAll(int fd, const std::string &data) {
  const char *cursor = data.data();
  size_t remaining = data.size();
  while (remaining > 0) {
    const ssize_t written = write(fd, cursor, remaining);
    if (written < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    cursor += written;
    remaining -= static_cast<size_t>(written);
  }
  return true;
}

NSDictionary *ParseJsonObject(const std::string &line) {
  NSData *data = [NSData dataWithBytes:line.data() length:line.size()];
  NSError *error = nil;
  id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
  if (![object isKindOfClass:[NSDictionary class]]) {
    return nil;
  }
  return static_cast<NSDictionary *>(object);
}

bool ReadLineWithTimeout(int fd, int timeout_ms, std::string *line) {
  line->clear();
  const auto deadline = [timeout_ms]() {
    timeval now {};
    gettimeofday(&now, nullptr);
    const long long now_ms = static_cast<long long>(now.tv_sec) * 1000 + now.tv_usec / 1000;
    return now_ms + timeout_ms;
  }();

  char byte = 0;
  while (true) {
    if (HopperAgentShouldStop()) return false;

    timeval now {};
    gettimeofday(&now, nullptr);
    const long long now_ms = static_cast<long long>(now.tv_sec) * 1000 + now.tv_usec / 1000;
    const long long remaining_ms = deadline - now_ms;
    if (remaining_ms <= 0) return false;

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);
    timeval timeout {};
    timeout.tv_sec = static_cast<time_t>(remaining_ms / 1000);
    timeout.tv_usec = static_cast<suseconds_t>((remaining_ms % 1000) * 1000);
    const int ready = select(fd + 1, &read_fds, nullptr, nullptr, &timeout);
    if (ready == 0) return false;
    if (ready < 0) {
      if (errno == EINTR && HopperAgentShouldStop()) return false;
      if (errno == EINTR) continue;
      return false;
    }

    const ssize_t count = read(fd, &byte, 1);
    if (count == 0) return false;
    if (count < 0) {
      if (errno == EINTR && HopperAgentShouldStop()) return false;
      if (errno == EINTR) continue;
      return false;
    }
    if (byte == '\n') return true;
    line->push_back(byte);
  }
  return false;
}

NSDictionary *RpcRequest(NSInteger request_id, NSString *method, NSDictionary *params) {
  return @{
    @"jsonrpc" : @"2.0",
    @"id" : @(request_id),
    @"method" : method,
    @"params" : params,
  };
}

bool WriteJsonLineToFd(int fd, NSDictionary *payload, NSString **error) {
  NSError *json_error = nil;
  NSData *data = [NSJSONSerialization dataWithJSONObject:payload options:0 error:&json_error];
  if (data == nil) {
    if (error != nullptr) *error = json_error.localizedDescription;
    return false;
  }
  std::string line(static_cast<const char *>(data.bytes), data.length);
  line.push_back('\n');
  if (!WriteAll(fd, line)) {
    if (error != nullptr) *error = [NSString stringWithFormat:@"write failed: %s", std::strerror(errno)];
    return false;
  }
  return true;
}

NSDictionary *ReadRpcResponse(int fd, NSInteger expected_id, int timeout_ms, NSString **error) {
  std::string line;
  while (ReadLineWithTimeout(fd, timeout_ms, &line)) {
    NSDictionary *message = ParseJsonObject(line);
    if (message == nil) continue;
    NSNumber *message_id = message[@"id"];
    if (![message_id isKindOfClass:[NSNumber class]] || message_id.integerValue != expected_id) {
      continue;
    }
    return message;
  }
  if (error != nullptr) {
    *error = HopperAgentShouldStop()
        ? @"official Hopper MCP request cancelled due to shutdown"
        : @"timed out waiting for official Hopper MCP response";
  }
  return nil;
}

id DecodeOfficialToolText(NSDictionary *result, NSString **error) {
  NSArray *content = result[@"content"];
  if (![content isKindOfClass:[NSArray class]]) {
    if (error != nullptr) *error = @"official Hopper MCP result did not contain content[]";
    return nil;
  }
  for (id item in content) {
    if (![item isKindOfClass:[NSDictionary class]]) continue;
    NSDictionary *entry = static_cast<NSDictionary *>(item);
    if (![entry[@"type"] isEqual:@"text"]) continue;
    NSString *text = entry[@"text"];
    if (![text isKindOfClass:[NSString class]]) continue;
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    NSError *json_error = nil;
    id decoded = [NSJSONSerialization JSONObjectWithData:data options:0 error:&json_error];
    return decoded ?: text;
  }
  if (error != nullptr) *error = @"official Hopper MCP result did not contain text content";
  return nil;
}

class OfficialMcpBridge {
 public:
  explicit OfficialMcpBridge(const Options &options) : options_(options) {}

  ~OfficialMcpBridge() {
    Terminate();
  }

  id ToolPayload(NSString *tool_name, NSDictionary *arguments, NSString **error);

 private:
  bool EnsureStarted(NSString **error);
  NSDictionary *Request(NSString *method, NSDictionary *params, NSString **error);
  void Terminate();

  Options options_;
  NSTask *task_ = nil;
  NSPipe *stdin_pipe_ = nil;
  NSPipe *stdout_pipe_ = nil;
  NSPipe *stderr_pipe_ = nil;
  NSInteger next_request_id_ = 0;
  bool initialized_ = false;
};

class PluginServiceBridge {
 public:
  explicit PluginServiceBridge(const Options &options) : options_(options) {}

  NSDictionary *CurrentDocument(NSString **error);
  NSDictionary *Procedures(NSUInteger max_results, NSString **error);

 private:
  bool EnsureConnected(NSString **error);
  void Reset();

  Options options_;
  NSConnection *connection_ = nil;
  id<HopperAgentPluginService> proxy_ = nil;
};

class FixtureEvidenceProvider : public EvidenceProvider {
 public:
  explicit FixtureEvidenceProvider(const Options &options) : options_(options) {}

  NSDictionary *Status(NSString **) override {
    return @{
      @"backendMode" : @"fixture_private",
      @"readiness" : @"ready",
      @"hopperVersion" : @"fixture",
      @"hopperBuild" : @"fixture",
      @"capabilities" : @{
        @"currentDocument" : @YES,
        @"procedures" : @YES,
        @"writes" : @NO,
        @"privateApi" : @YES,
        @"injected" : @NO,
        @"status" : @YES,
      },
      @"unsupportedReason" : [NSNull null],
    };
  }

  NSDictionary *CurrentDocument(NSString **) override {
    return @{
      @"type" : @"current_document",
      @"documentId" : ToNSString(options_.document_id),
      @"name" : ToNSString(options_.document_name),
    };
  }

  NSDictionary *Procedures(NSUInteger max_results, NSString **) override {
    NSMutableArray *procedures = [NSMutableArray array];
    NSUInteger emitted = 0;
    for (const Procedure &procedure : options_.procedures) {
      if (max_results != 0 && emitted >= max_results) break;
      [procedures addObject:ProcedureObject(procedure)];
      emitted += 1;
    }
    return @{
      @"type" : @"procedures",
      @"procedures" : procedures,
      @"truncated" : @(max_results != 0 && options_.procedures.size() > max_results),
    };
  }

 private:
  Options options_;
};

class InjectedEvidenceProvider : public EvidenceProvider {
 public:
  explicit InjectedEvidenceProvider(const Options &options) : injector_(options) {}

  NSDictionary *Status(NSString **error) override {
    if (!injector_.EnsureInjected(error)) return nil;
    return injector_.Status();
  }

  NSDictionary *CurrentDocument(NSString **error) override {
    return injector_.CurrentDocument(error);
  }

  NSDictionary *Procedures(NSUInteger max_results, NSString **error) override {
    return injector_.Procedures(max_results, error);
  }

 private:
  HopperInjector injector_;
};

class PluginEvidenceProvider : public EvidenceProvider {
 public:
  explicit PluginEvidenceProvider(const Options &options) : bridge_(options) {}

  NSDictionary *Status(NSString **) override {
    return @{
      @"backendMode" : @"plugin_private",
      @"readiness" : @"ready",
      @"hopperVersion" : [NSNull null],
      @"hopperBuild" : [NSNull null],
      @"capabilities" : @{
        @"currentDocument" : @YES,
        @"procedures" : @YES,
        @"writes" : @NO,
        @"privateApi" : @YES,
        @"injected" : @NO,
        @"status" : @YES,
      },
      @"unsupportedReason" : [NSNull null],
    };
  }

  NSDictionary *CurrentDocument(NSString **error) override {
    NSDictionary *payload = bridge_.CurrentDocument(error);
    if (payload == nil) {
      return ErrorResponse(@"plugin_service_failed",
                           MessageOrFallback(error, @"plugin current_document returned no payload"));
    }
    NSString *code = payload[@"code"];
    NSString *message = payload[@"message"];
    if ([code isKindOfClass:[NSString class]] && [message isKindOfClass:[NSString class]]) {
      return ErrorResponse(code, message);
    }
    NSString *document_id = payload[@"documentId"];
    NSString *name = payload[@"name"];
    if (![document_id isKindOfClass:[NSString class]] || [document_id length] == 0 ||
        ![name isKindOfClass:[NSString class]] || [name length] == 0) {
      return ErrorResponse(@"plugin_service_invalid_response",
                           @"plugin current_document returned an invalid payload");
    }
    return @{
      @"type" : @"current_document",
      @"documentId" : document_id,
      @"name" : name,
    };
  }

  NSDictionary *Procedures(NSUInteger max_results, NSString **error) override {
    NSDictionary *payload = bridge_.Procedures(max_results, error);
    if (payload == nil) {
      return ErrorResponse(@"plugin_service_failed",
                           MessageOrFallback(error, @"plugin list_procedures returned no payload"));
    }
    NSString *code = payload[@"code"];
    NSString *message = payload[@"message"];
    if ([code isKindOfClass:[NSString class]] && [message isKindOfClass:[NSString class]]) {
      return ErrorResponse(code, message);
    }
    NSArray *procedures = payload[@"procedures"];
    NSNumber *truncated = payload[@"truncated"];
    if (![procedures isKindOfClass:[NSArray class]] ||
        ![truncated isKindOfClass:[NSNumber class]]) {
      return ErrorResponse(@"plugin_service_invalid_response",
                           @"plugin list_procedures returned an invalid payload");
    }
    return @{
      @"type" : @"procedures",
      @"procedures" : procedures,
      @"truncated" : truncated,
    };
  }

 private:
  PluginServiceBridge bridge_;
};

class OfficialEvidenceProvider : public EvidenceProvider {
 public:
  explicit OfficialEvidenceProvider(const Options &options) : bridge_(options) {}

  NSDictionary *Status(NSString **) override {
    return @{
      @"backendMode" : @"official_mcp",
      @"readiness" : @"ready",
      @"hopperVersion" : [NSNull null],
      @"hopperBuild" : [NSNull null],
      @"capabilities" : @{
        @"currentDocument" : @YES,
        @"procedures" : @YES,
        @"writes" : @NO,
        @"privateApi" : @NO,
        @"injected" : @NO,
        @"status" : @YES,
      },
      @"unsupportedReason" : [NSNull null],
    };
  }

  NSDictionary *CurrentDocument(NSString **error) override {
    id payload = bridge_.ToolPayload(@"current_document", @{}, error);
    if (payload == nil) {
      return ErrorResponse(@"official_mcp_failed",
                           MessageOrFallback(error, @"official current_document returned no payload"));
    }
    if (![payload isKindOfClass:[NSString class]] || [static_cast<NSString *>(payload) length] == 0) {
      return ErrorResponse(@"official_mcp_invalid_response",
                           @"official current_document did not return a document name");
    }
    return @{
      @"type" : @"current_document",
      @"documentId" : payload,
      @"name" : payload,
    };
  }

  NSDictionary *Procedures(NSUInteger max_results, NSString **error) override {
    id payload = bridge_.ToolPayload(@"list_procedure_size", @{}, error);
    if (payload == nil) {
      return ErrorResponse(@"official_mcp_failed",
                           MessageOrFallback(error, @"official list_procedure_size returned no payload"));
    }
    if (![payload isKindOfClass:[NSDictionary class]]) {
      return ErrorResponse(@"official_mcp_invalid_response",
                           @"official list_procedure_size did not return an address-keyed object");
    }

    NSMutableArray *procedures = [NSMutableArray array];
    NSUInteger emitted = 0;
    NSDictionary *map = static_cast<NSDictionary *>(payload);
    for (id key in map) {
      if (max_results != 0 && emitted >= max_results) break;
      if (![key isKindOfClass:[NSString class]]) continue;
      id value = map[key];
      NSString *name = nil;
      NSNumber *size = nil;
      if ([value isKindOfClass:[NSDictionary class]]) {
        NSDictionary *info = static_cast<NSDictionary *>(value);
        id candidate_name = info[@"name"];
        if ([candidate_name isKindOfClass:[NSString class]]) name = candidate_name;
        id candidate_size = info[@"size"] ?: info[@"length"];
        if ([candidate_size isKindOfClass:[NSNumber class]]) size = candidate_size;
      } else if ([value isKindOfClass:[NSString class]]) {
        name = value;
      }
      [procedures addObject:@{
        @"addr" : key,
        @"name" : name ?: [NSNull null],
        @"size" : size ?: [NSNull null],
      }];
      emitted += 1;
    }
    return @{
      @"type" : @"procedures",
      @"procedures" : procedures,
      @"truncated" : @(max_results != 0 && map.count > max_results),
    };
  }

 private:
  OfficialMcpBridge bridge_;
};

bool PluginServiceBridge::EnsureConnected(NSString **error) {
  if (proxy_ != nil && connection_ != nil && connection_.isValid) return true;
  Reset();

  NSString *service_name = ToNSString(options_.plugin_service_name);
  connection_ = [NSConnection connectionWithRegisteredName:service_name host:nil];
  if (connection_ == nil) {
    if (error != nullptr) {
      *error = [NSString stringWithFormat:@"distributed service is not registered: %@",
                                        service_name];
    }
    return false;
  }

  NSDistantObject *proxy = [connection_ rootProxy];
  if (proxy == nil) {
    if (error != nullptr) *error = @"distributed service returned no root proxy";
    Reset();
    return false;
  }
  [proxy setProtocolForProxy:@protocol(HopperAgentPluginService)];
  proxy_ = static_cast<id<HopperAgentPluginService>>(proxy);
  return true;
}

void PluginServiceBridge::Reset() {
  if (connection_ != nil) [connection_ invalidate];
  connection_ = nil;
  proxy_ = nil;
}

NSDictionary *PluginServiceBridge::CurrentDocument(NSString **error) {
  if (!EnsureConnected(error)) return nil;
  @try {
    id payload = [proxy_ hopperCurrentDocument];
    return [payload isKindOfClass:[NSDictionary class]]
        ? static_cast<NSDictionary *>(payload)
        : nil;
  } @catch (NSException *exception) {
    if (error != nullptr) *error = exception.reason ?: exception.name;
    Reset();
    return nil;
  }
}

NSDictionary *PluginServiceBridge::Procedures(NSUInteger max_results, NSString **error) {
  if (!EnsureConnected(error)) return nil;
  @try {
    id payload = [proxy_ hopperProcedures:(max_results == 0 ? nil : @(max_results))];
    return [payload isKindOfClass:[NSDictionary class]]
        ? static_cast<NSDictionary *>(payload)
        : nil;
  } @catch (NSException *exception) {
    if (error != nullptr) *error = exception.reason ?: exception.name;
    Reset();
    return nil;
  }
}

bool OfficialMcpBridge::EnsureStarted(NSString **error) {
  if (initialized_ && task_ != nil && task_.isRunning) return true;
  Terminate();

  task_ = [[NSTask alloc] init];
  task_.executableURL = [NSURL fileURLWithPath:ToNSString(options_.official_mcp_command)];
  stdin_pipe_ = [NSPipe pipe];
  stdout_pipe_ = [NSPipe pipe];
  stderr_pipe_ = [NSPipe pipe];
  task_.standardInput = stdin_pipe_;
  task_.standardOutput = stdout_pipe_;
  task_.standardError = stderr_pipe_;

  NSError *launch_error = nil;
  if (![task_ launchAndReturnError:&launch_error]) {
    if (error != nullptr) *error = launch_error.localizedDescription;
    Terminate();
    return false;
  }

  NSString *local_error = nil;
  NSDictionary *initialize_response = Request(@"initialize", @{
    @"protocolVersion" : kOfficialProtocolVersion,
    @"capabilities" : @{},
    @"clientInfo" : @{
      @"name" : @"hopper-agent-official-bridge",
      @"version" : @"0.1.0",
    },
  }, &local_error);
  if (initialize_response == nil) {
    if (error != nullptr) *error = local_error;
    Terminate();
    return false;
  }
  NSDictionary *initialize_error = initialize_response[@"error"];
  if ([initialize_error isKindOfClass:[NSDictionary class]]) {
    if (error != nullptr) *error = initialize_error[@"message"] ?: @"official Hopper MCP initialize failed";
    Terminate();
    return false;
  }
  initialized_ = true;
  return true;
}

NSDictionary *OfficialMcpBridge::Request(NSString *method, NSDictionary *params, NSString **error) {
  if (task_ == nil || !task_.isRunning) {
    if (error != nullptr) *error = @"official Hopper MCP subprocess is not running";
    return nil;
  }

  const NSInteger request_id = ++next_request_id_;
  const int stdin_fd = stdin_pipe_.fileHandleForWriting.fileDescriptor;
  const int stdout_fd = stdout_pipe_.fileHandleForReading.fileDescriptor;
  NSString *local_error = nil;
  NSDictionary *request = RpcRequest(request_id, method, params ?: @{});
  if (!WriteJsonLineToFd(stdin_fd, request, &local_error)) {
    if (error != nullptr) *error = local_error;
    Terminate();
    return nil;
  }
  NSDictionary *response = ReadRpcResponse(stdout_fd, request_id, options_.official_timeout_ms, &local_error);
  if (response == nil) {
    if (error != nullptr) *error = local_error;
    Terminate();
    return nil;
  }
  return response;
}

id OfficialMcpBridge::ToolPayload(NSString *tool_name, NSDictionary *arguments, NSString **error) {
  NSString *local_error = nil;
  if (!EnsureStarted(&local_error)) {
    if (error != nullptr) *error = local_error;
    return nil;
  }

  NSDictionary *tool_response = Request(@"tools/call", @{
    @"name" : tool_name,
    @"arguments" : arguments ?: @{},
  }, &local_error);
  if (tool_response == nil) {
    if (error != nullptr) *error = local_error;
    return nil;
  }

  NSDictionary *tool_error = tool_response[@"error"];
  if ([tool_error isKindOfClass:[NSDictionary class]]) {
    if (error != nullptr) *error = tool_error[@"message"] ?: @"official Hopper MCP tool call failed";
    return nil;
  }
  NSDictionary *result = tool_response[@"result"];
  if (![result isKindOfClass:[NSDictionary class]]) {
    if (error != nullptr) *error = @"official Hopper MCP tool call returned no result object";
    return nil;
  }
  id payload = DecodeOfficialToolText(result, &local_error);
  if (payload == nil && error != nullptr) *error = local_error;
  return payload;
}

void OfficialMcpBridge::Terminate() {
  initialized_ = false;
  if (task_ != nil && task_.isRunning) {
    [task_ terminate];
    NSDate *deadline = [NSDate dateWithTimeIntervalSinceNow:1.0];
    while (task_.isRunning && [deadline timeIntervalSinceNow] > 0) {
      [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                               beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    }
    if (task_.isRunning) {
      kill(task_.processIdentifier, SIGKILL);
    }
  }
  task_ = nil;
  stdin_pipe_ = nil;
  stdout_pipe_ = nil;
  stderr_pipe_ = nil;
}

}  // namespace

std::unique_ptr<EvidenceProvider> CreateEvidenceProvider(const Options &options, NSString **error) {
  if (options.fixture_mode) {
    return std::make_unique<FixtureEvidenceProvider>(options);
  }
  if (!options.plugin_service_name.empty()) {
    return std::make_unique<PluginEvidenceProvider>(options);
  }
  if (options.private_provider == "fixture-injected") {
    return std::make_unique<InjectedEvidenceProvider>(options);
  }
  if (options.private_provider != "official") {
    if (error != nullptr) {
      *error = [NSString stringWithFormat:@"unsupported --private-provider: %s",
                                        options.private_provider.c_str()];
    }
    return nullptr;
  }
  return std::make_unique<OfficialEvidenceProvider>(options);
}

std::string PluginServiceNameForSocketPath(const std::string &socket_path) {
  std::string sanitized;
  sanitized.reserve(socket_path.size());
  for (char ch : socket_path) {
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
        (ch >= '0' && ch <= '9')) {
      sanitized.push_back(ch);
    } else {
      sanitized.push_back('-');
    }
  }
  while (!sanitized.empty() && sanitized.back() == '-') sanitized.pop_back();
  if (sanitized.empty()) sanitized = "default";
  if (sanitized.size() > 80) sanitized.resize(80);
  return "dev.hopper-mcp.plugin." + sanitized;
}
