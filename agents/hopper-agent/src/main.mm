#import "provider.hh"

#import <Foundation/Foundation.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

@protocol HopperAgentPluginService
- (NSDictionary *)hopperCurrentDocument;
- (NSDictionary *)hopperProcedures:(NSNumber *)maxResults;
@end

@interface HopperAgentFixtureService : NSObject <HopperAgentPluginService>
- (instancetype)initWithDocumentId:(NSString *)documentId
                              name:(NSString *)name
                        procedures:(NSArray<NSDictionary *> *)procedures;
@end

@implementation HopperAgentFixtureService {
  NSString *_documentId;
  NSString *_name;
  NSArray<NSDictionary *> *_procedures;
}

- (instancetype)initWithDocumentId:(NSString *)documentId
                              name:(NSString *)name
                        procedures:(NSArray<NSDictionary *> *)procedures {
  self = [super init];
  if (self != nil) {
    _documentId = [documentId copy];
    _name = [name copy];
    _procedures = [procedures copy];
  }
  return self;
}

- (NSDictionary *)hopperCurrentDocument {
  return @{
    @"documentId" : _documentId ?: @"fixture-document",
    @"name" : _name ?: @"Fixture",
  };
}

- (NSDictionary *)hopperProcedures:(NSNumber *)maxResults {
  const NSUInteger max = [maxResults isKindOfClass:[NSNumber class]]
      ? maxResults.unsignedIntegerValue
      : 0;
  NSMutableArray *procedures = [NSMutableArray array];
  for (NSDictionary *procedure in _procedures) {
    if (max != 0 && procedures.count >= max) break;
    [procedures addObject:procedure];
  }
  return @{
    @"procedures" : procedures,
    @"truncated" : @(max != 0 && _procedures.count > max),
  };
}

@end

namespace {

constexpr int kWireVersion = 1;

volatile std::sig_atomic_t g_should_stop = 0;

void HandleSignal(int) {
  g_should_stop = 1;
}

void InstallSignalHandlers(void) {
  struct sigaction action {};
  action.sa_handler = HandleSignal;
  sigemptyset(&action.sa_mask);
  action.sa_flags = 0;
  sigaction(SIGTERM, &action, nullptr);
  sigaction(SIGINT, &action, nullptr);
}

NSString *ToNSString(const std::string &value) {
  return [[NSString alloc] initWithBytes:value.data()
                                  length:value.size()
                                encoding:NSUTF8StringEncoding];
}

NSDictionary *ProcedureObject(const Procedure &procedure) {
  return @{
    @"addr" : ToNSString(procedure.addr),
    @"name" : ToNSString(procedure.name),
    @"size" : @(procedure.size.value_or(0)),
  };
}

NSArray<NSDictionary *> *FixtureProceduresArray(const Options &options) {
  NSMutableArray *procedures = [NSMutableArray array];
  for (const Procedure &procedure : options.procedures) {
    [procedures addObject:ProcedureObject(procedure)];
  }
  return procedures;
}

void PrintUsage(const char *program) {
  std::fprintf(stderr,
               "Usage: %s --socket PATH [--fixture] [--private-provider NAME] "
               "[--plugin-service NAME] [--service-fixture-name NAME] "
               "[--official-mcp-command PATH] [--fixture-document-id ID] "
               "[--fixture-document-name NAME]\n",
               program);
}

bool ParseProcedure(const std::string &value, Procedure *procedure) {
  const size_t first = value.find(':');
  const size_t second = first == std::string::npos ? std::string::npos : value.find(':', first + 1);
  if (first == std::string::npos || second == std::string::npos) {
    std::fprintf(stderr, "--fixture-procedure must use ADDR:NAME:SIZE\n");
    return false;
  }
  procedure->addr = value.substr(0, first);
  procedure->name = value.substr(first + 1, second - first - 1);
  const std::string size_text = value.substr(second + 1);
  if (procedure->addr.empty() || procedure->name.empty() || size_text.empty()) {
    std::fprintf(stderr, "--fixture-procedure must use non-empty ADDR:NAME:SIZE\n");
    return false;
  }
  char *end = nullptr;
  const unsigned long long size = std::strtoull(size_text.c_str(), &end, 10);
  if (end == size_text.c_str() || *end != '\0') {
    std::fprintf(stderr, "--fixture-procedure size must be an integer\n");
    return false;
  }
  procedure->size = size;
  return true;
}

bool ParseArgs(int argc, char **argv, Options *options) {
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    auto require_value = [&](const char *name) -> const char * {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "%s requires a value\n", name);
        return nullptr;
      }
      return argv[++i];
    };

    if (arg == "--fixture") {
      options->fixture_mode = true;
    } else if (arg == "--private-provider") {
      const char *value = require_value("--private-provider");
      if (value == nullptr) return false;
      options->private_provider = value;
    } else if (arg == "--plugin-service") {
      const char *value = require_value("--plugin-service");
      if (value == nullptr) return false;
      options->plugin_service_name = value;
    } else if (arg == "--service-fixture-name") {
      const char *value = require_value("--service-fixture-name");
      if (value == nullptr) return false;
      options->service_fixture_name = value;
    } else if (arg == "--socket") {
      const char *value = require_value("--socket");
      if (value == nullptr) return false;
      options->socket_path = value;
    } else if (arg == "--fixture-document-id") {
      const char *value = require_value("--fixture-document-id");
      if (value == nullptr) return false;
      options->document_id = value;
    } else if (arg == "--fixture-document-name") {
      const char *value = require_value("--fixture-document-name");
      if (value == nullptr) return false;
      options->document_name = value;
    } else if (arg == "--fixture-procedure") {
      const char *value = require_value("--fixture-procedure");
      if (value == nullptr) return false;
      Procedure procedure;
      if (!ParseProcedure(value, &procedure)) return false;
      options->procedures.push_back(procedure);
    } else if (arg == "--official-mcp-command") {
      const char *value = require_value("--official-mcp-command");
      if (value == nullptr) return false;
      options->official_mcp_command = value;
    } else if (arg == "--official-timeout-ms") {
      const char *value = require_value("--official-timeout-ms");
      if (value == nullptr) return false;
      char *end = nullptr;
      const long parsed = std::strtol(value, &end, 10);
      if (end == value || *end != '\0' || parsed <= 0 || parsed > 600000) {
        std::fprintf(stderr, "--official-timeout-ms must be an integer between 1 and 600000\n");
        return false;
      }
      options->official_timeout_ms = static_cast<int>(parsed);
    } else if (arg == "--help" || arg == "-h") {
      PrintUsage(argv[0]);
      std::exit(0);
    } else {
      std::fprintf(stderr, "unknown argument: %s\n", arg.c_str());
      return false;
    }
  }

  if (!options->service_fixture_name.empty() && !options->socket_path.empty()) {
    std::fprintf(stderr, "--service-fixture-name cannot be combined with --socket\n");
    return false;
  }
  if (options->private_provider != "official" &&
      options->private_provider != "fixture-injected") {
    std::fprintf(stderr, "--private-provider must be one of: official, fixture-injected\n");
    return false;
  }
  if (options->fixture_mode && !options->plugin_service_name.empty()) {
    std::fprintf(stderr, "--fixture cannot be combined with --plugin-service\n");
    return false;
  }
  if (!options->service_fixture_name.empty() && options->fixture_mode) {
    std::fprintf(stderr, "--service-fixture-name cannot be combined with --fixture\n");
    return false;
  }
  if (!options->service_fixture_name.empty() && !options->plugin_service_name.empty()) {
    std::fprintf(stderr, "--service-fixture-name cannot be combined with --plugin-service\n");
    return false;
  }
  if (options->private_provider == "fixture-injected" && options->fixture_mode) {
    std::fprintf(stderr, "--private-provider fixture-injected cannot be combined with --fixture\n");
    return false;
  }
  if (options->private_provider == "fixture-injected" && !options->plugin_service_name.empty()) {
    std::fprintf(stderr,
                 "--private-provider fixture-injected cannot be combined with --plugin-service\n");
    return false;
  }
  if (options->private_provider == "fixture-injected" &&
      !options->service_fixture_name.empty()) {
    std::fprintf(stderr,
                 "--private-provider fixture-injected cannot be combined with --service-fixture-name\n");
    return false;
  }
  if (options->service_fixture_name.empty() && options->socket_path.empty()) {
    std::fprintf(stderr, "--socket is required\n");
    return false;
  }
  if (!options->fixture_mode && options->plugin_service_name.empty() &&
      options->service_fixture_name.empty() && options->official_mcp_command.empty() &&
      options->private_provider == "official") {
    std::fprintf(stderr, "--official-mcp-command cannot be empty outside fixture mode\n");
    return false;
  }
  if (options->plugin_service_name == "auto") {
    options->plugin_service_name = PluginServiceNameForSocketPath(options->socket_path);
  }
  return true;
}

std::string ToJsonLine(NSDictionary *payload) {
  NSError *error = nil;
  NSData *data = [NSJSONSerialization dataWithJSONObject:payload options:0 error:&error];
  if (data == nil) {
    return "{\"type\":\"error\",\"code\":\"encode_failed\",\"message\":\"failed to encode JSON\"}\n";
  }
  std::string line(static_cast<const char *>(data.bytes), data.length);
  line.push_back('\n');
  return line;
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

bool ReadLine(int fd, std::string *line) {
  line->clear();
  char byte = 0;
  while (!g_should_stop) {
    const ssize_t count = read(fd, &byte, 1);
    if (count == 0) return false;
    if (count < 0) {
      if (errno == EINTR && !g_should_stop) continue;
      return false;
    }
    if (byte == '\n') return true;
    line->push_back(byte);
  }
  return false;
}

NSDictionary *ErrorResponse(NSString *code, NSString *message) {
  return @{
    @"type" : @"error",
    @"code" : code,
    @"message" : message,
  };
}

NSDictionary *HandshakeResponse(EvidenceProvider *provider) {
  NSString *error = nil;
  NSDictionary *status = provider->Status(&error);
  NSDictionary *capabilities = [status[@"capabilities"] isKindOfClass:[NSDictionary class]]
      ? status[@"capabilities"]
      : @{
          @"currentDocument" : @YES,
          @"procedures" : @YES,
          @"writes" : @NO,
        };
  id hopper_version = status[@"hopperVersion"];
  if (hopper_version == nil) hopper_version = [NSNull null];
  id unsupported_reason = status[@"unsupportedReason"];
  if (unsupported_reason == nil) unsupported_reason = error ?: [NSNull null];
  return @{
    @"type" : @"handshake",
    @"accepted" : @YES,
    @"wireVersion" : @(kWireVersion),
    @"agentVersion" : @"hopper-agent-0.1.0",
    @"hopperVersion" : hopper_version,
    @"capabilities" : capabilities,
    @"unsupportedReason" : unsupported_reason,
  };
}

NSDictionary *StatusResponse(EvidenceProvider *provider) {
  NSString *error = nil;
  NSDictionary *status = provider->Status(&error);
  if (status == nil) return ErrorResponse(@"provider_failed", error ?: @"status unavailable");
  NSMutableDictionary *response = [status mutableCopy];
  response[@"type"] = @"status";
  return response;
}

NSDictionary *HandleRequest(NSDictionary *request, EvidenceProvider *provider) {
  NSString *type = request[@"type"];
  if (![type isKindOfClass:[NSString class]]) {
    return ErrorResponse(@"invalid_request", @"request type is required");
  }

  if ([type isEqualToString:@"handshake"]) {
    NSNumber *wire_version = request[@"wireVersion"];
    if (![wire_version isKindOfClass:[NSNumber class]] ||
        wire_version.intValue != kWireVersion) {
      return @{
        @"type" : @"handshake",
        @"accepted" : @NO,
        @"wireVersion" : @(kWireVersion),
        @"agentVersion" : @"hopper-agent-0.1.0",
        @"hopperVersion" : [NSNull null],
        @"capabilities" : @{
          @"currentDocument" : @NO,
          @"procedures" : @NO,
          @"writes" : @NO,
        },
        @"unsupportedReason" : @"unsupported wire version",
      };
    }
    return HandshakeResponse(provider);
  }

  if ([type isEqualToString:@"status"]) {
    return StatusResponse(provider);
  }

  if ([type isEqualToString:@"current_document"]) {
    NSString *error = nil;
    NSDictionary *response = provider->CurrentDocument(&error);
    return response ?: ErrorResponse(@"provider_failed", error ?: @"current document unavailable");
  }

  if ([type isEqualToString:@"list_procedures"]) {
    NSNumber *max_results = request[@"maxResults"];
    const NSUInteger max = [max_results isKindOfClass:[NSNumber class]]
        ? max_results.unsignedIntegerValue
        : 0;
    NSString *error = nil;
    NSDictionary *response = provider->Procedures(max, &error);
    return response ?: ErrorResponse(@"provider_failed", error ?: @"procedures unavailable");
  }

  return ErrorResponse(@"unsupported_request", @"unsupported hopper-agent request");
}

int RunServiceFixture(const Options &options) {
  HopperAgentFixtureService *service = [[HopperAgentFixtureService alloc]
      initWithDocumentId:ToNSString(options.document_id)
                    name:ToNSString(options.document_name)
              procedures:FixtureProceduresArray(options)];
  NSConnection *connection =
      [NSConnection serviceConnectionWithName:ToNSString(options.service_fixture_name)
                                   rootObject:service];
  if (connection == nil) {
    std::fprintf(stderr, "failed to register distributed fixture service: %s\n",
                 options.service_fixture_name.c_str());
    return 1;
  }

  while (!g_should_stop) {
    @autoreleasepool {
      [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode
                               beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.1]];
    }
  }

  [connection invalidate];
  return 0;
}

void ServeClient(int client_fd, EvidenceProvider *provider) {
  std::string line;
  while (ReadLine(client_fd, &line)) {
    @autoreleasepool {
      NSDictionary *request = ParseJsonObject(line);
      NSDictionary *response = request == nil
          ? ErrorResponse(@"invalid_json", @"request must be a JSON object")
          : HandleRequest(request, provider);
      if (!WriteAll(client_fd, ToJsonLine(response))) break;
    }
  }
}

int CreateServerSocket(const std::string &socket_path) {
  if (socket_path.size() >= sizeof(sockaddr_un::sun_path)) {
    std::fprintf(stderr, "socket path is too long: %s\n", socket_path.c_str());
    return -1;
  }

  const int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    std::perror("socket");
    return -1;
  }

  sockaddr_un addr {};
  addr.sun_family = AF_UNIX;
  std::strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);
  unlink(socket_path.c_str());
  if (bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
    std::perror("bind");
    close(fd);
    return -1;
  }
  if (listen(fd, 16) < 0) {
    std::perror("listen");
    close(fd);
    return -1;
  }
  return fd;
}

}  // namespace

bool HopperAgentShouldStop(void) {
  return g_should_stop != 0;
}

int main(int argc, char **argv) {
  @autoreleasepool {
    Options options;
    if (!ParseArgs(argc, argv, &options)) {
      PrintUsage(argv[0]);
      return 2;
    }

    InstallSignalHandlers();
    if (!options.service_fixture_name.empty()) {
      return RunServiceFixture(options);
    }

    NSString *provider_error = nil;
    std::unique_ptr<EvidenceProvider> provider = CreateEvidenceProvider(options, &provider_error);
    if (provider == nullptr) {
      std::fprintf(stderr, "%s\n", provider_error != nil ? provider_error.UTF8String : "failed to create provider");
      return 1;
    }

    const int server_fd = CreateServerSocket(options.socket_path);
    if (server_fd < 0) return 1;

    while (!g_should_stop) {
      const int client_fd = accept(server_fd, nullptr, nullptr);
      if (client_fd < 0) {
        if (errno == EINTR) continue;
        std::perror("accept");
        break;
      }
      ServeClient(client_fd, provider.get());
      close(client_fd);
    }

    close(server_fd);
    unlink(options.socket_path.c_str());
  }
  return 0;
}
