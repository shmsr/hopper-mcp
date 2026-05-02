#import <Foundation/Foundation.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

struct Procedure {
  std::string addr;
  std::string name;
  std::optional<unsigned long long> size;
};

struct Options {
  std::string socket_path;
  std::string private_provider = "official";
  std::string document_id = "fixture-document";
  std::string document_name = "Fixture";
  std::vector<Procedure> procedures;
  std::string plugin_service_name;
  std::string service_fixture_name;
  std::string official_mcp_command =
      "/Applications/Hopper Disassembler.app/Contents/MacOS/HopperMCPServer";
  int official_timeout_ms = 30000;
  bool fixture_mode = false;
};

class EvidenceProvider {
 public:
  virtual ~EvidenceProvider() = default;
  virtual NSDictionary *Status(NSString **error) = 0;
  virtual NSDictionary *CurrentDocument(NSString **error) = 0;
  virtual NSDictionary *Procedures(NSUInteger max_results, NSString **error) = 0;
};

bool HopperAgentShouldStop(void);
std::unique_ptr<EvidenceProvider> CreateEvidenceProvider(const Options &options, NSString **error);
std::string PluginServiceNameForSocketPath(const std::string &socket_path);
