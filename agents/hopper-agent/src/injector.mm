#import "injector.hh"

#import "provider.hh"

namespace {

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

}  // namespace

HopperInjector::HopperInjector(const Options &options) : options_(options) {}

bool HopperInjector::EnsureInjected(NSString **error) {
  if (options_.private_provider == "fixture-injected") return true;
  if (error != nullptr) *error = @"unsupported injected provider";
  return false;
}

NSDictionary *HopperInjector::Status() const {
  return @{
    @"backendMode" : @"injected_private",
    @"readiness" : @"ready",
    @"hopperVersion" : @"fixture",
    @"hopperBuild" : @"fixture",
    @"capabilities" : @{
      @"currentDocument" : @YES,
      @"procedures" : @YES,
      @"writes" : @NO,
      @"privateApi" : @YES,
      @"injected" : @YES,
      @"status" : @YES,
    },
    @"unsupportedReason" : [NSNull null],
  };
}

NSDictionary *HopperInjector::CurrentDocument(NSString **error) const {
  if (!const_cast<HopperInjector *>(this)->EnsureInjected(error)) return nil;
  return @{
    @"type" : @"current_document",
    @"documentId" : ToNSString(options_.document_id),
    @"name" : ToNSString(options_.document_name),
  };
}

NSDictionary *HopperInjector::Procedures(NSUInteger max_results, NSString **error) const {
  if (!const_cast<HopperInjector *>(this)->EnsureInjected(error)) return nil;

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
