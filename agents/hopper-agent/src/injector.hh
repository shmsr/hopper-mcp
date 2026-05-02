#import <Foundation/Foundation.h>

struct Options;

class HopperInjector {
 public:
  explicit HopperInjector(const Options &options);
  bool EnsureInjected(NSString **error);
  NSDictionary *Status() const;
  NSDictionary *CurrentDocument(NSString **error) const;
  NSDictionary *Procedures(NSUInteger max_results, NSString **error) const;

 private:
  const Options &options_;
};
