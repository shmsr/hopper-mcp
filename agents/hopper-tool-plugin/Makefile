ROOT := ../..
SDK_ROOT ?= $(ROOT)/.cache/hopper-sdk/6.2.8
MACOS_SDK ?= $(shell xcrun --sdk macosx --show-sdk-path)
OUT_DIR := $(ROOT)/target/release/HopperMCPAgent.hopperTool
OUT_BIN := $(OUT_DIR)/Contents/MacOS/HopperMCPAgent
SRC := src/HopperMCPAgent.m
PLIST := Info.plist

.PHONY: all clean sdk

all: $(OUT_BIN)

sdk:
	cd "$(ROOT)" && node scripts/fetch-hopper-sdk.mjs

$(OUT_BIN): $(SRC) $(PLIST)
	@if [ ! -d "$(SDK_ROOT)/include/Hopper" ]; then \
		echo "Hopper SDK not found at $(SDK_ROOT). Run: npm run fetch:hopper-sdk"; \
		exit 2; \
	fi
	rm -rf "$(OUT_DIR)"
	mkdir -p "$(OUT_DIR)/Contents/MacOS"
	cp "$(PLIST)" "$(OUT_DIR)/Contents/Info.plist"
	clang -fobjc-arc -std=gnu11 -Wall -Wextra -Werror -Wno-deprecated-declarations -fmodules \
		-isysroot "$(MACOS_SDK)" -mmacosx-version-min=11.0 \
		-I"$(SDK_ROOT)/include" \
		-bundle \
		-framework Foundation \
		"$(SRC)" -o "$(OUT_BIN)"

clean:
	rm -rf "$(OUT_DIR)"
