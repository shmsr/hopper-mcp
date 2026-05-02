ROOT := ../..
OUT := $(ROOT)/target/release/hopper-agent
SRC := $(wildcard src/*.mm)

.PHONY: all clean

all: $(OUT)

$(OUT): $(SRC)
	mkdir -p "$(dir $(OUT))"
	clang++ -std=c++17 -Wall -Wextra -Werror -Wno-deprecated-declarations -ObjC++ -framework Foundation $(SRC) -o "$(OUT)"

clean:
	rm -f "$(OUT)"
