# BTCMobile - High-Performance Build System Configuration
# Copyright (c) 2026 Zoey Alejandroo JF

CXX := g++
CLANGXX := g++
LDFLAGS := -pthread -lpthread

ARCH ?= $(shell uname -m)

ifeq ($(ARCH),x86_64)
    CXXFLAGS := -std=c++17 -O3 -mssse3 -pthread -D_GNU_SOURCE -w -I. -DSSE2NEON_H -include tmmintrin.h
    CLANGFLAGS := -std=c++17 -O3 -pthread -I.
else ifeq ($(ARCH),i686)
    CXXFLAGS := -std=c++17 -O3 -mssse3 -pthread -D_GNU_SOURCE -w -I. -DSSE2NEON_H -include tmmintrin.h
    CLANGFLAGS := -std=c++17 -O3 -pthread -I.
else ifeq ($(ARCH),i386)
    CXXFLAGS := -std=c++17 -O3 -mssse3 -pthread -D_GNU_SOURCE -w -I. -DSSE2NEON_H -include tmmintrin.h
    CLANGFLAGS := -std=c++17 -O3 -pthread -I.
else ifeq ($(ARCH),aarch64)
    CXXFLAGS := -std=c++17 -O3 -march=armv8-a+crypto -pthread -D_GNU_SOURCE -w -I.
    CLANGFLAGS := -std=c++17 -O3 -march=armv8-a+crypto -pthread -I.
else ifeq ($(ARCH),arm64)
    CXXFLAGS := -std=c++17 -O3 -march=armv8-a+crypto -pthread -D_GNU_SOURCE -w -I.
    CLANGFLAGS := -std=c++17 -O3 -march=armv8-a+crypto -pthread -I.
else
    CXXFLAGS := -std=c++17 -O3 -pthread -D_GNU_SOURCE -DNO_SSE -w -I.
    CLANGFLAGS := -std=c++17 -O3 -pthread -DNO_SSE -I.
endif

ADDR_SRCS := Address-Hash160.cpp Secp256k1/sha256.cpp Secp256k1/ripemd160.cpp
ADDR_BIN  := Address-Hash160
ADDR_LIBS := -lz

OBJDIR := Secp256k1/.o

SRCS_C := $(wildcard Secp256k1/*.c)
SRCS_CPP := $(wildcard Secp256k1/*.cpp)

OBJS_LIB := $(patsubst Secp256k1/%.c,$(OBJDIR)/%.o,$(SRCS_C)) \
            $(patsubst Secp256k1/%.cpp,$(OBJDIR)/%.o,$(SRCS_CPP))

all: BTC CREATE-BIX $(ADDR_BIN)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: Secp256k1/%.c | $(OBJDIR)
	$(CXX) $(CXXFLAGS) -x c++ -c $< -o $@

$(OBJDIR)/%.o: Secp256k1/%.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJDIR)/BTC.o: BTC.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJDIR)/CREATE-BIX.o: CREATE-BIX.cpp | $(OBJDIR)
	$(CXX) $(CXXFLAGS) -c $< -o $@

BTC: $(OBJS_LIB) $(OBJDIR)/BTC.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

CREATE-BIX: $(OBJS_LIB) $(OBJDIR)/CREATE-BIX.o
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

$(ADDR_BIN): $(ADDR_SRCS)
	$(CLANGXX) $(CLANGFLAGS) $^ -o $@ $(ADDR_LIBS)

clean:
	rm -rf $(OBJDIR) BTC CREATE-BIX $(ADDR_BIN) BTC.hex BTC.bin BTC.idx BTC.xor FOUND.txt

.PHONY: all clean
