# BTCMobile - Build System Configuration
# Copyright (c) 2026 Zoey Alejandroo JF
#
# Description: Automated build targets for BTC key engine, CREATE-BIX database generator, and Address-Hash160 utility.
# Flags & Optimizations:
# - x86_64 / i686: -Ofast -mssse3 -DSSE2NEON_H for SSSE3 accelerated SHA256 / RIPEMD160.
# - ARMv8-A: -Ofast -march=armv8-a+crypto for mobile Snapdragon hardware vectorization.

CXX := g++
LDFLAGS := -pthread -lpthread

ARCH ?= $(shell uname -m)

ifeq ($(ARCH),x86_64)
    CXXFLAGS := -std=c++17 -Ofast -mssse3 -pthread -D_GNU_SOURCE -w -I. -DSSE2NEON_H -include tmmintrin.h
    CLANGFLAGS := -O3 -std=c++17 -pthread -I.
else ifeq ($(ARCH),i686)
    CXXFLAGS := -std=c++17 -Ofast -mssse3 -pthread -D_GNU_SOURCE -w -I. -DSSE2NEON_H -include tmmintrin.h
    CLANGFLAGS := -O3 -std=c++17 -pthread -I.
else ifeq ($(ARCH),i386)
    CXXFLAGS := -std=c++17 -Ofast -mssse3 -pthread -D_GNU_SOURCE -w -I. -DSSE2NEON_H -include tmmintrin.h
    CLANGFLAGS := -O3 -std=c++17 -pthread -I.
else
    CXXFLAGS := -std=c++17 -Ofast -march=armv8-a+crypto -pthread -D_GNU_SOURCE -w -I.
    CLANGFLAGS := -O3 -march=armv8-a+crypto -std=c++17 -pthread -I.
endif

# ---- Compilador y flags exclusivos para Address-Hash160 ----
CLANGXX     := g++
ADDR_SRCS   := Address-Hash160.cpp Secp256k1/sha256.cpp Secp256k1/ripemd160.cpp
ADDR_BIN    := Address-Hash160
ADDR_LIBS   := -lz

OBJDIR := Secp256k1/.o

SRCS_C := $(wildcard Secp256k1/*.c)
SRCS_CPP := $(wildcard Secp256k1/*.cpp)

OBJS_LIB := $(patsubst Secp256k1/%.c,$(OBJDIR)/%.o,$(SRCS_C)) \
            $(patsubst Secp256k1/%.cpp,$(OBJDIR)/%.o,$(SRCS_CPP))

OBJS_ROOT := $(OBJDIR)/BTC.o $(OBJDIR)/CREATE-BIX.o

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

# ---- Target independiente compilado con clang++ ----
$(ADDR_BIN): $(ADDR_SRCS)
	$(CLANGXX) $(CLANGFLAGS) $^ -o $@ $(ADDR_LIBS)

clean:
	rm -rf $(OBJDIR) BTC CREATE-BIX $(ADDR_BIN)
