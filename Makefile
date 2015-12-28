TARGET = sparsebundlefs

PKG_CONFIG = pkg-config
CFLAGS = -Wall -O2 -g

GCC_4_2_OR_HIGHER := $(shell expr `$(CXX) -dumpversion | sed 's/\.//g'` \>= 420)
ifeq "$(GCC_4_2_OR_HIGHER)" "1"
    CFLAGS += -march=native
endif

DEFINES = -DFUSE_USE_VERSION=26

ifeq ($(shell uname), Darwin)
	# Pick up OSXFUSE, even with pkg-config from brew and MacPorts
	PKG_CONFIG := PKG_CONFIG_PATH=$(shell ls -1d /usr/local/Cellar/libxml2/*/lib/pkgconfig \
		| tr '\n' ':'):/usr/local/lib/pkgconfig $(PKG_CONFIG)
else ifeq ($(shell uname), Linux)
	LFLAGS += -Wl,-rpath=$(shell $(PKG_CONFIG) fuse --variable=libdir)
endif

FUSE_FLAGS := $(shell $(PKG_CONFIG) fuse --cflags --libs)
XML2_FLAGS += $(shell $(PKG_CONFIG) libxml-2.0 --cflags --libs)

$(TARGET): sparsebundlefs.cpp
	$(CXX) $< -o $@ $(CFLAGS) $(FUSE_FLAGS) $(XML2_FLAGS) $(LFLAGS) $(DEFINES)

all: $(TARGET)

clean:
	rm -f $(TARGET)
	rm -Rf $(TARGET).dSYM
