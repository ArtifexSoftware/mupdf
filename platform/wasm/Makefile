-include user.make

build ?= release

EMSDK_DIR ?= /opt/emsdk
BUILD_DIR ?= ../../build/wasm/$(build)

ifeq ($(build),debug)
  BUILD_FLAGS := -Wall -O0
else
  BUILD_FLAGS := -Wall -Os
endif

all: libmupdf.js libmupdf.wasm

MUPDF_CORE := $(BUILD_DIR)/libmupdf.a $(BUILD_DIR)/libmupdf-third.a
$(MUPDF_CORE): .FORCE
	$(MAKE) -j4 -C ../.. generate
	BASH_SOURCE=$(EMSDK_DIR)/emsdk_env.sh; \
	. $(EMSDK_DIR)/emsdk_env.sh; \
	$(MAKE) -j4 -C ../.. \
		OS=wasm build=$(build) \
		XCFLAGS='-DTOFU -DTOFU_CJK -DFZ_ENABLE_SVG=0 -DFZ_ENABLE_HTML=0 -DFZ_ENABLE_EPUB=0 -DFZ_ENABLE_JS=0' \
		libs

libmupdf.js libmupdf.wasm: $(MUPDF_CORE) lib/wrap.c
	BASH_SOURCE=$(EMSDK_DIR)/emsdk_env.sh \
	. $(EMSDK_DIR)/emsdk_env.sh; \
	emcc -o $@ $(BUILD_FLAGS) \
		--no-entry \
		-s VERBOSE=0 \
		-s ABORTING_MALLOC=0 \
		-s ALLOW_MEMORY_GROWTH=1 \
		-s WASM=1 \
		-s MODULARIZE=1 \
		-s EXPORT_NAME='"libmupdf"' \
		-s EXPORTED_RUNTIME_METHODS='["ccall","cwrap", "UTF8ToString","lengthBytesUTF8","stringToUTF8"]' \
		-s EXPORTED_FUNCTIONS='["_malloc","_free"]' \
		-I ../../include \
		lib/wrap.c \
		$(BUILD_DIR)/libmupdf.a \
		$(BUILD_DIR)/libmupdf-third.a

clean:
	rm -f libmupdf.js libmupdf.wasm
	$(MAKE) -C ../../ OS=wasm build=$(build) clean

.PHONY: .FORCE clean
