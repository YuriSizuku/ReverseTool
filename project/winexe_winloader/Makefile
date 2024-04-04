# build example
# make winloader CC=i686-w64-mingw32-gcc WINDRES=i686-w64-mingw32-windres BUILD_TYPE=32d 
# make winloader CC=x86_64-w64-mingw32-gcc WINDRES=x86_64-w64-mingw32-windres BUILD_TYPE=64d

# general config
CC:=gcc # clang (llvm-mingw), gcc (mingw-w64), tcc (x86 stdcall name has problem)
WINDRES:=windres
BUILD_TYPE:=32# 32, 32d, 64, 64d
BUILD_DIR:=build
INCS:=-I../../src
LIBS:=-luser32 -lgdi32 -lpsapi
CFLAGS:=-fPIC -std=c99 \
	-fvisibility=hidden \
	-ffunction-sections -fdata-sections
LDFLAGS:=-Wl,--enable-stdcall-fixup \
		 -Wl,--kill-at \
		 -Wl,--gc-sections

# build config
ifneq (,$(findstring 64, $(BUILD_TYPE)))
CFLAGS+=-m64
ARCH_WINDRES=pe-x86-64
else
CFLAGS+=-m32
ARCH_WINDRES=pe-i386
endif
ifneq (,$(findstring d, $(BUILD_TYPE)))
CFLAGS+=-g -D_DEBUG
else
CFLAGS+=-Os
endif
ifneq (,$(findstring tcc, $(CC)))
LDFLAGS= # tcc can not remove at at stdcall in i686
else
endif

all: prepare winloader

clean:
	@rm -rf $(BUILD_DIR)/*winloader*

prepare:
	@if ! [ -d $(BUILD_DIR) ]; then mkdir -p $(BUILD_DIR); fi

$(BUILD_DIR)/winloader$(BUILD_TYPE).res: src/winloader.rc
	$(WINDRES) $< -F $(ARCH_WINDRES) -O coff -o $@

winloader: src/winloader.c $(BUILD_DIR)/winloader$(BUILD_TYPE).res
	@echo "## $@"
	$(CC) $^ -o $(BUILD_DIR)/$@$(BUILD_TYPE).exe \
		$(INCS) $(LIBS) \
		$(CFLAGS) $(LDFLAGS) 

.PHONY: all clean prepare winloader