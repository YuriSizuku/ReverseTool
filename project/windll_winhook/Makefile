# build example
# make libwinhook helloexe hellodll libwinhook_test CC=i686-w64-mingw32-gcc BUILD_TYPE=32d
# make libwinhook helloexe hellodll libwinhook_test CC=x86_64-w64-mingw32-gcc BUILD_TYPE=64d
# wine build/libwinhook_test32d.exe && wine build/libwinhook_test64d.exe

# general config
CC:=gcc # clang (llvm-mingw), gcc (mingw-w64), tcc (x86 stdcall name has problem)
BUILD_TYPE:=32# 32, 32d, 64, 64d
BUILD_DIR:=build
INCS:=-I../../src
LIBS:=-luser32 -lgdi32 -lpsapi
CFLAGS:=-fPIC -std=c99 \
	-fvisibility=hidden \
	-ffunction-sections -fdata-sections
LDFLAGS:=-Wl,--enable-stdcall-fixup \
		 -Wl,--kill-at \
		 -Wl,--gc-sections \
		 -D_WIN32_WINNT=0X0400 \
		 -Wl,--subsystem,console:4.0 # compatible for xp

# build config
ifneq (,$(findstring 64, $(BUILD_TYPE)))
CFLAGS+=-m64
else
CFLAGS+=-m32
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

all: prepare libwinhook

clean:
	@rm -rf $(BUILD_DIR)/*libwinhook*
	@rm -rf $(BUILD_DIR)/*hello*
	@rm -rf $(BUILD_DIR)/*test*

prepare:
	@if ! [ -d $(BUILD_DIR) ]; then mkdir -p $(BUILD_DIR); fi

libwinhook: src/libwinhook.c
	@echo "## $@"
	$(CC) -shared $^ -o $(BUILD_DIR)/$@$(BUILD_TYPE).dll \
		$(INCS) $(LIBS) \
		$(CFLAGS) $(LDFLAGS)

libwinhook_test: src/libwinhook_test.c
	@echo "## $@"
	$(CC) $< -o $(BUILD_DIR)/$@$(BUILD_TYPE).exe \
		-L$(BUILD_DIR) -lwinhook$(BUILD_TYPE) -DWINHOOK_NOINLINE \
		$(INCS) $(LIBS) \
		$(CFLAGS) $(LDFLAGS)

helloexe: src/helloexe.c
	@echo "## $@"
	@echo \#\#building $@ ...
	$(CC) $< -o $(BUILD_DIR)/hello$(BUILD_TYPE).exe \
		$(CFLAGS) -lgdi32 -luser32 \
		-Wl,-subsystem,windows -municode

hellodll: src/hellodll.c
	@echo "## $@"
	@echo \#\#building $@ ...
	$(CC) -shared $< -o $(BUILD_DIR)/hello$(BUILD_TYPE).dll \
		$(CFLAGS) -luser32

.PHONY: all clean prepare libwinhook helloexe hellodll