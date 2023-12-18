# main config
LIBPREFIX?=./../../
ARCH?=i686
PREFIX?=./build

CC:=clang
INCS:=-I$(LIBPREFIX)src
LIBDIRS:=
LIBS:=-luser32 -lgdi32 -lpsapi
CFLAGS:=-ffunction-sections\
	-fdata-sections -std=c99
LDFLAGS:=

# arch config
ifeq ($(ARCH), x86_64) 
ARCH_POSTFIX:=64
LIBDIRS+=-L$(LIBPREFIX)lib64
CFLAGS+=-D_WIN64
ifdef DEBUG
BUILD_POSTFIX:=64d
else
BUILD_POSTFIX:=64
endif 
else # x86
ARCH_POSTFIX:=32
LIBDIRS+=-L$(LIBPREFIX)lib32
ifdef DEBUG
BUILD_POSTFIX:=32d
else
BUILD_POSTFIX:=32
endif 
endif

# compiler config
ifneq (,$(findstring clang, $(CC)))
CFLAGS+=-target $(ARCH)-pc-windows-msvc \
	-D_CRT_SECURE_NO_DEPRECATE 
LDFLAGS+= -Wl,/OPT:REF\
    -Wl,/DEF:src/libwinhook.def\
	-Wno-undefined-inline
else  # mingw 
CFLAGS+=-m$(ARCH_POSTFIX) \
	-fPIC\
	-fvisibility=hidden\
	-fgnu89-inline\
	-DWINPE_NOASM 
ifneq (,$(findstring gcc, $(CC)))
LDFLAGS+=-lwinpthread \
	-static-libgcc \
	-static-libstdc++ \
	-Wl,-Bstatic,--whole-archive \
	-Wl,--no-whole-archive\
	-Wl,--gc-sections\
	-Wl,--enable-stdcall-fixup\
	-Wl,--kill-at
endif
endif

# optimization config
ifdef DEBUG
CFLAGS+=-g -D_DEBUG
else
CFLAGS+=-Os
endif 
LIBDIRS+=-L$(PREFIX) 

# system config
ifeq ($(shell echo ${OS}), Windows_NT)
DLL_EXT=.dll
EXE_EXT=.exe
else
DLL_EXT?=.so
EXE_EXT?=
endif

# other config
ifneq (,$(findstring clang, $(CC)))
else
ifneq (,$(findstring gcc, $(CC)))
endif
endif

all: prepare\
	libwinhook\
	libwinhook_test\
	helloexe\
	hellodll

clean:
	rm -rf $(PREFIX)/*libwinhook*
	rm -rf $(PREFIX)/*hello*
	rm -rf $(PREFIX)/*test*

prepare:
	@if ! [ -d $(PREFIX) ]; then mkdir -p $(PREFIX); fi

libwinhook: src\libwinhook.c
	@echo \#\#building $@ ...
	$(CC) -shared $< \
		-o $(PREFIX)/$@$(BUILD_POSTFIX)$(DLL_EXT) \
		$(CFLAGS) $(LDFLAGS) $(INCS) $(LIBS) $(LIBDIRS)

libwinhook_test: src\libwinhook_test.c
	$(CC) $< \
		-o $(PREFIX)/$@$(BUILD_POSTFIX).exe \
		$(CFLAGS) $(LDFLAGS) $(INCS) $(LIBS) $(LIBDIRS)

helloexe: src\helloexe.c
	@echo \#\#building $@ ...
	$(CC) $< -o $(PREFIX)/hello$(BUILD_POSTFIX).exe $(CFLAGS) -lgdi32 -luser32

hellodll: src\hellodll.c
	@echo \#\#building $@ ...
	$(CC) -shared $< -o $(PREFIX)/hello$(BUILD_POSTFIX).dll $(CFLAGS) -luser32

.PHONY: all clean prepare libwinhook helloexe hellodll