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
	winloader

clean:
	rm -rf $(PREFIX)/*winloader*

prepare:
	@if ! [ -d $(PREFIX) ]; then mkdir -p $(PREFIX); fi

winloader: src\winloader.c
	@echo \#\#building $@ ...
	$(CC) $< \
		-o $(PREFIX)/$@$(BUILD_POSTFIX)$(EXE_EXT) \
		$(CFLAGS) $(LDFLAGS) $(INCS) $(LIBS) $(LIBDIRS)

.PHONY: all clean prepare winloader