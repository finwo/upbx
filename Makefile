lc = $(subst A,a,$(subst B,b,$(subst C,c,$(subst D,d,$(subst E,e,$(subst F,f,$(subst G,g,$(subst H,h,$(subst I,i,$(subst J,j,$(subst K,k,$(subst L,l,$(subst M,m,$(subst N,n,$(subst O,o,$(subst P,p,$(subst Q,q,$(subst R,r,$(subst S,s,$(subst T,t,$(subst U,u,$(subst V,v,$(subst W,w,$(subst X,x,$(subst Y,y,$(subst Z,z,$1))))))))))))))))))))))))))

LIBS:=
SRC:=

# UNAME_MACHINE=$(call lc,$(shell uname -m))
# UNAME_SYSTEM=$(call lc,$(shell uname -s))

BIN?=upbx

CC:=gcc
CPP:=g++

FIND=$(shell which gfind find | head -1)
SRC+=$(shell $(FIND) src/ -type f -name '*.c')
# Exclude standalone test programs from main binary
SRC:=$(filter-out src/AppModule/md5_test.c,$(SRC))

INCLUDES:=

override CFLAGS?=-Wall -O2
override CFLAGS+=-I src -D INI_HANDLER_LINENO=1
override LDFLAGS?=

override LDFLAGS+=-lresolv -pthread

override CPPFLAGS?=

ifeq ($(OS),Windows_NT)
    # CFLAGS += -D WIN32
    override CPPFLAGS+=-lstdc++
    override CPPFLAGS+=
    ifeq ($(PROCESSOR_ARCHITEW6432),AMD64)
        # CFLAGS += -D AMD64
    else
        ifeq ($(PROCESSOR_ARCHITECTURE),AMD64)
            # CFLAGS += -D AMD64
        endif
        ifeq ($(PROCESSOR_ARCHITECTURE),x86)
            # CFLAGS += -D IA32
        endif
    endif
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Linux)
        # CFLAGS += -D LINUX
        override CPPFLAGS+=-lstdc++
        # override CFLAGS+=$(shell pkg-config --cflags glib-2.0)
        # override LDFLAGS+=$(shell pkg-config --libs glib-2.0)
        override CFLAGS+=-D _GNU_SOURCE
    endif
    ifeq ($(UNAME_S),Darwin)
        # CFLAGS += -D OSX
        override CPPFLAGS+=-std=c++14
        override CFLAGS+=-D _BSD_SOURCE
    endif
    UNAME_P := $(shell uname -p)
    ifeq ($(UNAME_P),x86_64)
        # CFLAGS += -D AMD64
    endif
    ifneq ($(filter %86,$(UNAME_P)),)
        # CFLAGS += -D IA32
    endif
    ifneq ($(filter arm%,$(UNAME_P)),)
        # CFLAGS += -D ARM
    endif
    # TODO: flags for riscv
endif

include lib/.dep/config.mk

OBJ:=$(SRC:.c=.o)
OBJ:=$(OBJ:.cc=.o)

override CFLAGS+=$(INCLUDES)
override CPPFLAGS+=$(INCLUDES)
override CPPFLAGS+=$(CFLAGS)

.PHONY: default
default: $(BIN)

# .cc.o:
# 	$(CPP) $< $(CPPFLAGS) -c -o $@

.c.o:
	${CC} $< ${CFLAGS} -c -o $@

$(BIN): $(OBJ)
	${CC} ${OBJ} ${CFLAGS} ${LDFLAGS} -o $@

# MD5 test (single-file test program + md5.c)
md5_test: src/AppModule/md5_test.o src/AppModule/md5.o
	$(CC) $^ $(CFLAGS) -o $@

.PHONY: clean
clean:
	rm -rf $(BIN) md5_test
	rm -rf $(OBJ)
