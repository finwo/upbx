lc = $(subst A,a,$(subst B,b,$(subst C,c,$(subst D,d,$(subst E,e,$(subst F,f,$(subst G,g,$(subst H,h,$(subst I,i,$(subst J,j,$(subst K,k,$(subst L,l,$(subst M,m,$(subst N,n,$(subst O,o,$(subst P,p,$(subst Q,q,$(subst R,r,$(subst S,s,$(subst T,t,$(subst U,u,$(subst V,v,$(subst W,w,$(subst X,x,$(subst Y,y,$(subst Z,z,$1))))))))))))))))))))))))))

LIBS:=
SRC:=

# UNAME_MACHINE=$(call lc,$(shell uname -m))
# UNAME_SYSTEM=$(call lc,$(shell uname -s))

BIN?=upbx
VERSION?=0.1.0

CC:=gcc
CPP:=g++

FIND=$(shell which gfind find | head -1)
SRC+=$(shell $(FIND) src/ -type f -name '*.c')
# Exclude standalone test programs from main binary
SRC:=$(filter-out $(wildcard src/test/test_*.c),$(SRC))

INCLUDES:=

override CFLAGS?=-Wall -O2
override CFLAGS+=-I src -D INI_HANDLER_LINENO=1 -D'UPBX_VERSION_STR="$(VERSION)"'
override LDFLAGS?=

override LDFLAGS+=-lresolv

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
default: $(BIN) $(BIN).1

# Stddoc: extract /// documentation from source to markdown for manpage
STDDOC ?= stddoc
doc/cli_doc.md: $(SRC)
	@mkdir -p doc
	cat $(SRC) | $(STDDOC) > doc/cli_doc.md

# Manpage: template + stddoc fragment (markdown -> man) + envsubst for VERSION
doc/cli_doc.man: doc/cli_doc.md
	pandoc doc/cli_doc.md -f markdown -t man -o doc/cli_doc.man

doc/license.man: LICENSE.md
	@mkdir -p doc
	pandoc LICENSE.md -f markdown -t man --standalone=false -o doc/license.man

$(BIN).1: doc/upbx.1.in doc/cli_doc.man doc/license.man
	VERSION=$(VERSION) envsubst '$$VERSION' < doc/upbx.1.in | sed '/__COMMANDS_MAN__/r doc/cli_doc.man' | sed '/__COMMANDS_MAN__/d' | sed '/__LICENSE_MAN__/r doc/license.man' | sed '/__LICENSE_MAN__/d' > $(BIN).1

# .cc.o:
# 	$(CPP) $< $(CPPFLAGS) -c -o $@

.c.o:
	${CC} $< ${CFLAGS} -c -o $@

$(BIN): $(OBJ)
	${CC} ${OBJ} ${CFLAGS} ${LDFLAGS} -o $@

# ---- Test targets (finwo/assert) ----
TEST_BINS:=test_md5 test_sdp_parse test_sip_parse test_config test_digest_auth

test_md5: src/test/test_md5.o src/common/md5.o
	$(CC) $^ $(CFLAGS) -o $@

test_sdp_parse: src/test/test_sdp_parse.o src/AppModule/util/sdp_parse.o
	$(CC) $^ $(CFLAGS) -o $@

test_sip_parse: src/test/test_sip_parse.o src/AppModule/sip_parse.o lib/rxi/log/src/log.o
	$(CC) $^ $(CFLAGS) -o $@

test_config: src/test/test_config.o src/config.o lib/benhoyt/inih/ini.o lib/rxi/log/src/log.o src/PluginModule/plugin.o src/common/socket_util.o
	$(CC) $^ $(CFLAGS) -o $@

test_digest_auth: src/test/test_digest_auth.o src/common/digest_auth.o src/common/md5.o
	$(CC) $^ $(CFLAGS) -o $@

.PHONY: test
test: $(TEST_BINS)
	@for t in $(TEST_BINS); do echo "--- $$t ---"; ./$$t || exit 1; done
	@echo "All tests passed."

.PHONY: clean
clean:
	rm -rf $(BIN) $(BIN).1 $(TEST_BINS)
	rm -rf $(OBJ)
	rm -rf $(patsubst %,src/test/%.o,$(TEST_BINS:test_%=test_%))
	rm -rf src/test/*.o
	rm -rf doc/cli_doc.md doc/cli_doc.man doc/license.man
