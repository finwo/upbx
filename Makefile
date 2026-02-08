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

INCLUDES:=

override CFLAGS?=-Wall -O2
override CFLAGS+=-I src
override LDFLAGS?=

override CPPFLAGS?=

# override CFLAGS+=-D WEBVIEW_STATIC
# override CFLAGS+=-D WINTERM

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

# tool/bin2c/bin2c-${UNAME_SYSTEM}-${UNAME_MACHINE}:
# 	bash -c "cd tool/bin2c && make"

# tool/client-jerry/dist/index.js:
# 	bash -c "cd $$(dirname $$(dirname $@)) && npm i && npm run build"

# tool/overlay-chat/dist/index.bundled.html: tool/client-jerry/dist/index.js

# htmltools:  $(htmltools)
# $(htmltools):
# 	bash -c "cd $$(dirname $$(dirname $@)) && npm i && npm run build"

# headertools: $(headertools)
# # $(headertools): tool/bin2c/bin2c-${UNAME_SYSTEM}-${UNAME_MACHINE} $(htmltools)
# $(headertools): $(htmltools)
# 	# tool/bin2c/bin2c-${UNAME_SYSTEM}-${UNAME_MACHINE} < $(@:.h=.html) > $@

# .cc.o:
# 	$(CPP) $< $(CPPFLAGS) -c -o $@

.c.o:
	${CC} $< ${CFLAGS} -c -o $@

$(BIN): $(OBJ)
	${CC} ${OBJ} ${CFLAGS} ${LDFLAGS} -o $@

.PHONY: clean
clean:
	rm -rf $(BIN)
	rm -rf $(OBJ)
