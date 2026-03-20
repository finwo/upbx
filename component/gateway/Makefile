CC?=clang
VERSION?=0.1.0

FIND=$(shell which gfind find | head -1)

UNAME_S:=$(shell uname -s)
UNAME_M:=$(shell uname -m)

SRC:=
INCLUDES:=
CFLAGS:=-DGW_VERSION=\"$(VERSION)\"
LDFLAGS:=
DESTDIR?=/usr/local

ifeq ($(UNAME_S),Darwin)
  OBJCOPY:=$(shell echo "echo 'Not using objcopy'")
  LD:=$(shell which ld)
  LICENSE_OBJ:=license.c
  LDFLAGS+=-lobjc
else
  OBJCOPY?=objcopy
  OBJCOPY:=$(shell which objcopy)
  LICENSE_OBJ:=license.o
endif

ARCH_TARGET?=$(shell echo $(UNAME_M) | sed -e 's/x86_64/elf64-x86-64/' -e 's/arm64/elf64-littleaarch64/' -e 's/aarch64/elf64-littleaarch64/')
ARCH_BIN?=$(shell echo $(UNAME_M) | sed -e 's/x86_64/i386/' -e 's/arm64/aarch64/' -e 's/aarch64/aarch64/')

ifeq ($(UNAME_S),Darwin)
  CFLAGS+=-D_DARWIN_C_SOURCE
endif

SRC+=$(shell $(FIND) src/ -type f -name '*.c')
INCLUDES+=-Isrc

include lib/.dep/config.mk

OBJ:=$(SRC:.c=.o)
OBJ:=$(OBJ:.cc=.o)
OBJ+=$(LICENSE_OBJ)

CFLAGS+=${INCLUDES} -O0 -g

.PHONY: default
default: upbx-gw

license.o: LICENSE.md
	$(OBJCOPY) --input binary --output $(ARCH_TARGET) --binary-architecture $(ARCH_BIN) $< $@

license.c: LICENSE.md
	(echo "static const unsigned char _license_md_data[] = {"; xxd -i < LICENSE.md; echo "};") > license.c
	(echo "static const unsigned char * const _license_md_end = _license_md_data + sizeof(_license_md_data);" >> license.c)
	(echo "const unsigned char * const _binary_LICENSE_md_start = _license_md_data;" >> license.c)
	(echo "const unsigned char * const _binary_LICENSE_md_end = _license_md_end;" >> license.c)

.c.o:
	${CC} $< ${CFLAGS} -c -o $@

upbx-gw: $(OBJ)
	${CC} ${OBJ} ${CFLAGS} ${LDFLAGS} -o $@

.PHONY: install
install: upbx-gw
	install upbx-gw ${DESTDIR}/bin

.PHONY: clean
clean:
	rm -f $(OBJ)
	rm -f $(TEST_OBJ) $(TEST_BIN)

TEST_OBJ=test/same_node.o test/testutil.o
TEST_BIN=test_same_node
TEST_LIBS=lib/orlp/ed25519/src/fe.o lib/orlp/ed25519/src/ge.o \
	lib/orlp/ed25519/src/key_exchange.o lib/orlp/ed25519/src/keypair.o \
	lib/orlp/ed25519/src/sc.o lib/orlp/ed25519/src/seed.o \
	lib/orlp/ed25519/src/sha512.o lib/orlp/ed25519/src/sign.o \
	lib/orlp/ed25519/src/verify.o lib/finwo/pbkdf2/src/pbkdf2.o \
	lib/rxi/log/src/log.o

$(TEST_BIN): $(TEST_OBJ) $(TEST_LIBS) upbx-gw
	${CC} ${TEST_OBJ} ${TEST_LIBS} ${CFLAGS} ${LDFLAGS} -o $@
	strip -u -r $@ 2>/dev/null || true

test/same_node.o: test/same_node.c
	${CC} $< ${CFLAGS} -Isrc -Ilib/.dep/include -c -o $@

test/testutil.o: test/testutil.c
	${CC} $< ${CFLAGS} -Isrc -Ilib/.dep/include -c -o $@

.PHONY: test-same-node
test-same-node: $(TEST_BIN)
	./$(TEST_BIN)

.PHONY: test
test: test-same-node

.PHONY: clean-test
clean-test:
	rm -f $(TEST_OBJ) $(TEST_BIN)

.PHONY: format
format:
	$(FIND) src/ -type f \( -name '*.c' -o -name '*.h' \) -exec clang-format -i {} +

.PHONY: dep
dep:
	cd . && dep i
