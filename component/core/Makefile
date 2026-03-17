CC?=clang

FIND=$(shell which gfind find | head -1)

UNAME_S:=$(shell uname -s)
UNAME_M:=$(shell uname -m)

SRC:=
INCLUDES:=
CFLAGS:=
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

SRC+=$(shell $(FIND) src/ -type f -name '*.c')
INCLUDES+=-Isrc

include lib/.dep/config.mk

OBJ:=$(SRC:.c=.o)
OBJ:=$(OBJ:.cc=.o)
OBJ+=$(LICENSE_OBJ)

CFLAGS+=${INCLUDES}

.PHONY: default
default: upbx

license.o: LICENSE.md
	$(OBJCOPY) --input binary --output $(ARCH_TARGET) --binary-architecture $(ARCH_BIN) $< $@

license.c: LICENSE.md
	(echo "static const unsigned char _license_md_data[] = {"; xxd -i < LICENSE.md; echo "};") > license.c
	(echo "static const unsigned char * const _license_md_end = _license_md_data + sizeof(_license_md_data);" >> license.c)
	(echo "const unsigned char * const _binary_LICENSE_md_start = _license_md_data;" >> license.c)
	(echo "const unsigned char * const _binary_LICENSE_md_end = _license_md_end;" >> license.c)

.c.o:
	${CC} $< ${CFLAGS} -c -o $@

upbx: $(OBJ)
	${CC} ${OBJ} ${CFLAGS} ${LDFLAGS} -o $@
	strip -u -r $@ 2>/dev/null || true

.PHONY: install
install: upbx
	install upbx ${DESTDIR}/bin

.PHONY: clean
clean:
	rm -f $(OBJ)

.PHONY: format
format:
	$(FIND) src/ -type f \( -name '*.c' -o -name '*.h' \) -exec clang-format -i {} +
