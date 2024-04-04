#   Copyright (C) 2024 John Törnblom
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.

PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/make/x86_64-ps5-payload.inc
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

CFLAGS := -Wall -Werror
LDADD  := -lSceLibcInternal -lkernel_sys

SUBDIRS := bundles/core bundles/http2_get bundles/launch

TOPTARGETS := all clean

$(TOPTARGETS): $(SUBDIRS)

$(SUBDIRS):
	make -C $@ $(MAKECMDGOALS)

.PHONY: $(TOPTARGETS) $(SUBDIRS)


all: shsrv.elf sh.elf

shsrv.o: sh.elf.inc

builtin.o: bundles/core/core.elf.inc bundles/http2_get/http2_get.elf.inc \
           bundles/launch/launch.elf.inc

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

shsrv.elf: shsrv.o elfldr.o pt.o
	$(LD) -o $@ $^ $(LDADD)

sh.elf: sh.o builtin.o elfldr.o pt.o
	$(LD) -o $@ $^ $(LDADD)

sh.elf.inc: sh.elf
	xxd -i $^ > $@

clean:
	rm -f *.o *.elf

test: shsrv.elf
	nc -q0 $(PS5_HOST) $(PS5_PORT) < $^

