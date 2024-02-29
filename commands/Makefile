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

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/make/x86_64-ps5-payload.inc
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

CFLAGS += -Wall
LDADD  += -lkernel_sys

SRCS = env_elf.c ls_elf.c ps_elf.c

all: $(SRCS)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ $<

%.elf: %.o
	$(LD) -o $@ $^ $(LDADD)

%_elf.c: %.elf
	xxd -i $^ > $@

clean:
	rm -f *.o *.elf *_elf.c


