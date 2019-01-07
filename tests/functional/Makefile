#
# Copyright(c) 2019 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause-Clear
#

PWD=$(shell pwd)
OCFDIR=$(PWD)/../../
ADAPTERDIR=$(PWD)/test_adapter
SRCDIR=$(ADAPTERDIR)/src
INCDIR=$(ADAPTERDIR)/include

CC=gcc
CFLAGS=-g -Wall -I$(INCDIR) -I$(SRCDIR)
LDFLAGS=-pthread

SRC=$(shell find $(SRCDIR) -name \*.c)
OBJS=$(patsubst %.c, %.o, $(SRC))
OCFLIB=libocf.so

all: sync $(OBJS) $(OCFLIB)

$(OCFLIB): $(OBJS)
	$(CC) -shared -o $@ $(CFLAGS) $^ -fPIC $(LDFLAGS)

%.o: %.c
	$(CC) -c $(CFLAGS) -o $@ -fPIC $^ $(LDFLAGS)

sync:
	$(MAKE) -C $(OCFDIR) inc O=$(ADAPTERDIR)
	$(MAKE) -C $(OCFDIR) src O=$(ADAPTERDIR)

clean:
	rm -rf $(OCFLIB) $(OBJS)

distclean:
	rm -rf $(OCFLIB) $(OBJS)
	rm -rf $(SRCDIR)/ocf
	rm -rf $(INCDIR)/ocf

.PHONY: all clean
