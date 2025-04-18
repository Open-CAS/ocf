#
# Copyright(c) 2019-2022 Intel Corporation
# Copyright(c) 2025 Huawei Technologies
# SPDX-License-Identifier: BSD-3-Clause
#

PWD=$(shell pwd)
OCFDIR=$(PWD)/../../
ADAPTERDIR=$(PWD)/pyocf
SRCDIR=$(ADAPTERDIR)/ocf/src
INCDIR=$(ADAPTERDIR)/ocf/include
WRAPDIR=$(ADAPTERDIR)/c/wrappers
HELPDIR=$(ADAPTERDIR)/c/helpers

CFLAGS=-g -Wall -I$(INCDIR) -I$(SRCDIR)/ocf/env $(OPT_CFLAGS)
LDFLAGS=-pthread #-lz

SRC=$(shell find $(SRCDIR) $(WRAPDIR) $(HELPDIR) -name \*.c)
OBJS=$(patsubst %.c, %.o, $(SRC))
OCFLIB=$(ADAPTERDIR)/libocf.so

all: | sync config_random
	$(MAKE) $(OCFLIB)

$(OCFLIB): $(OBJS)
	@echo "Building $@"
	@$(CC) -coverage -shared -o $@ $(CFLAGS) $^ -fPIC $(LDFLAGS)

%.o: %.c
	@echo "Compiling $@"
	@$(CC) -coverage -c $(CFLAGS) -o $@ -fPIC $^ $(LDFLAGS)

sync:
	@echo "Syncing OCF sources"
	@mkdir -p $(ADAPTERDIR)/ocf
	@$(MAKE) -C $(OCFDIR) inc O=$(ADAPTERDIR)/ocf
	@$(MAKE) -C $(OCFDIR) src O=$(ADAPTERDIR)/ocf
	@$(MAKE) -C $(OCFDIR) env O=$(ADAPTERDIR)/ocf OCF_ENV=posix

config_random:
	@python3 utils/configure_random.py

clean:
	@rm -rf $(OCFLIB) $(OBJS)
	@echo "  CLEAN "

distclean: clean
	@rm -rf $(OCFLIB) $(OBJS)
	@rm -rf $(SRCDIR)/ocf
	@rm -rf $(INCDIR)/ocf
	@find . -name *.gc* -delete
	@echo "  DISTCLEAN "

.PHONY: all clean sync config_random distclean
