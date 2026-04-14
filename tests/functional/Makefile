#
# Copyright(c) 2019-2022 Intel Corporation
# Copyright(c) 2025 Huawei Technologies
# Copyright(c) 2026 Unvertical
# SPDX-License-Identifier: BSD-3-Clause
#

PWD=$(shell pwd)
OCFDIR=$(PWD)/../../
ADAPTERDIR=$(PWD)/pyocf
SRCDIR=$(ADAPTERDIR)/ocf/src
INCDIR=$(ADAPTERDIR)/ocf/include
WRAPDIR=$(ADAPTERDIR)/c/wrappers
HELPDIR=$(ADAPTERDIR)/c/helpers
ENVDIR=$(ADAPTERDIR)/c/env

CFLAGS=-g -Wall -I$(INCDIR) -I$(SRCDIR)/ocf/env $(OPT_CFLAGS)
LDFLAGS=-pthread #-lz

SRC=$(shell find $(SRCDIR) $(WRAPDIR) $(HELPDIR) -name \*.c)
OBJS=$(patsubst %.c, %.o, $(SRC))
OCFLIB=$(ADAPTERDIR)/libocf.so

all: | sync env_override config_random
	$(MAKE) $(OCFLIB)

env_override: sync
	@rm -f $(SRCDIR)/ocf/env/ocf_env.h
	@cp $(ENVDIR)/ocf_env.h $(SRCDIR)/ocf/env/ocf_env.h
	@cp $(ENVDIR)/ocf_env_time.h $(SRCDIR)/ocf/env/ocf_env_time.h

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

.PHONY: all clean sync env_override config_random distclean
