#
# Copyright(c) 2019-2022 Intel Corporation
# Copyright(c) 2023-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause
#

PWD=$(shell pwd)
OCFDIR=$(PWD)/../../
ADAPTERDIR=$(PWD)/pyocf
SRCDIR=$(ADAPTERDIR)/ocf/src
INCDIR=$(ADAPTERDIR)/ocf/include
WRAPDIR=$(ADAPTERDIR)/c/wrappers
HELPDIR=$(ADAPTERDIR)/c/helpers

DEBUG_STATS ?= 0
CC=gcc
CFLAGS=-g -Wall -MMD -I$(INCDIR) -I$(SRCDIR)/ocf/env -DOCF_USER_OVERRIDE_CLASSES
LDFLAGS=-pthread -lz

ifeq ($(DEBUG_STATS),1)
CFLAGS += -DOCF_DEBUG_STATS
endif

SRC=$(shell find $(SRCDIR) $(WRAPDIR) $(HELPDIR) -name \*.c)
OBJS=$(patsubst %.c, %.o, $(SRC))
OCFLIB=$(ADAPTERDIR)/libocf.so

all: | sync config_random
	$(MAKE) $(OCFLIB)

$(OCFLIB): $(OBJS)
	@echo "Building $@"
	@$(CC) -coverage -shared -o $@ $(CFLAGS) $^ -fPIC $(LDFLAGS)

%.o: %.c Makefile
	@echo "Compiling $@"
	@$(CC) -coverage -c $(CFLAGS) -o $@ -fPIC $< $(LDFLAGS)

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
	@echo "  DISTCLEAN "

-include $(SRC:.c=.d)

.PHONY: all clean sync config_random distclean
