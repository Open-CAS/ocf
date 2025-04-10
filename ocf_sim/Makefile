#
# Copyright(c) 2021-2025 Huawei Technologies Co., Ltd.
# SPDX-License-Identifier: BSD-3-Clause
#

OCFDIR=..
SRCDIR=src
INCDIR=include
CASADMDIR=../../casadm
CASMODDIR=../../modules/include

SRC=$(shell find ${SRCDIR} -name \*.c)
SRC+=$(shell find ${CASADMDIR} -name statistics\*.c)
SRC+=${CASADMDIR}/cas_lib.c \
      ${CASADMDIR}/csvparse.c \
      ${CASADMDIR}/table.c \
      ${CASADMDIR}/intvector.c \
      ${CASADMDIR}/extended_err_msg.c
SRC+=$(shell find ${CASADMDIR}/safeclib -name \*.c)

OBJS = $(patsubst %.c, %.o, $(SRC))
PROGRAM=ocf_sim

CC = gcc
CFLAGS = -g -Wall -MMD -Werror -Ofast -I${INCDIR} -I${SRCDIR}/ocf/env/ -I${CASMODDIR} -I${CASADMDIR} -DOCF_SIM -DOCF_BLKTRACE
LDFLAGS = -lm -lz -pthread
CFLAGS:=$(filter-out -Ofast,$(CFLAGS))

GIT_VERSION := $(shell git describe --abbrev=8 --always)
CFLAGS += -DVERSION=0x${GIT_VERSION}

all: sync
	$(MAKE) $(PROGRAM)

$(PROGRAM): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c Makefile
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

sync:
	@$(MAKE) -C ${OCFDIR} inc O=$(PWD)
	@$(MAKE) -C ${OCFDIR} src O=$(PWD)
	@$(MAKE) -C ${OCFDIR} env O=$(PWD) OCF_ENV=posix

clean:
	@rm -rf $(PROGRAM) $(OBJS) $(OBJS:.o=.d)

distclean: clean
	@rm -rf src/ocf
	@rm -rf include/ocf

-include $(SRC:.c=.d)

.PHONY: all clean
