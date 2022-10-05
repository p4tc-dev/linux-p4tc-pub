# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for KPARSER module
#
GCOV_PROFILE := y

##KBUILD_CFLAGS   := -Wall -Wundef -Wno-trigraphs \
#                   -fno-strict-aliasing -fno-common -fshort-wchar -fno-PIE \
#                   -Werror=implicit-function-declaration -Werror=implicit-int \
#                   -Wno-format-security \
#                   -fanalyzer           \
#                   -std=gnu89
ccflags-y := -DDEBUG -DKERNEL_MOD -Wall

obj-$(CONFIG_KPARSER) += kparser.o

kparser-objs := kparser_main.o kparser_cmds.o kparser_cmds_ops.o kparser_cmds_dump_ops.o kparser_datapath.o
