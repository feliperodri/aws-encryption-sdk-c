# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not use
# this file except in compliance with the License. A copy of the License is
# located at
#
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.

# if Makefile.local exists, use it. This provides a way to override the defaults
sinclude ../Makefile.local
#otherwise, use the default values
include ../Makefile.local_default
include ../Makefile.string
include ../Makefile.aws_array_list

# Expect runtime for this proof is 10sec
#########
# Local vars
MAX_TABLE_SIZE ?= 2
DEFINES += -DMAX_TABLE_SIZE=$(MAX_TABLE_SIZE)

NUM_ELEMS = 2
DEFINES += -DNUM_ELEMS=$(NUM_ELEMS)

CBMCFLAGS +=

# aws_atomic_fetch_add_explicit receives a volatile input, which is always model
# as non-deterministic in CBMC; thus, we need a deterministic stub for it
#ABSTRACTIONS += $(LINKFARM)/helper-stubs/aws_atomic_fetch_add_explicit.c
#REMOVE_FUNCTION_BODY += --remove-function-body aws_atomic_fetch_add_explicit

#ABSTRACTIONS += $(LINKFARM)/helper-stubs/aws_atomic_load_int.c
#REMOVE_FUNCTION_BODY += --remove-function-body aws_atomic_load_int

#ABSTRACTIONS += $(LINKFARM)/helper-stubs/aws_atomic_priv_xlate_order.c
#REMOVE_FUNCTION_BODY += --remove-function-body aws_atomic_priv_xlate_order

DEPENDENCIES += $(SRCDIR)/c-common-helper-src/make_common_data_structures.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/proof_allocators.c
DEPENDENCIES += $(SRCDIR)/c-common-src/array_list.c
DEPENDENCIES += $(SRCDIR)/c-common-src/byte_buf.c
DEPENDENCIES += $(SRCDIR)/c-common-src/common.c
DEPENDENCIES += $(SRCDIR)/c-common-src/error.c
DEPENDENCIES += $(SRCDIR)/c-common-src/hash_table.c
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/cipher.c
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/edk.c
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/keyring_trace.c
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/materials.c
DEPENDENCIES += $(SRCDIR)/helper-src/make_common_data_structures.c
DEPENDENCIES += $(SRCDIR)/c-common-helper-uninline/atomics.c

ENTRY = aws_cryptosdk_keyring_on_encrypt_harness

addone = $(shell echo $$(( $(1) + 1)))

UNWINDSET += aws_cryptosdk_edk_list_clear.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += aws_cryptosdk_edk_list_elements_are_bounded.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += aws_cryptosdk_edk_list_elements_are_valid.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += aws_cryptosdk_edk_list_is_bounded.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += aws_cryptosdk_edk_list_is_valid.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += ensure_cryptosdk_edk_list_has_allocated_list_elements.0:$(call addone,$(NUM_ELEMS))
UNWINDSET += ensure_cryptosdk_edk_list_has_allocated_members.0:$(call addone,$(NUM_ELEMS))

include ../Makefile.common
