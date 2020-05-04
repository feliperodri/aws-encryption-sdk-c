# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

###########
# if Makefile.local exists, use it. This provides a way to override the defaults
sinclude ../Makefile.local
#otherwise, use the default values
include ../Makefile.local_default
include ../Makefile.aws_byte_buf
include ../Makefile.string

MAX_BUFFER_SIZE = 10
#UNWINDSET += flush_openssl_errors.0:1
UNWINDSET += aws_cryptosdk_encrypt_body.0:$(shell echo $$((1 + $(MAX_BUFFER_SIZE))))
UNWINDSET += strlen.0:37#$(shell echo $$((1 + $(MAX_STRING_LEN))))

CBMCFLAGS +=

ENTRY = aws_cryptosdk_decrypt_body_harness

#DEPENDENCIES += $(COMMON_HELPERDIR)/stubs/memcpy_override_havoc.goto
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/make_common_data_structures.goto
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/proof_allocators.goto
DEPENDENCIES += $(SRCDIR)/c-common-helper-src/utils.goto
DEPENDENCIES += $(SRCDIR)/c-common-src/byte_buf.goto
DEPENDENCIES += $(SRCDIR)/c-common-src/common.goto
DEPENDENCIES += $(SRCDIR)/c-common-src/error.goto
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/cipher.goto
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/cipher_openssl.goto
DEPENDENCIES += $(SRCDIR)/c-enc-sdk-src/hkdf.goto
DEPENDENCIES += $(SRCDIR)/helper-src/cbmc_invariants.goto
DEPENDENCIES += $(SRCDIR)/helper-src/make_common_data_structures.goto
DEPENDENCIES += $(SRCDIR)/helper-src/openssl/bn_override.goto
DEPENDENCIES += $(SRCDIR)/helper-src/openssl/ec_override.goto
DEPENDENCIES += $(SRCDIR)/helper-src/openssl/err_override.goto
DEPENDENCIES += $(SRCDIR)/helper-src/openssl/evp_override.goto

###########

include ../Makefile.common
