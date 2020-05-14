/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include <aws/cryptosdk/materials.h>
#include <make_common_data_structures.h>

void aws_cryptosdk_keyring_on_encrypt_harness() {
    /* Non-deterministic inputs. */
    const struct aws_cryptosdk_keyring_vt vtable = { .vt_size    = sizeof(struct aws_cryptosdk_keyring_vt),
                                                     .name       = ensure_c_str_is_allocated(SIZE_MAX),
                                                     .destroy    = nondet_voidp(),
                                                     .on_encrypt = nondet_voidp(),
                                                     .on_decrypt = nondet_voidp() };
    struct aws_cryptosdk_keyring keyring;
    ensure_cryptosdk_keyring_has_allocated_members(&keyring, &vtable);

    /* Pre-conditions. */
    __CPROVER_assume(aws_cryptosdk_keyring_is_valid(&keyring));
    __CPROVER_assume(aws_atomic_var_is_valid(&keyring.refcount));
    
    struct aws_array_list edk_list;
    /* Precondition: We have a valid list */
    __CPROVER_assume(aws_cryptosdk_edk_list_is_bounded(&edk_list, NUM_ELEMS));
    ensure_cryptosdk_edk_list_has_allocated_list(&edk_list);
    __CPROVER_assume(aws_cryptosdk_edk_list_is_valid(&edk_list));

    /* Precondition: The list has valid list elements */
    __CPROVER_assume(aws_cryptosdk_edk_list_elements_are_bounded(&edk_list, SIZE_MAX));
    ensure_cryptosdk_edk_list_has_allocated_list_elements(&edk_list);
    __CPROVER_assume(aws_cryptosdk_edk_list_elements_are_valid(&edk_list));

    struct aws_array_list keyring_trace;
    __CPROVER_assume(aws_array_list_is_bounded(&keyring_trace, MAX_ITEM_SIZE, sizeof(struct aws_cryptosdk_keyring_trace_record)));
    __CPROVER_assume(keyring_trace.item_size == sizeof(struct aws_cryptosdk_keyring_trace_record));
    ensure_array_list_has_allocated_data_member(&keyring_trace);
    __CPROVER_assume(aws_array_list_is_valid(&keyring_trace));
    ensure_trace_has_allocated_records(&keyring_trace, MAX_STRING_LEN);
    __CPROVER_assume(aws_cryptosdk_keyring_trace_is_valid(&keyring_trace));

    struct aws_byte_buf unencrypted_data_key;
    ensure_byte_buf_has_allocated_buffer_member(&unencrypted_data_key);
    __CPROVER_assume(aws_byte_buf_is_valid(&unencrypted_data_key));

    struct aws_hash_table enc_ctx;
    ensure_allocated_hash_table(&enc_ctx, MAX_TABLE_SIZE);
    __CPROVER_assume(aws_hash_table_is_valid(&enc_ctx));
    ensure_hash_table_has_valid_destroy_functions(&enc_ctx);
    size_t empty_slot_idx;
    __CPROVER_assume(aws_hash_table_has_an_empty_slot(&enc_ctx, &empty_slot_idx));

    enum aws_cryptosdk_alg_id alg;

    /* Save previous reference count. */

    /* Operation under verification. */
    aws_cryptosdk_keyring_on_encrypt(&keyring,
                                     nondet_bool() ? NULL : can_fail_allocator(),
                                     &unencrypted_data_key,
                                     &keyring_trace,
                                     &edk_list,
                                     &enc_ctx,
                                     alg);

    /* Post-conditions. */
    //assert(aws_cryptosdk_keyring_is_valid(&keyring));
    //size_t new = aws_atomic_load_int(&keyring.refcount);
    //assert(new > prev_refcount);
}
