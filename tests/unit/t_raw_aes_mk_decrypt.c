/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may not use
 * this file except in compliance with the License. A copy of the License is
 * located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <aws/cryptosdk/private/raw_aes_mk.h>
#include "testing.h"

const uint8_t test_vector_master_key_id[] = "asdfhasiufhiasuhviawurhgiuawrhefiuawhf";
const uint8_t test_vector_provider_id[] = "static-random";
const uint8_t test_vector_wrapping_key[] =
{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

/**
 * The right EDK for decrypt_data_key_empty_encryption_context.
 */
struct aws_cryptosdk_edk good_edk() {
    // first 32 bytes: encrypted data key, last 16 bytes GCM tag
    static const uint8_t edk_bytes[] =
        {0x54, 0x2b, 0xf0, 0xdc, 0x35, 0x20, 0x07, 0x38, 0xe4, 0x9e, 0x34, 0xfa, 0xa6, 0xbf, 0x11, 0xed,
         0x45, 0x40, 0x97, 0xfd, 0xb8, 0xe3, 0x36, 0x75, 0x5c, 0x03, 0xbb, 0x9f, 0xa4, 0x42, 0x9e, 0x66,
         0x44, 0x7c, 0x39, 0xf7, 0x7f, 0xfe, 0xbc, 0xa5, 0x98, 0x70, 0xe9, 0xa8, 0xc9, 0xb5, 0x7f, 0x6f};

    static const uint8_t edk_provider_info[] =
        "asdfhasiufhiasuhviawurhgiuawrhefiuawhf" // master key ID
        "\x00\x00\x00\x80" // GCM tag length in bits
        "\x00\x00\x00\x0c" // IV length in bytes
        "\xbe\xa0\xfb\xd0\x0e\xee\x0d\x94\xd9\xb1\xb3\x93"; // IV

    struct aws_cryptosdk_edk edk;
    edk.enc_data_key = aws_byte_buf_from_array(edk_bytes, sizeof(edk_bytes));
    edk.provider_id = aws_byte_buf_from_array(test_vector_provider_id, sizeof(test_vector_provider_id) - 1);
    edk.provider_info = aws_byte_buf_from_array(edk_provider_info, sizeof(edk_provider_info) - 1);
    return edk;
}

/**
 * A bunch of wrong EDKs for testing various failure scenarios.
 */
struct aws_cryptosdk_edk empty_edk() {
    struct aws_cryptosdk_edk edk = {{0}};
    return edk;
}

struct aws_cryptosdk_edk wrong_provider_id_edk() {
    struct aws_cryptosdk_edk edk = good_edk();
    edk.provider_id = aws_byte_buf_from_c_str("foobar");
    return edk;
} 

struct aws_cryptosdk_edk wrong_edk_bytes_len_edk() {
    struct aws_cryptosdk_edk edk = good_edk();
    edk.enc_data_key.len--;
    return edk;
}

struct aws_cryptosdk_edk wrong_provider_info_len_edk() {
    struct aws_cryptosdk_edk edk = good_edk();
    edk.provider_info.len--;
    return edk;
}

struct aws_cryptosdk_edk wrong_master_key_id_edk() {
    struct aws_cryptosdk_edk edk = good_edk();
    static const uint8_t edk_provider_info[] =
        "asdfhasiufhiasuhviawurhgiuawrhefiuOOPS" // wrong master key ID
        "\x00\x00\x00\x80" // GCM tag length in bits
        "\x00\x00\x00\x0c" // IV length in bytes
        "\xbe\xa0\xfb\xd0\x0e\xee\x0d\x94\xd9\xb1\xb3\x93"; // IV
    edk.provider_info = aws_byte_buf_from_array(edk_provider_info, sizeof(edk_provider_info) - 1);
    return edk;
}

struct aws_cryptosdk_edk wrong_iv_len_edk() {
    struct aws_cryptosdk_edk edk = good_edk();
    static const uint8_t edk_provider_info[] =
        "asdfhasiufhiasuhviawurhgiuawrhefiuawhf" // master key ID
        "\x00\x00\x00\x80" // GCM tag length in bits
        "\x00\x00\x00\x0d" // wrong IV length in bytes
        "\xbe\xa0\xfb\xd0\x0e\xee\x0d\x94\xd9\xb1\xb3\x93"; // IV
    edk.provider_info = aws_byte_buf_from_array(edk_provider_info, sizeof(edk_provider_info) - 1);
    return edk;
}

struct aws_cryptosdk_edk wrong_tag_len_edk() {
    struct aws_cryptosdk_edk edk = good_edk();
    static const uint8_t edk_provider_info[] =
        "asdfhasiufhiasuhviawurhgiuawrhefiuawhf" // master key ID
        "\x00\x00\x00\x81" // wrong GCM tag length in bits
        "\x00\x00\x00\x0c" // IV length in bytes
        "\xbe\xa0\xfb\xd0\x0e\xee\x0d\x94\xd9\xb1\xb3\x93"; // IV
    edk.provider_info = aws_byte_buf_from_array(edk_provider_info, sizeof(edk_provider_info) - 1);
    return edk;
}

/**
 * Straightforward decrypt data key in simplest case: one EDK in list and no encryption context.
 */
int decrypt_data_key_empty_encryption_context() {
    struct aws_allocator * alloc = aws_default_allocator();

    struct aws_cryptosdk_mk * mk = aws_cryptosdk_raw_aes_mk_new(alloc,
                                                                test_vector_master_key_id,
                                                                sizeof(test_vector_master_key_id) - 1,
                                                                test_vector_provider_id,
                                                                sizeof(test_vector_provider_id) - 1,
                                                                test_vector_wrapping_key);
    TEST_ASSERT_ADDR_NOT_NULL(mk);

    struct aws_hash_table enc_context;
    TEST_ASSERT_INT_EQ(aws_hash_table_init(&enc_context, alloc, 1, aws_hash_string, aws_string_eq, aws_string_destroy, aws_string_destroy),
		     AWS_OP_SUCCESS);

    struct aws_cryptosdk_decryption_request req;
    req.alloc = alloc;
    req.alg = AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE;
    req.enc_context = &enc_context;

    aws_array_list_init_dynamic(&req.encrypted_data_keys, alloc, 1, sizeof(struct aws_cryptosdk_edk));

    struct aws_cryptosdk_edk edk = good_edk();
    aws_array_list_push_back(&req.encrypted_data_keys, (void *)&edk);

    struct aws_cryptosdk_decryption_materials * dec_mat = aws_cryptosdk_decryption_materials_new(alloc, req.alg);
    TEST_ASSERT_ADDR_NOT_NULL(dec_mat);

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_mk_decrypt_data_key(mk, dec_mat, &req));
    TEST_ASSERT_ADDR_NOT_NULL(dec_mat->unencrypted_data_key.buffer);
    TEST_ASSERT_BUF_EQ(dec_mat->unencrypted_data_key,
		       0xdd, 0xc2, 0xf6, 0x5f, 0x96, 0xa2, 0xda, 0x96, 0x86, 0xea, 0xd6, 0x58, 0xfe, 0xe9, 0xc0, 0xc3,
		       0xb6, 0xd4, 0xb1, 0x92, 0xf2, 0xba, 0x50, 0x93, 0x21, 0x97, 0x62, 0xab, 0x7d, 0x25, 0x9f, 0x2c);

    aws_cryptosdk_decryption_materials_destroy(dec_mat);
    aws_array_list_clean_up(&req.encrypted_data_keys);
    aws_hash_table_clean_up(&enc_context);
    aws_cryptosdk_mk_destroy(mk);
    return 0;
}

typedef struct aws_cryptosdk_edk (*edk_generator)();

/**
 * Same as the last test but EDK list has many wrong EDKs which fail for different reasons before getting to good one.
 */
int decrypt_data_key_multiple_edks() {
    struct aws_allocator * alloc = aws_default_allocator();

    struct aws_cryptosdk_mk * mk = aws_cryptosdk_raw_aes_mk_new(alloc,
                                                                test_vector_master_key_id,
                                                                sizeof(test_vector_master_key_id) - 1,
                                                                test_vector_provider_id,
                                                                sizeof(test_vector_provider_id) - 1,
                                                                test_vector_wrapping_key);
    TEST_ASSERT_ADDR_NOT_NULL(mk);

    struct aws_hash_table enc_context;
    TEST_ASSERT_INT_EQ(aws_hash_table_init(&enc_context, alloc, 1, aws_hash_string, aws_string_eq, aws_string_destroy, aws_string_destroy),
                       AWS_OP_SUCCESS);

    struct aws_cryptosdk_decryption_request req;
    req.alloc = alloc;
    req.alg = AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE;
    req.enc_context = &enc_context;

    aws_array_list_init_dynamic(&req.encrypted_data_keys, alloc, 1, sizeof(struct aws_cryptosdk_edk));

    edk_generator edk_gens[] = {empty_edk,
                                wrong_provider_id_edk,
                                wrong_edk_bytes_len_edk,
                                wrong_provider_info_len_edk,
                                wrong_master_key_id_edk,
                                wrong_iv_len_edk,
                                wrong_tag_len_edk,
                                good_edk};

    for (int idx = 0; idx < sizeof(edk_gens)/sizeof(edk_generator); ++idx) {
        struct aws_cryptosdk_edk edk = edk_gens[idx]();
        aws_array_list_push_back(&req.encrypted_data_keys, (void *)&edk);
    }

    struct aws_cryptosdk_decryption_materials * dec_mat = aws_cryptosdk_decryption_materials_new(alloc, req.alg);
    TEST_ASSERT_ADDR_NOT_NULL(dec_mat);

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_mk_decrypt_data_key(mk, dec_mat, &req));
    TEST_ASSERT_ADDR_NOT_NULL(dec_mat->unencrypted_data_key.buffer);
    TEST_ASSERT_BUF_EQ(dec_mat->unencrypted_data_key,
                       0xdd, 0xc2, 0xf6, 0x5f, 0x96, 0xa2, 0xda, 0x96, 0x86, 0xea, 0xd6, 0x58, 0xfe, 0xe9, 0xc0, 0xc3,
                       0xb6, 0xd4, 0xb1, 0x92, 0xf2, 0xba, 0x50, 0x93, 0x21, 0x97, 0x62, 0xab, 0x7d, 0x25, 0x9f, 0x2c);

    aws_cryptosdk_decryption_materials_destroy(dec_mat);
    aws_array_list_clean_up(&req.encrypted_data_keys);
    aws_hash_table_clean_up(&enc_context);
    aws_cryptosdk_mk_destroy(mk);

    return 0;
}

/**
 * Same as the last test but no good EDK, so decryption fails.
 */
int decrypt_data_key_no_good_edk() {
    struct aws_allocator * alloc = aws_default_allocator();

    struct aws_cryptosdk_mk * mk = aws_cryptosdk_raw_aes_mk_new(alloc,
                                                                test_vector_master_key_id,
                                                                sizeof(test_vector_master_key_id) - 1,
                                                                test_vector_provider_id,
                                                                sizeof(test_vector_provider_id) - 1,
                                                                test_vector_wrapping_key);
    TEST_ASSERT_ADDR_NOT_NULL(mk);

    struct aws_hash_table enc_context;
    TEST_ASSERT_INT_EQ(aws_hash_table_init(&enc_context, alloc, 1, aws_hash_string, aws_string_eq, aws_string_destroy, aws_string_destroy),
                       AWS_OP_SUCCESS);

    struct aws_cryptosdk_decryption_request req;
    req.alloc = alloc;
    req.alg = AES_256_GCM_IV12_AUTH16_KDSHA256_SIGNONE;
    req.enc_context = &enc_context;

    aws_array_list_init_dynamic(&req.encrypted_data_keys, alloc, 1, sizeof(struct aws_cryptosdk_edk));

    edk_generator edk_gens[] = {empty_edk,
                                wrong_provider_id_edk,
                                wrong_edk_bytes_len_edk,
                                wrong_provider_info_len_edk,
                                wrong_master_key_id_edk,
                                wrong_iv_len_edk,
                                wrong_tag_len_edk};

    for (int idx = 0; idx < sizeof(edk_gens)/sizeof(edk_generator); ++idx) {
        struct aws_cryptosdk_edk edk = edk_gens[idx]();
        aws_array_list_push_back(&req.encrypted_data_keys, (void *)&edk);
    }

    struct aws_cryptosdk_decryption_materials * dec_mat = aws_cryptosdk_decryption_materials_new(alloc, req.alg);
    TEST_ASSERT_ADDR_NOT_NULL(dec_mat);

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_mk_decrypt_data_key(mk, dec_mat, &req));
    TEST_ASSERT_ADDR_NULL(dec_mat->unencrypted_data_key.buffer);

    aws_cryptosdk_decryption_materials_destroy(dec_mat);
    aws_array_list_clean_up(&req.encrypted_data_keys);
    aws_hash_table_clean_up(&enc_context);
    aws_cryptosdk_mk_destroy(mk);

    return 0;
}

/**
 * Single EDK test with algorithm suite including signing, so that there is an encryption context with public key.
 */
int decrypt_data_key_with_signature() {
    struct aws_allocator * alloc = aws_default_allocator();

    struct aws_cryptosdk_mk * mk = aws_cryptosdk_raw_aes_mk_new(alloc,
                                                                test_vector_master_key_id,
                                                                sizeof(test_vector_master_key_id) - 1,
                                                                test_vector_provider_id,
                                                                sizeof(test_vector_provider_id) - 1,
                                                                test_vector_wrapping_key);
    TEST_ASSERT_ADDR_NOT_NULL(mk);

    AWS_STATIC_STRING_FROM_LITERAL(enc_context_key, "aws-crypto-public-key");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_val, "AguATtjJFzJnlpNXdyDG7e8bfLZYRx+vxdAmYz+ztVBYyFhsMpchjz9ev3MdXQMD9Q==");
    struct aws_hash_table enc_context;
    TEST_ASSERT_INT_EQ(aws_hash_table_init(&enc_context, alloc, 1, aws_hash_string, aws_string_eq, aws_string_destroy, aws_string_destroy),
                       AWS_OP_SUCCESS);
    struct aws_hash_element * elem;
    TEST_ASSERT_INT_EQ(aws_hash_table_create(&enc_context, (void *)enc_context_key, &elem, NULL), AWS_OP_SUCCESS);
    elem->value = (void *)enc_context_val;

    struct aws_cryptosdk_decryption_request req;
    req.alloc = alloc;
    // FIXME: change to correct algorithm after it is implemented.
    // This test data was made in mode AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384, so it includes the public key in the
    // encryption context. The only thing this test is using the algorithm for is getting the length of the data key,
    // so as long as we specify another AES-256 suite the test passes, but it communicates the wrong thing to the reader.
    // We cannot specify the correct algorithm at the moment, because it is currently commented out of alg_props implementation.
    // Once we are done implementing the algorithm with signature in alg_props, remove this comment and switch req.alg to
    // correct value.
    //req.alg = AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384; // correct algorithm suite
    req.alg = AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE; // wrong algorithm suite
    req.enc_context = &enc_context;
    aws_array_list_init_dynamic(&req.encrypted_data_keys, alloc, 1, sizeof(struct aws_cryptosdk_edk));

    // first 32 bytes: encrypted data key, last 16 bytes GCM tag
    const uint8_t edk_bytes[] = {0xff, 0xaf, 0xb4, 0x82, 0xf0, 0x0f, 0x9b, 0x4e, 0x5e, 0x0e, 0x75, 0xea, 0x67, 0xbb, 0x80, 0xc6,
                                 0x5a, 0x37, 0x18, 0x35, 0x55, 0x62, 0xfb, 0x9c, 0x9e, 0x90, 0xd8, 0xae, 0xdd, 0x39, 0xd0, 0x67,
                                 0x85, 0x0e, 0x18, 0x5b, 0xcb, 0x92, 0xc7, 0xbb, 0xff, 0x88, 0xfd, 0xe8, 0xf9, 0x33, 0x6c, 0x74};

    const uint8_t edk_provider_info[] =
      "asdfhasiufhiasuhviawurhgiuawrhefiuawhf" // master key ID
      "\x00\x00\x00\x80" // GCM tag length in bits
      "\x00\x00\x00\x0c" // IV length in bytes
      "\x1b\x48\x76\xb4\x7a\x10\x16\x19\xeb\x3f\x93\x1d"; // IV

    struct aws_cryptosdk_edk edk;
    edk.enc_data_key = aws_byte_buf_from_array(edk_bytes, sizeof(edk_bytes));
    edk.provider_id = aws_byte_buf_from_array(test_vector_provider_id, sizeof(test_vector_provider_id) - 1);
    edk.provider_info = aws_byte_buf_from_array(edk_provider_info, sizeof(edk_provider_info) - 1);

    aws_array_list_push_back(&req.encrypted_data_keys, (void *)&edk);
    
    struct aws_cryptosdk_decryption_materials * dec_mat = aws_cryptosdk_decryption_materials_new(alloc, req.alg);
    TEST_ASSERT_ADDR_NOT_NULL(dec_mat);

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_mk_decrypt_data_key(mk, dec_mat, &req));
    TEST_ASSERT_ADDR_NOT_NULL(dec_mat->unencrypted_data_key.buffer);
    TEST_ASSERT_BUF_EQ(dec_mat->unencrypted_data_key,
                       0x9b, 0x01, 0xc1, 0xaa, 0x62, 0x25, 0x1d, 0x0f, 0x16, 0xa0, 0xa2, 0x15, 0xea, 0xe4, 0xc2, 0x37,
                       0x4a, 0x8c, 0xc7, 0x9f, 0xfa, 0x3a, 0xe7, 0xa2, 0xa4, 0xa8, 0x1e, 0x83, 0xba, 0x38, 0x23, 0x16);

    aws_cryptosdk_decryption_materials_destroy(dec_mat);
    aws_array_list_clean_up(&req.encrypted_data_keys);
    aws_hash_table_clean_up(&enc_context);
    aws_cryptosdk_mk_destroy(mk);
    return 0;
}

/**
 * Same as the last test but with more stuff in the encryption context to verify that sorting and serialization of
 * encryption context works properly vis a vis decrypting data keys.
 */
int decrypt_data_key_with_signature_and_encryption_context() {
    struct aws_allocator * alloc = aws_default_allocator();

    struct aws_cryptosdk_mk * mk = aws_cryptosdk_raw_aes_mk_new(alloc,
                                                                test_vector_master_key_id,
                                                                sizeof(test_vector_master_key_id) - 1,
                                                                test_vector_provider_id,
                                                                sizeof(test_vector_provider_id) - 1,
                                                                test_vector_wrapping_key);
    TEST_ASSERT_ADDR_NOT_NULL(mk);

    AWS_STATIC_STRING_FROM_LITERAL(enc_context_key_1, "aws-crypto-public-key");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_val_1, "A/f8U0IfPC5vseQ13rHlkbPjK6c0jikfvY7F+I2PZxVI9ZHW38lbxMUabbPZdIgMOg==");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_key_2, "aaaaaaaa");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_val_2, "AAAAAAAA");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_key_3, "bbbbbbbb");
    AWS_STATIC_STRING_FROM_LITERAL(enc_context_val_3, "BBBBBBBB");

    const struct aws_string * keys[] = {enc_context_key_1, enc_context_key_2, enc_context_key_3};
    const struct aws_string * vals[] = {enc_context_val_1, enc_context_val_2, enc_context_val_3};

    struct aws_hash_table enc_context;
    TEST_ASSERT_INT_EQ(aws_hash_table_init(&enc_context, alloc, 4, aws_hash_string, aws_string_eq, aws_string_destroy, aws_string_destroy),
                       AWS_OP_SUCCESS);

    for (int idx = 0; idx < sizeof(keys)/sizeof(const struct aws_string *); ++idx) {
        struct aws_hash_element * elem;
        TEST_ASSERT_INT_EQ(aws_hash_table_create(&enc_context, (void *)keys[idx], &elem, NULL), AWS_OP_SUCCESS);
        elem->value = (void *)vals[idx];
    }

    struct aws_cryptosdk_decryption_request req;
    req.alloc = alloc;
    // FIXME: change to correct algorithm after it is implemented.
    // This test data was made in mode AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384, so it includes the public key in the
    // encryption context. The only thing this test is using the algorithm for is getting the length of the data key,
    // so as long as we specify another AES-256 suite the test passes, but it communicates the wrong thing to the reader.
    // We cannot specify the correct algorithm at the moment, because it is currently commented out of alg_props implementation.
    // Once we are done implementing the algorithm with signature in alg_props, remove this comment and switch req.alg to
    // correct value.
    //req.alg = AES_256_GCM_IV12_AUTH16_KDSHA384_SIGEC384; // correct algorithm suite
    req.alg = AES_256_GCM_IV12_AUTH16_KDNONE_SIGNONE; // wrong algorithm suite
    req.enc_context = &enc_context;
    aws_array_list_init_dynamic(&req.encrypted_data_keys, alloc, 1, sizeof(struct aws_cryptosdk_edk));

    // first 32 bytes: encrypted data key, last 16 bytes GCM tag
    const uint8_t edk_bytes[] = {0x14, 0xcc, 0xfb, 0xfe, 0x81, 0x50, 0x1e, 0x07, 0xe6, 0xc8, 0x34, 0x00, 0x95, 0xb1, 0x17, 0xd3,
                                 0x0e, 0x7c, 0xb9, 0x15, 0xc7, 0x45, 0x94, 0x0d, 0x34, 0xf7, 0xde, 0x11, 0x1b, 0x33, 0x5c, 0xbb,
                                 0xc7, 0x40, 0xc5, 0x23, 0xec, 0x5c, 0x3e, 0xc1, 0xa0, 0x54, 0x7a, 0x60, 0xab, 0x20, 0x85, 0xff};

    const uint8_t edk_provider_info[] =
        "asdfhasiufhiasuhviawurhgiuawrhefiuawhf" // master key ID
        "\x00\x00\x00\x80" // GCM tag length in bits
        "\x00\x00\x00\x0c" // IV length in bytes
        "\x53\xd3\x06\x47\xee\xa2\x4d\x3e\xcd\x28\x16\x82"; // IV

    struct aws_cryptosdk_edk edk;
    edk.enc_data_key = aws_byte_buf_from_array(edk_bytes, sizeof(edk_bytes));
    edk.provider_id = aws_byte_buf_from_array(test_vector_provider_id, sizeof(test_vector_provider_id) - 1);
    edk.provider_info = aws_byte_buf_from_array(edk_provider_info, sizeof(edk_provider_info) - 1);

    aws_array_list_push_back(&req.encrypted_data_keys, (void *)&edk);

    struct aws_cryptosdk_decryption_materials * dec_mat = aws_cryptosdk_decryption_materials_new(alloc, req.alg);
    TEST_ASSERT_ADDR_NOT_NULL(dec_mat);

    TEST_ASSERT_INT_EQ(AWS_OP_SUCCESS, aws_cryptosdk_mk_decrypt_data_key(mk, dec_mat, &req));
    TEST_ASSERT_ADDR_NOT_NULL(dec_mat->unencrypted_data_key.buffer);
    TEST_ASSERT_BUF_EQ(dec_mat->unencrypted_data_key,
                       0xaf, 0x4e, 0xaa, 0x6f, 0x3e, 0x34, 0xfa, 0x50, 0x48, 0xd1, 0x48, 0x02, 0x33, 0x86, 0xc5, 0x98,
                       0x2c, 0x64, 0xe3, 0x54, 0xc4, 0x27, 0xe3, 0x66, 0x39, 0x28, 0x94, 0x89, 0xf5, 0x71, 0x68, 0xcd);

    aws_cryptosdk_decryption_materials_destroy(dec_mat);
    aws_array_list_clean_up(&req.encrypted_data_keys);
    aws_hash_table_clean_up(&enc_context);
    aws_cryptosdk_mk_destroy(mk);
    return 0;
}

struct test_case raw_aes_mk_decrypt_test_cases[] = {
    { "raw_aes_mk", "decrypt_data_key_empty_encryption_context", decrypt_data_key_empty_encryption_context },
    { "raw_aes_mk", "decrypt_data_key_multiple_edks", decrypt_data_key_multiple_edks },
    { "raw_aes_mk", "decrypt_data_key_no_good_edk", decrypt_data_key_no_good_edk },
    { "raw_aes_mk", "decrypt_data_key_with_signature", decrypt_data_key_with_signature },
    { "raw_aes_mk", "decrypt_data_key_with_signature_and_encryption_context", decrypt_data_key_with_signature_and_encryption_context },
    { NULL }
};
