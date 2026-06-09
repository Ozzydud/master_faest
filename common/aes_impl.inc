template <secpar S, size_t num_keys, size_t blocks_per_key>
ALWAYS_INLINE void
aes_keygen_ecb(const block_secpar<S>* __restrict__ keys, aes_round_keys<S>* __restrict__ aeses,
               block128* __restrict__ data)
{
    // TODO: can probably ditch this wrapper now.
    aes_keygen_impl<S, num_keys, blocks_per_key>(aeses, keys, data);
}

#ifndef FAEST_USE_VAES
#define FAEST_USE_VAES 0
#endif

#if FAEST_USE_VAES && (!defined(__VAES__) || !defined(__AVX512F__))
#error "FAEST_USE_VAES requires compiling with VAES and AVX-512F support."
#endif

template <secpar S, size_t num_keys, size_t blocks_per_key>
inline void aes_ecb(const aes_round_keys<S>* __restrict__ aeses, block128* __restrict__ data)
{
#if FAEST_USE_VAES && defined(__VAES__) && defined(__AVX512F__)
    if constexpr (num_keys >= 4 && blocks_per_key == 1)
    {
        size_t key_idx = 0;
        for (; key_idx + 4 <= num_keys; key_idx += 4)
        {
            __m512i state =
                _mm512_loadu_si512(reinterpret_cast<const void*>(&data[key_idx]));

            for (size_t round = 0; round <= AES_ROUNDS<S>; ++round)
                state = vaes_round_4_keys<S>(state, aeses, key_idx, round);

            _mm512_storeu_si512(reinterpret_cast<void*>(&data[key_idx]), state);
        }
        for (; key_idx < num_keys; ++key_idx)
        {
            block128 state = data[key_idx];
            for (size_t round = 0; round <= AES_ROUNDS<S>; ++round)
                state = aes_round_1_key<S>(state, aeses, key_idx, round);
            data[key_idx] = state;
        }
        return;
    }

    if constexpr (num_keys >= 4 && blocks_per_key == 2)
    {
        size_t key_idx = 0;
        alignas(64) block128 lanes0[4];
        alignas(64) block128 lanes1[4];
        for (; key_idx + 4 <= num_keys; key_idx += 4)
        {
            __m512i state0 = vaes_set4_128(data[(key_idx + 0) * 2 + 0].data,
                                           data[(key_idx + 1) * 2 + 0].data,
                                           data[(key_idx + 2) * 2 + 0].data,
                                           data[(key_idx + 3) * 2 + 0].data);
            __m512i state1 = vaes_set4_128(data[(key_idx + 0) * 2 + 1].data,
                                           data[(key_idx + 1) * 2 + 1].data,
                                           data[(key_idx + 2) * 2 + 1].data,
                                           data[(key_idx + 3) * 2 + 1].data);

            for (size_t round = 0; round <= AES_ROUNDS<S>; ++round)
            {
                const __m512i round_key = vaes_load_round_keys_4<S>(aeses, key_idx, round);
                state0 = vaes_round_with_key<S>(state0, round_key, round);
                state1 = vaes_round_with_key<S>(state1, round_key, round);
            }

            _mm512_storeu_si512(reinterpret_cast<void*>(lanes0), state0);
            _mm512_storeu_si512(reinterpret_cast<void*>(lanes1), state1);
            data[(key_idx + 0) * 2 + 0] = lanes0[0];
            data[(key_idx + 0) * 2 + 1] = lanes1[0];
            data[(key_idx + 1) * 2 + 0] = lanes0[1];
            data[(key_idx + 1) * 2 + 1] = lanes1[1];
            data[(key_idx + 2) * 2 + 0] = lanes0[2];
            data[(key_idx + 2) * 2 + 1] = lanes1[2];
            data[(key_idx + 3) * 2 + 0] = lanes0[3];
            data[(key_idx + 3) * 2 + 1] = lanes1[3];
        }
        for (; key_idx < num_keys; ++key_idx)
            for (size_t block_idx = 0; block_idx < blocks_per_key; ++block_idx)
            {
                block128 state = data[key_idx * blocks_per_key + block_idx];
                for (size_t round = 0; round <= AES_ROUNDS<S>; ++round)
                    state = aes_round_1_key<S>(state, aeses, key_idx, round);
                data[key_idx * blocks_per_key + block_idx] = state;
            }
        return;
    }

    if constexpr (num_keys >= 8 && blocks_per_key == 4)
    {
        for (size_t i = 0; i < num_keys; ++i)
        {
            __m512i state =
                _mm512_loadu_si512(reinterpret_cast<const void*>(&data[i * blocks_per_key]));
            __m512i round_key = _mm512_broadcast_i32x4(aeses[i].keys[0].data);
            state = _mm512_xor_si512(state, round_key);

            for (size_t round = 1; round < AES_ROUNDS<S>; ++round)
            {
                round_key = _mm512_broadcast_i32x4(aeses[i].keys[round].data);
                state = _mm512_aesenc_epi128(state, round_key);
            }

            round_key = _mm512_broadcast_i32x4(aeses[i].keys[AES_ROUNDS<S>].data);
            state = _mm512_aesenclast_epi128(state, round_key);
            _mm512_storeu_si512(reinterpret_cast<void*>(&data[i * blocks_per_key]), state);
        }
        return;
    }
#endif

    // IIRC, GCC won't keep state in registers unless I make this a local variable.
    block128 state[num_keys * blocks_per_key];
    memcpy(state, data, sizeof(state));

    // Make it easier for the compiler to optimize by unwinding the first and last rounds. (Since we
    // aren't asking it to unwind the whole loop.)
    aes_round(aeses, state, num_keys, blocks_per_key, 0);
    for (size_t round = 1; round < AES_ROUNDS<S>; ++round)
        aes_round(aeses, state, num_keys, blocks_per_key, round);
    aes_round(aeses, state, num_keys, blocks_per_key, AES_ROUNDS<S>);

    memcpy(data, state, sizeof(state));
}

template <size_t num_keys, uint32_t num_blocks>
inline void aes_fixed_key_ctr(const aes_round_keys<secpar::s128>* __restrict__ fixed_key,
                              const block128* __restrict__ keys,
                              const block128& iv,
                              const uint32_t* __restrict__ tweaks,
                              const uint32_t* counters,
                              block128* __restrict__ output)
{
    block128 state[num_keys * num_blocks];

    for (size_t l = 0; l < num_keys; ++l)
        for (uint32_t m = 0; m < num_blocks; ++m)
            state[l * num_blocks + m] = iv.add32(block128::set_low32(counters[l] + m, tweaks[l])) ^ keys[l];

    aes_round(fixed_key, state, 1, num_keys * num_blocks, 0);
    for (size_t round = 1; round < AES_ROUNDS<secpar::s128>; ++round)
        aes_round(fixed_key, state, 1, num_keys * num_blocks, round);
    aes_round(fixed_key, state, 1, num_keys * num_blocks, AES_ROUNDS<secpar::s128>);

    for (size_t l = 0; l < num_keys; ++l)
        for (uint32_t m = 0; m < num_blocks; ++m)
            output[l * num_blocks + m] = state[l * num_blocks + m] ^ keys[l];
}

template <size_t num_keys, uint32_t num_blocks>
inline void rijndael256_fixed_key_ctr(const rijndael256_round_keys* __restrict__ fixed_key,
                                      const block256* __restrict__ keys,
                                      const block256& iv,
                                      const uint32_t* __restrict__ tweaks,
                                      const uint32_t* __restrict__ counters,
                                      block256* __restrict__ output)
{
    block256 state[num_keys * num_blocks];

    for (size_t l = 0; l < num_keys; ++l)
        for (uint32_t m = 0; m < num_blocks; ++m)
            state[l * num_blocks + m] = iv.add32(block256::set_low32(counters[l] + m, tweaks[l])) ^ keys[l];

    rijndael256_round(fixed_key, state, 1, num_keys * num_blocks, 0);
    for (size_t round = 1; round < RIJNDAEL_ROUNDS<secpar::s256>; ++round)
        rijndael256_round(fixed_key, state, 1, num_keys * num_blocks, round);
    rijndael256_round(fixed_key, state, 1, num_keys * num_blocks, RIJNDAEL_ROUNDS<secpar::s256>);

    for (size_t l = 0; l < num_keys; ++l)
        for (uint32_t m = 0; m < num_blocks; ++m)
            output[l * num_blocks + m] = state[l * num_blocks + m] ^ keys[l];
}

template <size_t num_keys, uint32_t num_blocks>
inline void rijndael192_fixed_key_ctr(const rijndael192_round_keys* __restrict__ fixed_key,
                                      const block192* __restrict__ keys,
                                      const block192& iv,
                                      const uint32_t* __restrict__ tweaks,
                                      const uint32_t* __restrict__ counters,
                                      block192* __restrict__ output)
{
    for (size_t l = 0; l < num_keys; ++l)
    {
        for (uint32_t m = 0; m < num_blocks; ++m)
        {
            block192 state = iv.add32(block192::set_low32(counters[l] + m, tweaks[l])) ^ keys[l];
            rijndael192_encrypt_block(fixed_key, &state);
            output[l * num_blocks + m] = state ^ keys[l];
        }
    }
}
