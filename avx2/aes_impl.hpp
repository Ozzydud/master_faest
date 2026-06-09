#ifndef AES_IMPL_HPP
#define AES_IMPL_HPP

#include <cassert>
#include <cstring>
#include <immintrin.h>
#include <inttypes.h>
#include <wmmintrin.h>

#include "../aes_defs.hpp"
#include "../constants.hpp"
#include "../transpose.hpp"
#include "../util.hpp"

namespace faest
{

#ifndef FAEST_USE_VAES
#define FAEST_USE_VAES 0
#endif

#if FAEST_USE_VAES && (!defined(__VAES__) || !defined(__AVX512F__))
#error "FAEST_USE_VAES requires compiling with VAES and AVX-512F support."
#endif

template <secpar S, size_t num_keys, uint32_t num_blocks>
void aes_keygen_impl(aes_round_keys<S>* aeses, const block_secpar<S>* keys, block128* output);

void rijndael192_encrypt_block(const rijndael192_round_keys* __restrict__ fixed_key,
                               block192* __restrict__ block);

template <secpar S>
inline void aes_round_function(const aes_round_keys<S>* __restrict__ round_keys,
                               block128* __restrict__ block, block128* __restrict__ after_sbox,
                               size_t round)
{
    block128 state = *block;
    block128 state_after_sbox = {_mm_aesenclast_si128(state.data, block128::set_zero().data)};
    *after_sbox = state_after_sbox;

    if (round < AES_ROUNDS<S>)
        state = {_mm_aesenc_si128(state.data, round_keys->keys[round].data)};
    else
        state = state_after_sbox ^ round_keys->keys[round];
    *block = state;
}

#if FAEST_USE_VAES && defined(__VAES__) && defined(__AVX512F__)
ALWAYS_INLINE __m512i vaes_set4_128(__m128i x0, __m128i x1, __m128i x2, __m128i x3)
{
    __m512i out = _mm512_castsi128_si512(x0);
    out = _mm512_inserti32x4(out, x1, 1);
    out = _mm512_inserti32x4(out, x2, 2);
    out = _mm512_inserti32x4(out, x3, 3);
    return out;
}

template <secpar S>
ALWAYS_INLINE __m512i vaes_load_round_keys_4(const aes_round_keys<S>* aeses, size_t key_idx,
                                             size_t round)
{
    return vaes_set4_128(aeses[key_idx + 0].keys[round].data,
                         aeses[key_idx + 1].keys[round].data,
                         aeses[key_idx + 2].keys[round].data,
                         aeses[key_idx + 3].keys[round].data);
}

template <secpar S>
ALWAYS_INLINE __m512i vaes_round_4_keys(__m512i state, const aes_round_keys<S>* aeses,
                                        size_t key_idx, size_t round)
{
    const __m512i round_key = vaes_load_round_keys_4<S>(aeses, key_idx, round);
    if (round == 0)
        return _mm512_xor_si512(state, round_key);
    if (round < AES_ROUNDS<S>)
        return _mm512_aesenc_epi128(state, round_key);
    return _mm512_aesenclast_epi128(state, round_key);
}

template <secpar S>
ALWAYS_INLINE __m512i vaes_round_with_key(__m512i state, __m512i round_key, size_t round)
{
    if (round == 0)
        return _mm512_xor_si512(state, round_key);
    if (round < AES_ROUNDS<S>)
        return _mm512_aesenc_epi128(state, round_key);
    return _mm512_aesenclast_epi128(state, round_key);
}

template <secpar S>
ALWAYS_INLINE block128 aes_round_1_key(block128 state, const aes_round_keys<S>* aeses,
                                       size_t key_idx, size_t round)
{
    if (round == 0)
        return state ^ aeses[key_idx].keys[round];
    if (round < AES_ROUNDS<S>)
        return {_mm_aesenc_si128(state.data, aeses[key_idx].keys[round].data)};
    return {_mm_aesenclast_si128(state.data, aeses[key_idx].keys[round].data)};
}
#endif

template <secpar S>
ALWAYS_INLINE void aes_round(const aes_round_keys<S>* aeses, block128* state, size_t num_keys,
                             size_t evals_per_key, size_t round)
{
    PRAGMA_UNROLL(2*AES_PREFERRED_WIDTH)
    for (size_t i = 0; i < num_keys * evals_per_key; ++i)
        if (round == 0)
            state[i] = state[i] ^ aeses[i / evals_per_key].keys[round];
        else if (round < AES_ROUNDS<S>)
            state[i] = {_mm_aesenc_si128(state[i].data, aeses[i / evals_per_key].keys[round].data)};
        else state[i] = {
            _mm_aesenclast_si128(state[i].data, aeses[i / evals_per_key].keys[round].data)};
}

// This implements the rijndael256 RotateRows step, then cancels out the RotateRows of AES so
// that AES-NI can be used for the sbox.
ALWAYS_INLINE void rijndael256_rotate_rows_undo_128(block128* s)
{
    // Swapping bytes between 128-bit halves is equivalent to rotating left overall, then
    // rotating right within each half.
    __m128i mask = _mm_setr_epi8(0, -1, -1, -1, 0, 0, -1, -1, 0, 0, -1, -1, 0, 0, 0, -1);
    __m128i b0_blended = _mm_blendv_epi8(s[0].data, s[1].data, mask);
    __m128i b1_blended = _mm_blendv_epi8(s[1].data, s[0].data, mask);

    // The rotations for 128-bit AES are different, so rotate within the halves to
    // match.
    __m128i perm = _mm_setr_epi8(0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3);
    s[0] = {_mm_shuffle_epi8(b0_blended, perm)};
    s[1] = {_mm_shuffle_epi8(b1_blended, perm)};
}

ALWAYS_INLINE void rijndael256_round(const rijndael256_round_keys* round_keys, block256* state,
                                     size_t num_keys, size_t evals_per_key, size_t round)
{
#ifdef __GNUC__
    _Pragma(STRINGIZE(GCC unroll (2*RIJNDAEL256_PREFERRED_WIDTH)))
#endif
        for (size_t i = 0; i < num_keys * evals_per_key; ++i)
    {
        block128 s[2], round_key[2];
        memcpy(&s[0], &state[i], sizeof(block256));
        memcpy(&round_key[0], &round_keys[i / evals_per_key].keys[round], sizeof(block256));

        // Use AES-NI to implement the round function.
        if (round == 0)
        {
            s[0] = s[0] ^ round_key[0];
            s[1] = s[1] ^ round_key[1];
        }
        else if (round < AES_ROUNDS<secpar::s256>)
        {
            rijndael256_rotate_rows_undo_128(&s[0]);
            s[0] = {_mm_aesenc_si128(s[0].data, round_key[0].data)};
            s[1] = {_mm_aesenc_si128(s[1].data, round_key[1].data)};
        }
        else
        {
            rijndael256_rotate_rows_undo_128(&s[0]);
            s[0] = {_mm_aesenclast_si128(s[0].data, round_key[0].data)};
            s[1] = {_mm_aesenclast_si128(s[1].data, round_key[1].data)};
        }

        memcpy(&state[i], &s[0], sizeof(block256));
    }
}

#include "../common/aes_impl.inc"

} // namespace faest

#endif
