#include <array>
#include <string>

#include "aes.hpp"
#include "prgs.hpp"
#include "test.hpp"

#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_template_test_macros.hpp>
#include <catch2/catch_test_macros.hpp>

template <size_t N>
static block128 reduce_blocks(const std::array<block128, N>& blocks)
{
    block128 acc = block128::set_zero();
    for (const auto& block : blocks)
        acc = acc ^ block;
    return acc;
}

template <secpar S, size_t N>
static block128 reduce_round_keys(const std::array<aes_round_keys<S>, N>& round_keys)
{
    block128 acc = block128::set_zero();
    for (const auto& key : round_keys)
    {
        acc = acc ^ key.keys[0];
        acc = acc ^ key.keys[AES_ROUNDS<S>];
    }
    return acc;
}

template <secpar S, size_t num_keys, uint32_t blocks_per_key>
static void bench_aes_ctr_prg_shape()
{
    using PRG = aes_ctr_prg<S>;

    std::array<typename PRG::key_t, num_keys> keys;
    std::array<typename PRG::expanded_key_t, num_keys> expanded_keys;
    std::array<typename PRG::tweak_t, num_keys> tweaks;
    std::array<typename PRG::count_t, num_keys> counters;
    std::array<typename PRG::block_t, num_keys * blocks_per_key> output;

    std::generate(keys.begin(), keys.end(), rand<typename PRG::key_t>);
    std::generate(tweaks.begin(), tweaks.end(), rand<typename PRG::tweak_t>);
    std::generate(counters.begin(), counters.end(), rand<typename PRG::count_t>);
    const typename PRG::iv_t iv = rand<typename PRG::iv_t>();

    PRG::template init<num_keys, blocks_per_key>(keys.data(), expanded_keys.data(), iv,
                                                 tweaks.data(), counters.data(), output.data());

    const std::string shape = std::to_string(num_keys) + " keys x " +
                              std::to_string(blocks_per_key) + " blocks";

    BENCHMARK("aes_keygen only - " + shape)
    {
        std::array<typename PRG::expanded_key_t, num_keys> local_expanded_keys;
        for (size_t i = 0; i < num_keys; ++i)
            aes_keygen<S>(&local_expanded_keys[i], keys[i]);
        return reduce_round_keys<S>(local_expanded_keys);
    };

    BENCHMARK("aes_ctr_prg::init keygen+encrypt - " + shape)
    {
        std::array<typename PRG::expanded_key_t, num_keys> local_expanded_keys;
        std::array<typename PRG::block_t, num_keys * blocks_per_key> local_output;
        PRG::template init<num_keys, blocks_per_key>(keys.data(), local_expanded_keys.data(), iv,
                                                     tweaks.data(), counters.data(),
                                                     local_output.data());
        return reduce_blocks(local_output);
    };

    BENCHMARK("aes_ctr_prg::gen encrypt only - " + shape)
    {
        std::array<typename PRG::block_t, num_keys * blocks_per_key> local_output;
        PRG::template gen<num_keys, blocks_per_key>(expanded_keys.data(), iv, tweaks.data(),
                                                    counters.data(), local_output.data());
        return reduce_blocks(local_output);
    };
}

template <secpar S, size_t num_keys>
static void bench_aes_ctr_prg_key_count()
{
    bench_aes_ctr_prg_shape<S, num_keys, 1>();
    bench_aes_ctr_prg_shape<S, num_keys, 2>();
    bench_aes_ctr_prg_shape<S, num_keys, 4>();
}

template <secpar S>
static void bench_aes_ctr_prg_secpar()
{
    bench_aes_ctr_prg_key_count<S, 1>();
    bench_aes_ctr_prg_key_count<S, 2>();
    bench_aes_ctr_prg_key_count<S, 4>();
    bench_aes_ctr_prg_key_count<S, 8>();
}

TEMPLATE_TEST_CASE("bench prg aes-ctr key schedule", "[.][bench][prg]", secpar128_t, secpar192_t,
                   secpar256_t)
{
    bench_aes_ctr_prg_secpar<TestType::value>();
}
