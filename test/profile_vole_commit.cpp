#include "all.inc"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <iostream>
#include <new>
#include <stdexcept>
#include <string>
#include <vector>

using namespace faest;

namespace
{

volatile uint64_t profile_sink = 0;

class splitmix64
{
  public:
    explicit splitmix64(uint64_t seed) : state(seed) {}

    uint64_t next()
    {
        uint64_t z = (state += 0x9e3779b97f4a7c15ULL);
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
        z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
        return z ^ (z >> 31);
    }

    void fill(void* ptr, size_t bytes)
    {
        auto* out = static_cast<uint8_t*>(ptr);
        while (bytes >= sizeof(uint64_t))
        {
            const uint64_t value = next();
            std::memcpy(out, &value, sizeof(value));
            out += sizeof(value);
            bytes -= sizeof(value);
        }
        if (bytes)
        {
            const uint64_t value = next();
            std::memcpy(out, &value, bytes);
        }
    }

  private:
    uint64_t state;
};

template <typename T> T random_object(splitmix64& rng)
{
    T out;
    rng.fill(&out, sizeof(out));
    return out;
}

template <typename T> T* alloc_aligned_array(size_t count)
{
    const size_t alignment = alignof(T);
    const size_t bytes = count * sizeof(T);
    const size_t rounded_bytes = ((bytes + alignment - 1) / alignment) * alignment;
    auto* ptr = static_cast<T*>(std::aligned_alloc(alignment, rounded_bytes));
    if (!ptr)
        throw std::bad_alloc();
    std::memset(ptr, 0, rounded_bytes);
    return ptr;
}

unsigned char* alloc_aligned_bytes(size_t bytes, size_t alignment)
{
    const size_t rounded_bytes = ((bytes + alignment - 1) / alignment) * alignment;
    auto* ptr = static_cast<unsigned char*>(std::aligned_alloc(alignment, rounded_bytes));
    if (!ptr)
        throw std::bad_alloc();
    std::memset(ptr, 0, rounded_bytes);
    return ptr;
}

void consume_bytes(const void* ptr, size_t bytes)
{
    const auto* data = static_cast<const uint8_t*>(ptr);
    uint64_t acc = profile_sink;
    if (bytes)
    {
        acc ^= data[0];
        acc ^= static_cast<uint64_t>(data[bytes / 2]) << 8;
        acc ^= static_cast<uint64_t>(data[bytes - 1]) << 16;
    }
    profile_sink = acc;
}

template <typename P> struct profile_buffers
{
    using CP = typename P::CONSTS;
    static constexpr secpar S = P::secpar_v;

    explicit profile_buffers(uint64_t seed_value) : commitment((P::tau_v - 1) * CP::VOLE_ROWS / 8),
                                                    check(CP::VOLE_COMMIT_CHECK_SIZE),
                                                    delta_bytes(P::delta_bits_v)
    {
        splitmix64 rng(seed_value);
        seed = random_object<block_secpar<S>>(rng);
        iv = random_object<block128>(rng);

        forest = alloc_aligned_array<block_secpar<S>>(P::bavc_t::COMMIT_NODES);
        leaves = alloc_aligned_array<block_secpar<S>>(P::bavc_t::COMMIT_LEAVES);
        hashed_leaves =
            alloc_aligned_bytes(P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len,
                                alignof(block_2secpar<S>));
        u = alloc_aligned_array<vole_block>(CP::VOLE_COL_BLOCKS);
        v = alloc_aligned_array<vole_block>(P::secpar_bits * CP::VOLE_COL_BLOCKS);
        q = alloc_aligned_array<vole_block>(P::secpar_bits * CP::VOLE_COL_BLOCKS);

        rng.fill(leaves, P::bavc_t::COMMIT_LEAVES * sizeof(block_secpar<S>));
        rng.fill(commitment.data(), commitment.size());
        for (auto& delta : delta_bytes)
            delta = (rng.next() & 1) ? 0xff : 0x00;
    }

    profile_buffers(const profile_buffers&) = delete;
    profile_buffers& operator=(const profile_buffers&) = delete;

    ~profile_buffers()
    {
        std::free(forest);
        std::free(leaves);
        std::free(hashed_leaves);
        std::free(u);
        std::free(v);
        std::free(q);
    }

    block_secpar<S> seed;
    block128 iv;
    block_secpar<S>* forest = nullptr;
    block_secpar<S>* leaves = nullptr;
    unsigned char* hashed_leaves = nullptr;
    vole_block* u = nullptr;
    vole_block* v = nullptr;
    vole_block* q = nullptr;
    std::vector<uint8_t> commitment;
    std::vector<uint8_t> check;
    std::vector<uint8_t> delta_bytes;
};

template <typename F> double run_loop(size_t iterations, F&& f)
{
    f();
    const auto start = std::chrono::steady_clock::now();
    for (size_t i = 0; i < iterations; ++i)
        f();
    const auto stop = std::chrono::steady_clock::now();
    return std::chrono::duration<double>(stop - start).count();
}

template <typename P> void run_convert_to_vole_sender(profile_buffers<P>& buffers)
{
    using CP = typename P::CONSTS;
    using VC = typename P::CONSTS::VEC_COM;
    constexpr auto S = P::secpar_v;

    vole_block* v = buffers.v;
    uint8_t* commitment = buffers.commitment.data();
    block_secpar<S>* leaves_iter = buffers.leaves;
    vole_block correction[CP::VOLE_COL_BLOCKS];

    for (size_t i = 0; i < P::tau_v; ++i)
    {
        const unsigned int k = i < VC::NUM_MAX_K ? VC::MAX_K : VC::MIN_K;
        const auto tweak = (static_cast<typename P::vole_prg_t::tweak_t>(1) << 31) + i;
        if (!i)
            vole_sender<P>(k, leaves_iter, buffers.iv, tweak, nullptr, v, buffers.u);
        else
        {
            vole_sender<P>(k, leaves_iter, buffers.iv, tweak, buffers.u, v, correction);
            std::memcpy(commitment, correction, CP::VOLE_ROWS / 8);
            commitment += CP::VOLE_ROWS / 8;
        }

        leaves_iter += static_cast<size_t>(1) << k;
        v += CP::VOLE_COL_BLOCKS * k;
    }

    if constexpr (P::zero_bits_in_delta_v > 0)
        std::memset(v, 0, CP::VOLE_COL_BLOCKS * P::zero_bits_in_delta_v * sizeof(*v));

    consume_bytes(buffers.u, CP::VOLE_ROWS / 8);
    consume_bytes(buffers.v, P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(vole_block));
}

template <typename P> void run_convert_to_vole_receiver(profile_buffers<P>& buffers)
{
    using CP = typename P::CONSTS;
    using VC = typename P::CONSTS::VEC_COM;
    constexpr auto S = P::secpar_v;

    vole_block* q = buffers.q;
    const uint8_t* commitment = buffers.commitment.data();
    const uint8_t* delta_bytes = buffers.delta_bytes.data();
    block_secpar<S>* leaves_iter = buffers.leaves;
    vole_block correction[CP::VOLE_COL_BLOCKS];
    if (CP::VOLE_COL_BLOCKS * sizeof(vole_block) != CP::VOLE_ROWS / 8)
        correction[CP::VOLE_COL_BLOCKS - 1] = vole_block::set_zero();

    for (size_t i = 0; i < P::tau_v; ++i)
    {
        const unsigned int k = i < VC::NUM_MAX_K ? VC::MAX_K : VC::MIN_K;
        const auto tweak = (static_cast<typename P::vole_prg_t::tweak_t>(1) << 31) + i;
        if (!i)
            vole_receiver<P>(k, leaves_iter, buffers.iv, tweak, nullptr, q, delta_bytes);
        else
        {
            std::memcpy(correction, commitment, CP::VOLE_ROWS / 8);
            commitment += CP::VOLE_ROWS / 8;
            vole_receiver<P>(k, leaves_iter, buffers.iv, tweak, correction, q, delta_bytes);
        }

        leaves_iter += static_cast<size_t>(1) << k;
        q += CP::VOLE_COL_BLOCKS * k;
        delta_bytes += k;
    }

    if constexpr (P::zero_bits_in_delta_v > 0)
        std::memset(q, 0, CP::VOLE_COL_BLOCKS * P::zero_bits_in_delta_v * sizeof(*q));

    consume_bytes(buffers.q, P::secpar_bits * CP::VOLE_COL_BLOCKS * sizeof(vole_block));
}

template <typename P, bool receiver, bool max_k>
void run_single_small_vole(profile_buffers<P>& buffers)
{
    using CP = typename P::CONSTS;
    using VC = typename P::CONSTS::VEC_COM;

    constexpr unsigned int k = max_k ? VC::MAX_K : VC::MIN_K;
    const auto tweak = static_cast<typename P::vole_prg_t::tweak_t>(1) << 31;

    if constexpr (receiver)
    {
        vole_receiver<P>(k, buffers.leaves, buffers.iv, tweak, buffers.u, buffers.q,
                         buffers.delta_bytes.data());
        consume_bytes(buffers.q, k * CP::VOLE_COL_BLOCKS * sizeof(vole_block));
    }
    else
    {
        vole_block correction[CP::VOLE_COL_BLOCKS];
        vole_sender<P>(k, buffers.leaves, buffers.iv, tweak, buffers.u, buffers.v, correction);
        consume_bytes(buffers.v, k * CP::VOLE_COL_BLOCKS * sizeof(vole_block));
        consume_bytes(correction, CP::VOLE_ROWS / 8);
    }
}

template <typename P> int run_profile(const std::string& scheme, const std::string& operation,
                                      size_t iterations)
{
    using CP = typename P::CONSTS;
    using VC = typename CP::VEC_COM;
    profile_buffers<P> buffers(0xface57ULL);

    double seconds = 0.0;
    if (operation == "vole_commit")
    {
        seconds = run_loop(iterations,
                           [&]
                           {
                               vole_commit<P>(buffers.seed, buffers.iv, buffers.forest,
                                              buffers.hashed_leaves, buffers.u, buffers.v,
                                              buffers.commitment.data(), buffers.check.data());
                               consume_bytes(buffers.check.data(), buffers.check.size());
                           });
    }
    else if (operation == "vector_commit")
    {
        seconds = run_loop(iterations,
                           [&]
                           {
                               P::bavc_t::commit(buffers.seed, buffers.iv, buffers.forest,
                                                 buffers.leaves, buffers.hashed_leaves);
                               consume_bytes(buffers.hashed_leaves,
                                             P::bavc_t::COMMIT_LEAVES * P::leaf_hash_t::hash_len);
                           });
    }
    else if (operation == "hash_hashed_leaves")
    {
        P::bavc_t::commit(buffers.seed, buffers.iv, buffers.forest, buffers.leaves,
                          buffers.hashed_leaves);
        seconds = run_loop(iterations,
                           [&]
                           {
                               hash_hashed_leaves<P>(buffers.hashed_leaves, buffers.check.data());
                               consume_bytes(buffers.check.data(), buffers.check.size());
                           });
    }
    else if (operation == "convert_to_vole_sender")
    {
        seconds = run_loop(iterations, [&] { run_convert_to_vole_sender<P>(buffers); });
    }
    else if (operation == "convert_to_vole_receiver")
    {
        seconds = run_loop(iterations, [&] { run_convert_to_vole_receiver<P>(buffers); });
    }
    else if (operation == "small_vole_sender_min")
    {
        seconds = run_loop(iterations,
                           [&] { run_single_small_vole<P, false, false>(buffers); });
    }
    else if (operation == "small_vole_sender_max")
    {
        seconds = run_loop(iterations, [&] { run_single_small_vole<P, false, true>(buffers); });
    }
    else if (operation == "small_vole_receiver_min")
    {
        seconds = run_loop(iterations, [&] { run_single_small_vole<P, true, false>(buffers); });
    }
    else if (operation == "small_vole_receiver_max")
    {
        seconds = run_loop(iterations, [&] { run_single_small_vole<P, true, true>(buffers); });
    }
    else
    {
        std::cerr << "Unknown operation: " << operation << "\n";
        return 2;
    }

    const double ns_per_iter = seconds * 1e9 / static_cast<double>(iterations);
    std::cout << "{\n"
              << "  \"scheme\": \"" << scheme << "\",\n"
              << "  \"operation\": \"" << operation << "\",\n"
              << "  \"iterations\": " << iterations << ",\n"
              << "  \"seconds\": " << seconds << ",\n"
              << "  \"ns_per_iteration\": " << ns_per_iter << ",\n"
              << "  \"commit_leaves\": " << P::bavc_t::COMMIT_LEAVES << ",\n"
              << "  \"hash_len\": " << P::leaf_hash_t::hash_len << ",\n"
              << "  \"tau\": " << P::tau_v << ",\n"
              << "  \"delta_bits\": " << P::delta_bits_v << ",\n"
              << "  \"min_k\": " << VC::MIN_K << ",\n"
              << "  \"max_k\": " << VC::MAX_K << ",\n"
              << "  \"num_min_k\": " << VC::NUM_MIN_K << ",\n"
              << "  \"num_max_k\": " << VC::NUM_MAX_K << ",\n"
              << "  \"vole_rows\": " << CP::VOLE_ROWS << ",\n"
              << "  \"vole_col_blocks\": " << CP::VOLE_COL_BLOCKS << ",\n"
              << "  \"vole_width\": " << CP::VOLE_WIDTH << ",\n"
              << "  \"prg_vole_blocks\": " << CP::PRG_VOLE_BLOCKS << ",\n"
              << "  \"sink\": " << profile_sink << "\n"
              << "}\n";
    return 0;
}

int usage(const char* argv0)
{
    std::cerr << "Usage: " << argv0 << " <scheme> <operation> [iterations]\n"
              << "\nSchemes:\n"
              << "  faest_128_s faest_128_f faest_192_s faest_192_f faest_256_s faest_256_f\n"
              << "  faest_em_128_s faest_em_128_f faest_em_192_s faest_em_192_f\n"
              << "  faest_em_256_s faest_em_256_f\n"
              << "\nOperations:\n"
              << "  vole_commit\n"
              << "  vector_commit\n"
              << "  hash_hashed_leaves\n"
              << "  convert_to_vole_sender\n"
              << "  convert_to_vole_receiver\n"
              << "  small_vole_sender_min\n"
              << "  small_vole_sender_max\n"
              << "  small_vole_receiver_min\n"
              << "  small_vole_receiver_max\n";
    return 2;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc < 3 || argc > 4)
        return usage(argv[0]);

    const std::string scheme = argv[1];
    const std::string operation = argv[2];
    const size_t iterations = argc == 4 ? std::stoull(argv[3]) : 1000;
    if (iterations == 0)
        throw std::invalid_argument("iterations must be positive");

    if (scheme == "faest_128_s")
        return run_profile<v2::faest_128_s>(scheme, operation, iterations);
    if (scheme == "faest_128_f")
        return run_profile<v2::faest_128_f>(scheme, operation, iterations);
    if (scheme == "faest_192_s")
        return run_profile<v2::faest_192_s>(scheme, operation, iterations);
    if (scheme == "faest_192_f")
        return run_profile<v2::faest_192_f>(scheme, operation, iterations);
    if (scheme == "faest_256_s")
        return run_profile<v2::faest_256_s>(scheme, operation, iterations);
    if (scheme == "faest_256_f")
        return run_profile<v2::faest_256_f>(scheme, operation, iterations);
    if (scheme == "faest_em_128_s")
        return run_profile<v2::faest_em_128_s>(scheme, operation, iterations);
    if (scheme == "faest_em_128_f")
        return run_profile<v2::faest_em_128_f>(scheme, operation, iterations);
    if (scheme == "faest_em_192_s")
        return run_profile<v2::faest_em_192_s>(scheme, operation, iterations);
    if (scheme == "faest_em_192_f")
        return run_profile<v2::faest_em_192_f>(scheme, operation, iterations);
    if (scheme == "faest_em_256_s")
        return run_profile<v2::faest_em_256_s>(scheme, operation, iterations);
    if (scheme == "faest_em_256_f")
        return run_profile<v2::faest_em_256_f>(scheme, operation, iterations);

    std::cerr << "Unknown scheme: " << scheme << "\n";
    return usage(argv[0]);
}
