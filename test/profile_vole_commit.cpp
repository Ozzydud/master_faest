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
                                                    check(CP::VOLE_COMMIT_CHECK_SIZE)
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
    }

    block_secpar<S> seed;
    block128 iv;
    block_secpar<S>* forest = nullptr;
    block_secpar<S>* leaves = nullptr;
    unsigned char* hashed_leaves = nullptr;
    vole_block* u = nullptr;
    vole_block* v = nullptr;
    std::vector<uint8_t> commitment;
    std::vector<uint8_t> check;
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

template <typename P> int run_profile(const std::string& scheme, const std::string& operation,
                                      size_t iterations)
{
    using CP = typename P::CONSTS;
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
              << "  \"vole_rows\": " << CP::VOLE_ROWS << ",\n"
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
              << "  hash_hashed_leaves\n";
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
