#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <cstring>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <chrono>

constexpr size_t OUTPUT_SIZE = 128;
constexpr size_t SALT_LENGTH = 16;
constexpr size_t MIN_MEMORY_MB = 1;     // Minimum memory size in MB
constexpr size_t MAX_MEMORY_MB = 512;   // Maximum memory size in MB
constexpr size_t MIN_ITERATIONS = 1;
constexpr size_t MAX_ITERATIONS = 100;
constexpr size_t MIN_THREADS = 1;

struct HashState {
    uint8_t state[OUTPUT_SIZE];
    HashState() { std::memset(state, 0, OUTPUT_SIZE); }
};

std::vector<uint8_t> generateSalt(size_t length) {
    std::vector<uint8_t> salt(length);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint8_t> dist(0, 255);
    for (size_t i = 0; i < length; ++i) salt[i] = dist(gen);
    return salt;
}

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    for (uint8_t byte : bytes) oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    return oss.str();
}

std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        bytes.push_back(std::stoi(hex.substr(i, 2), nullptr, 16));
    }
    return bytes;
}

void processBlock(HashState& state, const std::vector<uint8_t>& block) {
    for (size_t i = 0; i < block.size(); ++i) {
        size_t index = i % OUTPUT_SIZE;
        state.state[index] ^= block[i];
        state.state[index] = (state.state[index] << 3) | (state.state[index] >> (8 - 3));
        state.state[index] = (state.state[index] + state.state[(index + 1) % OUTPUT_SIZE]) % 256;
        size_t swapIndex = (index * 7) % OUTPUT_SIZE;
        std::swap(state.state[index], state.state[swapIndex]);
    }
}

void processChunks(HashState& state, const std::vector<uint8_t>& data, size_t blockSize, size_t numThreads, size_t iterations) {
    std::mutex stateMutex;
    size_t chunkSize = data.size() / numThreads;

    auto worker = [&](size_t start, size_t end) {
        HashState localState;
        for (size_t iter = 0; iter < iterations; ++iter) {
            for (size_t i = start; i < end; i += blockSize) {
                std::vector<uint8_t> block(data.begin() + i, data.begin() + std::min(i + blockSize, end));
                processBlock(localState, block);
            }
        }

        std::lock_guard<std::mutex> lock(stateMutex);
        for (size_t i = 0; i < OUTPUT_SIZE; ++i) state.state[i] ^= localState.state[i];
    };

    std::vector<std::thread> threads;
    for (size_t i = 0; i < numThreads; ++i) {
        size_t start = i * chunkSize;
        size_t end = (i == numThreads - 1) ? data.size() : start + chunkSize;
        threads.emplace_back(worker, start, end);
    }
    for (auto& t : threads) t.join();
}

std::vector<uint8_t> doubleHash(const std::vector<uint8_t>& data, size_t blockSize, size_t numThreads, size_t iterations) {
    HashState state1, state2;
    processChunks(state1, data, blockSize, numThreads, iterations);
    processChunks(state2, std::vector<uint8_t>(state1.state, state1.state + OUTPUT_SIZE), blockSize, numThreads, iterations);
    return std::vector<uint8_t>(state2.state, state2.state + OUTPUT_SIZE);
}

std::string customHash(const std::string& password, size_t blockSize, size_t numThreads, size_t iterations, const std::string& pepper) {
    std::vector<uint8_t> salt = generateSalt(SALT_LENGTH);
    std::vector<uint8_t> data(password.begin(), password.end());
    data.insert(data.end(), salt.begin(), salt.end());
    data.insert(data.end(), pepper.begin(), pepper.end());

    std::vector<uint8_t> hash = doubleHash(data, blockSize, numThreads, iterations);
    std::string params = std::to_string(blockSize) + ":" + std::to_string(numThreads) + ":" + std::to_string(iterations);
    std::string encryptedParams = bytesToHex(std::vector<uint8_t>(params.begin(), params.end()));

    return bytesToHex(salt) + ":" + encryptedParams + ":" + bytesToHex(hash);
}

bool verifyPassword(const std::string& password, const std::string& hashString) {
    size_t pos1 = hashString.find(":");
    size_t pos2 = hashString.find(":", pos1 + 1);

    if (pos1 == std::string::npos || pos2 == std::string::npos) return false;

    std::vector<uint8_t> salt = hexToBytes(hashString.substr(0, pos1));
    std::string encryptedParams = hashString.substr(pos1 + 1, pos2 - pos1 - 1);
    std::vector<uint8_t> storedHash = hexToBytes(hashString.substr(pos2 + 1));

    std::vector<uint8_t> paramsBytes = hexToBytes(encryptedParams);
    std::string params(paramsBytes.begin(), paramsBytes.end());
    size_t blockSize, numThreads, iterations;
    std::stringstream ss(params);
    ss >> blockSize; ss.ignore();
    ss >> numThreads; ss.ignore();
    ss >> iterations;

    std::string pepper = "CustomPepper456";
    std::vector<uint8_t> data(password.begin(), password.end());
    data.insert(data.end(), salt.begin(), salt.end());
    data.insert(data.end(), pepper.begin(), pepper.end());

    std::vector<uint8_t> calculatedHash = doubleHash(data, blockSize, numThreads, iterations);
    return storedHash == calculatedHash;
}

int main() {
    std::string password;
    std::cout << "Enter password: ";
    std::getline(std::cin, password);

    size_t memoryMB, numThreads, iterations;

    // Get memory size
    while (true) {
        std::cout << "Enter memory size in MB (" << MIN_MEMORY_MB << " - " << MAX_MEMORY_MB << "): ";
        std::cin >> memoryMB;
        if (memoryMB >= MIN_MEMORY_MB && memoryMB <= MAX_MEMORY_MB) break;
        std::cout << "Invalid memory size. Please try again.\n";
    }

    // Get number of threads
    while (true) {
        std::cout << "Enter number of threads: ";
        std::cin >> numThreads;
        size_t maxThreads = std::thread::hardware_concurrency();
        if (numThreads >= MIN_THREADS && numThreads <= maxThreads) break;
        std::cout << "Invalid number of threads. Please try again.\n";
    }

    // Get iterations
    while (true) {
        std::cout << "Enter number of iterations (" << MIN_ITERATIONS << " - " << MAX_ITERATIONS << "): ";
        std::cin >> iterations;
        if (iterations >= MIN_ITERATIONS && iterations <= MAX_ITERATIONS) break;
        std::cout << "Invalid number of iterations. Please try again.\n";
    }

    // Calculate block size based on memory size
    size_t totalBytes = memoryMB * 1024 * 1024;
    size_t blockSize = totalBytes / numThreads;

    std::cout << "Calculated block size per thread: " << blockSize << " bytes\n";

    std::string pepper = "CustomPepper456";

    auto startHashing = std::chrono::high_resolution_clock::now();
    std::string hash = customHash(password, blockSize, numThreads, iterations, pepper);
    auto endHashing = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> hashDuration = endHashing - startHashing;
    std::cout << "Hash: " << hash << std::endl;
    std::cout << "Hashing Time: " << hashDuration.count() << " seconds\n";

    std::string checkPassword;
    std::cout << "Enter password to verify: ";
    std::cin.ignore();
    std::getline(std::cin, checkPassword);

    auto startVerification = std::chrono::high_resolution_clock::now();
    bool verificationResult = verifyPassword(checkPassword, hash);
    auto endVerification = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> verifyDuration = endVerification - startVerification;

    std::cout << "Verification: " << (verificationResult ? "Success" : "Failure") << std::endl;
    std::cout << "Verification Time: " << verifyDuration.count() << " seconds\n";

    return 0;
}
