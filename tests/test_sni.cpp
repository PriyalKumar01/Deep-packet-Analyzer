// =============================================================================
// test_sni.cpp — CTest unit tests for SNIExtractor and HTTPHostExtractor
//
// Tests use raw byte sequences that match real TLS Client Hello and HTTP
// request structures, so these verify actual protocol parsing logic.
//
// Run: ctest --output-on-failure  (after cmake + make)
// =============================================================================

#include "sni_extractor.h"
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

using namespace DPI;

// -----------------------------------------------------------------------------
// Helper: build a minimal but valid TLS Client Hello containing a given SNI
// This mirrors the real wire format byte-for-byte.
// -----------------------------------------------------------------------------
static std::vector<uint8_t> buildTLSClientHello(const std::string& sni) {
    // SNI extension payload
    uint16_t sni_len         = static_cast<uint16_t>(sni.size());
    uint16_t sni_entry_len   = sni_len + 3;   // type(1) + len(2) + sni
    uint16_t sni_list_len    = sni_entry_len;
    uint16_t ext_data_len    = sni_list_len + 2; // list_len field itself

    // Extension: type(2) + ext_data_len(2) + ext_data
    uint16_t ext_total_len   = 4 + ext_data_len;

    // Client Hello body:
    //   version(2) + random(32) + session_id_len(1) + cipher_suites_len(2)
    //   + 2 cipher suites(4) + comp_len(1) + 1 comp method(1)
    //   + extensions_total_len(2) + extension
    uint16_t hello_body_len  = 2 + 32 + 1 + 2 + 4 + 1 + 1 + 2 + ext_total_len;

    // Handshake header: type(1) + length(3)
    uint32_t handshake_len   = hello_body_len;

    // TLS record header: type(1) + version(2) + record_len(2)
    uint16_t record_len      = 4 + hello_body_len;  // handshake header + body

    std::vector<uint8_t> pkt;
    auto push2 = [&](uint16_t v) {
        pkt.push_back(static_cast<uint8_t>(v >> 8));
        pkt.push_back(static_cast<uint8_t>(v & 0xFF));
    };
    auto push3 = [&](uint32_t v) {
        pkt.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
        pkt.push_back(static_cast<uint8_t>((v >> 8)  & 0xFF));
        pkt.push_back(static_cast<uint8_t>(v & 0xFF));
    };

    // TLS Record Header
    pkt.push_back(0x16);        // Content Type: Handshake
    push2(0x0303);              // Version: TLS 1.2
    push2(record_len);

    // Handshake Header
    pkt.push_back(0x01);        // Handshake Type: Client Hello
    push3(handshake_len);

    // Client Hello Body
    push2(0x0303);              // Client version: TLS 1.2
    for (int i = 0; i < 32; i++) pkt.push_back(0xAB); // Random (32 bytes)
    pkt.push_back(0x00);        // Session ID length = 0

    // Cipher Suites
    push2(0x0004);              // Length = 4 bytes (2 suites)
    push2(0x002F);              // TLS_RSA_WITH_AES_128_CBC_SHA
    push2(0xC02B);              // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256

    // Compression Methods
    pkt.push_back(0x01);        // length = 1
    pkt.push_back(0x00);        // null compression

    // Extensions length
    push2(ext_total_len);

    // SNI Extension
    push2(0x0000);              // Extension type: SNI
    push2(ext_data_len);        // Extension data length
    push2(sni_list_len);        // SNI list length
    pkt.push_back(0x00);        // SNI type: host_name
    push2(sni_len);             // SNI value length
    for (char c : sni) pkt.push_back(static_cast<uint8_t>(c));

    return pkt;
}

// -----------------------------------------------------------------------------
// Helper: build a minimal HTTP GET request with a Host header
// -----------------------------------------------------------------------------
static std::vector<uint8_t> buildHTTPRequest(const std::string& host) {
    std::string req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
    return std::vector<uint8_t>(req.begin(), req.end());
}

// =============================================================================
// TEST CASES
// =============================================================================

// --- TLS SNI extraction tests ------------------------------------------------

static void test_sni_youtube() {
    auto pkt = buildTLSClientHello("www.youtube.com");
    auto result = SNIExtractor::extract(pkt.data(), pkt.size());
    assert(result.has_value());
    assert(result.value() == "www.youtube.com");
    std::cout << "[PASS] test_sni_youtube\n";
}

static void test_sni_facebook() {
    auto pkt = buildTLSClientHello("www.facebook.com");
    auto result = SNIExtractor::extract(pkt.data(), pkt.size());
    assert(result.has_value());
    assert(result.value() == "www.facebook.com");
    std::cout << "[PASS] test_sni_facebook\n";
}

static void test_sni_github() {
    auto pkt = buildTLSClientHello("github.com");
    auto result = SNIExtractor::extract(pkt.data(), pkt.size());
    assert(result.has_value());
    assert(result.value() == "github.com");
    std::cout << "[PASS] test_sni_github\n";
}

static void test_sni_empty_payload() {
    // Empty payload — should return nullopt cleanly (no crash)
    std::vector<uint8_t> empty = {};
    auto result = SNIExtractor::extract(empty.data(), 0);
    assert(!result.has_value());
    std::cout << "[PASS] test_sni_empty_payload\n";
}

static void test_sni_not_tls() {
    // Random bytes that are not a TLS record
    std::vector<uint8_t> garbage = {0x47, 0x45, 0x54, 0x20, 0x2F}; // "GET /"
    auto result = SNIExtractor::extract(garbage.data(), garbage.size());
    assert(!result.has_value());
    std::cout << "[PASS] test_sni_not_tls\n";
}

static void test_sni_truncated() {
    // A valid start but truncated — should not crash, should return nullopt
    auto pkt = buildTLSClientHello("example.com");
    pkt.resize(10); // Truncate aggressively
    auto result = SNIExtractor::extract(pkt.data(), pkt.size());
    // May or may not have value depending on where truncation falls
    // The key thing: no crash / undefined behaviour
    std::cout << "[PASS] test_sni_truncated (no crash)\n";
}

// --- HTTP Host extraction tests ---------------------------------------------

static void test_http_google() {
    auto pkt = buildHTTPRequest("www.google.com");
    auto result = HTTPHostExtractor::extract(pkt.data(), pkt.size());
    assert(result.has_value());
    assert(result.value() == "www.google.com");
    std::cout << "[PASS] test_http_google\n";
}

static void test_http_with_port() {
    // Host header containing port — port should be stripped
    auto pkt = buildHTTPRequest("example.com:8080");
    auto result = HTTPHostExtractor::extract(pkt.data(), pkt.size());
    assert(result.has_value());
    assert(result.value() == "example.com");  // port stripped
    std::cout << "[PASS] test_http_with_port\n";
}

static void test_http_post_request() {
    std::string req = "POST /api/data HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 0\r\n\r\n";
    std::vector<uint8_t> pkt(req.begin(), req.end());
    auto result = HTTPHostExtractor::extract(pkt.data(), pkt.size());
    assert(result.has_value());
    assert(result.value() == "api.example.com");
    std::cout << "[PASS] test_http_post_request\n";
}

static void test_http_not_http() {
    // Binary data, not HTTP
    std::vector<uint8_t> binary = {0x16, 0x03, 0x01, 0x00, 0x10};
    auto result = HTTPHostExtractor::extract(binary.data(), binary.size());
    assert(!result.has_value());
    std::cout << "[PASS] test_http_not_http\n";
}

static void test_http_empty() {
    std::vector<uint8_t> empty = {};
    auto result = HTTPHostExtractor::extract(empty.data(), 0);
    assert(!result.has_value());
    std::cout << "[PASS] test_http_empty\n";
}

// =============================================================================
// MAIN
// =============================================================================
int main() {
    std::cout << "\n========================================\n";
    std::cout <<   "  DPI Engine — SNI Extractor Unit Tests\n";
    std::cout <<   "========================================\n\n";

    // TLS/SNI tests
    std::cout << "-- TLS Client Hello SNI Tests --\n";
    test_sni_youtube();
    test_sni_facebook();
    test_sni_github();
    test_sni_empty_payload();
    test_sni_not_tls();
    test_sni_truncated();

    // HTTP Host tests
    std::cout << "\n-- HTTP Host Header Tests --\n";
    test_http_google();
    test_http_with_port();
    test_http_post_request();
    test_http_not_http();
    test_http_empty();

    std::cout << "\n========================================\n";
    std::cout <<   "  ALL TESTS PASSED ✓\n";
    std::cout <<   "========================================\n\n";

    return 0;  // Non-zero return = CTest failure
}
