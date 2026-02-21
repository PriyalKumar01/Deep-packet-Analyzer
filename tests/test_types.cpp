// =============================================================================
// test_types.cpp — CTest unit tests for sniToAppType() and FiveTuple helpers
//
// Tests the application classification logic in types.cpp.
// Run: ctest --output-on-failure
// =============================================================================

#include "types.h"
#include <cassert>
#include <iostream>
#include <string>

using namespace DPI;

// =============================================================================
// sniToAppType() tests
// =============================================================================

static void test_apptype_youtube() {
    assert(sniToAppType("www.youtube.com")  == AppType::YOUTUBE);
    assert(sniToAppType("ytimg.com")        == AppType::YOUTUBE);
    assert(sniToAppType("youtu.be")         == AppType::YOUTUBE);
    std::cout << "[PASS] test_apptype_youtube\n";
}

static void test_apptype_facebook() {
    assert(sniToAppType("www.facebook.com") == AppType::FACEBOOK);
    assert(sniToAppType("static.xx.fbcdn.net") == AppType::FACEBOOK);
    assert(sniToAppType("fb.com")           == AppType::FACEBOOK);
    std::cout << "[PASS] test_apptype_facebook\n";
}

static void test_apptype_instagram() {
    assert(sniToAppType("www.instagram.com")    == AppType::INSTAGRAM);
    assert(sniToAppType("scontent.cdninstagram.com") == AppType::INSTAGRAM);
    std::cout << "[PASS] test_apptype_instagram\n";
}

static void test_apptype_google() {
    assert(sniToAppType("www.google.com")  == AppType::GOOGLE);
    assert(sniToAppType("apis.google.com") == AppType::GOOGLE);
    assert(sniToAppType("gstatic.com")     == AppType::GOOGLE);
    std::cout << "[PASS] test_apptype_google\n";
}

static void test_apptype_netflix() {
    assert(sniToAppType("www.netflix.com")           == AppType::NETFLIX);
    assert(sniToAppType("assets.nflxvideo.net")      == AppType::NETFLIX);
    std::cout << "[PASS] test_apptype_netflix\n";
}

static void test_apptype_twitter() {
    assert(sniToAppType("twitter.com")   == AppType::TWITTER);
    assert(sniToAppType("x.com")         == AppType::TWITTER);
    assert(sniToAppType("abs.twimg.com") == AppType::TWITTER);
    std::cout << "[PASS] test_apptype_twitter\n";
}

static void test_apptype_amazon() {
    assert(sniToAppType("www.amazon.com")   == AppType::AMAZON);
    assert(sniToAppType("s3.amazonaws.com") == AppType::AMAZON);
    std::cout << "[PASS] test_apptype_amazon\n";
}

static void test_apptype_microsoft() {
    assert(sniToAppType("login.microsoft.com") == AppType::MICROSOFT);
    assert(sniToAppType("outlook.com")         == AppType::MICROSOFT);
    assert(sniToAppType("www.bing.com")        == AppType::MICROSOFT);
    std::cout << "[PASS] test_apptype_microsoft\n";
}

static void test_apptype_apple() {
    assert(sniToAppType("www.apple.com")  == AppType::APPLE);
    assert(sniToAppType("icloud.com")     == AppType::APPLE);
    assert(sniToAppType("itunes.apple.com") == AppType::APPLE);
    std::cout << "[PASS] test_apptype_apple\n";
}

static void test_apptype_discord() {
    assert(sniToAppType("discord.com")        == AppType::DISCORD);
    assert(sniToAppType("cdn.discordapp.com") == AppType::DISCORD);
    std::cout << "[PASS] test_apptype_discord\n";
}

static void test_apptype_github() {
    assert(sniToAppType("github.com")                == AppType::GITHUB);
    assert(sniToAppType("raw.githubusercontent.com") == AppType::GITHUB);
    std::cout << "[PASS] test_apptype_github\n";
}

static void test_apptype_tiktok() {
    assert(sniToAppType("www.tiktok.com")   == AppType::TIKTOK);
    assert(sniToAppType("musical.ly")        == AppType::TIKTOK);
    assert(sniToAppType("bytedance.com")     == AppType::TIKTOK);
    std::cout << "[PASS] test_apptype_tiktok\n";
}

static void test_apptype_zoom() {
    assert(sniToAppType("zoom.us")           == AppType::ZOOM);
    assert(sniToAppType("us02web.zoom.us")   == AppType::ZOOM);
    std::cout << "[PASS] test_apptype_zoom\n";
}

static void test_apptype_spotify() {
    assert(sniToAppType("open.spotify.com") == AppType::SPOTIFY);
    assert(sniToAppType("scdn.co")           == AppType::SPOTIFY);
    std::cout << "[PASS] test_apptype_spotify\n";
}

static void test_apptype_unknown_sni() {
    // Completely unknown domains should still be classified as HTTPS
    // (because they have an SNI but don't match any pattern)
    AppType t = sniToAppType("some.obscure.domain.example");
    assert(t == AppType::HTTPS);
    std::cout << "[PASS] test_apptype_unknown_sni (returns HTTPS)\n";
}

static void test_apptype_empty_sni() {
    assert(sniToAppType("") == AppType::UNKNOWN);
    std::cout << "[PASS] test_apptype_empty_sni\n";
}

static void test_apptype_case_insensitive() {
    // sniToAppType must be case-insensitive
    assert(sniToAppType("WWW.YOUTUBE.COM") == AppType::YOUTUBE);
    assert(sniToAppType("GitHub.COM")      == AppType::GITHUB);
    std::cout << "[PASS] test_apptype_case_insensitive\n";
}

// =============================================================================
// FiveTuple tests
// =============================================================================

static void test_fivetuple_equality() {
    FiveTuple a;
    a.src_ip   = 0xC0A80101;  // 192.168.1.1
    a.dst_ip   = 0x08080808;  // 8.8.8.8
    a.src_port = 54321;
    a.dst_port = 443;
    a.protocol = 6;            // TCP

    FiveTuple b = a;
    assert(a == b);
    std::cout << "[PASS] test_fivetuple_equality\n";
}

static void test_fivetuple_inequality() {
    FiveTuple a;
    a.src_ip = 0xC0A80101; a.dst_ip = 0x08080808;
    a.src_port = 54321;    a.dst_port = 443; a.protocol = 6;

    FiveTuple b = a;
    b.src_port = 54322;   // Different port
    assert(!(a == b));
    std::cout << "[PASS] test_fivetuple_inequality\n";
}

static void test_fivetuple_reverse() {
    FiveTuple original;
    original.src_ip   = 0xC0A80101;
    original.dst_ip   = 0x08080808;
    original.src_port = 54321;
    original.dst_port = 443;
    original.protocol = 6;

    FiveTuple rev = original.reverse();

    assert(rev.src_ip   == original.dst_ip);
    assert(rev.dst_ip   == original.src_ip);
    assert(rev.src_port == original.dst_port);
    assert(rev.dst_port == original.src_port);
    assert(rev.protocol == original.protocol);
    std::cout << "[PASS] test_fivetuple_reverse\n";
}

static void test_fivetuple_hash_consistency() {
    // Same tuple must always produce the same hash
    FiveTuple t;
    t.src_ip = 0xC0A80101; t.dst_ip = 0x08080808;
    t.src_port = 12345;    t.dst_port = 443; t.protocol = 6;

    std::hash<FiveTuple> hasher;
    size_t h1 = hasher(t);
    size_t h2 = hasher(t);
    assert(h1 == h2);
    std::cout << "[PASS] test_fivetuple_hash_consistency\n";
}

// =============================================================================
// appTypeToString() tests
// =============================================================================

static void test_apptype_to_string() {
    assert(appTypeToString(AppType::YOUTUBE)  == "YouTube");
    assert(appTypeToString(AppType::FACEBOOK) == "Facebook");
    assert(appTypeToString(AppType::UNKNOWN)  == "Unknown");
    assert(appTypeToString(AppType::HTTP)     == "HTTP");
    assert(appTypeToString(AppType::DNS)      == "DNS");
    std::cout << "[PASS] test_apptype_to_string\n";
}

// =============================================================================
// MAIN
// =============================================================================
int main() {
    std::cout << "\n=============================================\n";
    std::cout <<   "  DPI Engine — Types & Classification Tests\n";
    std::cout <<   "=============================================\n\n";

    std::cout << "-- App Classification (sniToAppType) Tests --\n";
    test_apptype_youtube();
    test_apptype_facebook();
    test_apptype_instagram();
    test_apptype_google();
    test_apptype_netflix();
    test_apptype_twitter();
    test_apptype_amazon();
    test_apptype_microsoft();
    test_apptype_apple();
    test_apptype_discord();
    test_apptype_github();
    test_apptype_tiktok();
    test_apptype_zoom();
    test_apptype_spotify();
    test_apptype_unknown_sni();
    test_apptype_empty_sni();
    test_apptype_case_insensitive();

    std::cout << "\n-- FiveTuple Tests --\n";
    test_fivetuple_equality();
    test_fivetuple_inequality();
    test_fivetuple_reverse();
    test_fivetuple_hash_consistency();

    std::cout << "\n-- AppType String Conversion Tests --\n";
    test_apptype_to_string();

    std::cout << "\n=============================================\n";
    std::cout <<   "  ALL TESTS PASSED ✓\n";
    std::cout <<   "=============================================\n\n";

    return 0;
}
