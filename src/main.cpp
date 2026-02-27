// C++ Text-to-Speech Starter - Backend Server
//
// This is a simple C++ HTTP server using the Crow microframework that provides
// a text-to-speech API endpoint powered by Deepgram's Text-to-Speech service.
// It's designed to be easily modified and extended for your own projects.
//
// Key Features:
// - Contract-compliant API endpoint: POST /api/text-to-speech
// - Accepts text in body and model as query parameter
// - Returns binary audio data (audio/mpeg)
// - JWT session auth for API protection
// - CORS enabled for frontend communication
// - Pure API server (frontend served separately)

#include <crow.h>
#include <nlohmann/json.hpp>
#include <toml++/toml.hpp>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using json = nlohmann::json;

// ============================================================================
// CONFIGURATION - Customize these values for your needs
// ============================================================================

// DefaultModel is the default text-to-speech model to use when none is specified.
// Options: "aura-2-thalia-en", "aura-2-theia-en", "aura-2-andromeda-en", etc.
// See: https://developers.deepgram.com/docs/text-to-speech-models
static const std::string DEFAULT_MODEL = "aura-2-thalia-en";

// JWT token expiry duration in seconds (1 hour).
static const int JWT_EXPIRY_SECONDS = 3600;

// ============================================================================
// GLOBAL STATE
// ============================================================================

static std::string g_api_key;
static std::string g_session_secret;

// ============================================================================
// HELPER FUNCTIONS - Base64url encoding, hex generation, CORS headers
// ============================================================================

// base64url_encode encodes raw bytes into base64url (no padding) as required by JWT.
static std::string base64url_encode(const std::string& input) {
    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string encoded;
    const unsigned char* data = reinterpret_cast<const unsigned char*>(input.data());
    size_t len = input.size();

    for (size_t i = 0; i < len; i += 3) {
        unsigned int n = static_cast<unsigned int>(data[i]) << 16;
        if (i + 1 < len) n |= static_cast<unsigned int>(data[i + 1]) << 8;
        if (i + 2 < len) n |= static_cast<unsigned int>(data[i + 2]);

        encoded += table[(n >> 18) & 0x3F];
        encoded += table[(n >> 12) & 0x3F];
        if (i + 1 < len) encoded += table[(n >> 6) & 0x3F];
        if (i + 2 < len) encoded += table[n & 0x3F];
    }

    // Convert to URL-safe: replace + with -, / with _, strip padding
    for (auto& c : encoded) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }

    return encoded;
}

// base64url_decode decodes a base64url (no padding) string back to raw bytes.
static std::string base64url_decode(const std::string& input) {
    // Convert from URL-safe back to standard base64
    std::string b64 = input;
    for (auto& c : b64) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    // Add padding
    while (b64.size() % 4 != 0) b64 += '=';

    static const int lookup[] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };

    std::string decoded;
    int val = 0, bits = -8;
    for (unsigned char c : b64) {
        if (c == '=') break;
        if (c >= 128 || lookup[c] == -1) continue;
        val = (val << 6) | lookup[c];
        bits += 6;
        if (bits >= 0) {
            decoded += static_cast<char>((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return decoded;
}

// generate_random_hex produces a random hex string of the given byte length.
static std::string generate_random_hex(int n) {
    std::vector<unsigned char> buf(n);
    RAND_bytes(buf.data(), n);
    std::ostringstream oss;
    for (auto b : buf) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

// hmac_sha256 computes an HMAC-SHA256 signature over data using the given key.
static std::string hmac_sha256(const std::string& key, const std::string& data) {
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_len = 0;

    HMAC(EVP_sha256(),
         key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(),
         result, &result_len);

    return std::string(reinterpret_cast<char*>(result), result_len);
}

// add_cors_headers sets standard CORS headers on the response.
static void add_cors_headers(crow::response& res) {
    res.add_header("Access-Control-Allow-Origin", "*");
    res.add_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.add_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

// ============================================================================
// JWT FUNCTIONS - Manual HS256 JWT implementation using OpenSSL HMAC
// ============================================================================

// create_jwt signs a new JWT with the configured session secret.
static std::string create_jwt() {
    auto now = std::time(nullptr);
    auto exp = now + JWT_EXPIRY_SECONDS;

    // Header
    json header = {{"alg", "HS256"}, {"typ", "JWT"}};
    std::string header_enc = base64url_encode(header.dump());

    // Payload
    json payload = {{"iat", now}, {"exp", exp}};
    std::string payload_enc = base64url_encode(payload.dump());

    // Signature
    std::string signing_input = header_enc + "." + payload_enc;
    std::string sig = hmac_sha256(g_session_secret, signing_input);
    std::string sig_enc = base64url_encode(sig);

    return signing_input + "." + sig_enc;
}

// verify_jwt validates a JWT token string and returns true if valid.
// Sets error_message with a reason on failure.
static bool verify_jwt(const std::string& token, std::string& error_message) {
    // Split into parts
    auto first_dot = token.find('.');
    if (first_dot == std::string::npos) {
        error_message = "Invalid token format";
        return false;
    }
    auto second_dot = token.find('.', first_dot + 1);
    if (second_dot == std::string::npos) {
        error_message = "Invalid token format";
        return false;
    }

    std::string header_payload = token.substr(0, second_dot);
    std::string signature = token.substr(second_dot + 1);

    // Verify signature
    std::string expected_sig = hmac_sha256(g_session_secret, header_payload);
    std::string expected_sig_enc = base64url_encode(expected_sig);

    if (signature != expected_sig_enc) {
        error_message = "Invalid session token";
        return false;
    }

    // Decode payload and check expiry
    std::string payload_enc = token.substr(first_dot + 1, second_dot - first_dot - 1);
    std::string payload_str = base64url_decode(payload_enc);
    try {
        json payload = json::parse(payload_str);
        if (payload.contains("exp")) {
            auto exp = payload["exp"].get<long long>();
            auto now = static_cast<long long>(std::time(nullptr));
            if (now > exp) {
                error_message = "Session expired, please refresh the page";
                return false;
            }
        }
    } catch (...) {
        error_message = "Invalid token payload";
        return false;
    }

    return true;
}

// ============================================================================
// ERROR RESPONSE HELPERS - Contract-compliant structured errors
// ============================================================================

// make_error_response builds a contract-compliant error JSON response.
static json make_error_response(const std::string& type, const std::string& code,
                                const std::string& message) {
    return json{
        {"error", {
            {"type", type},
            {"code", code},
            {"message", message},
            {"details", {{"originalError", message}}}
        }}
    };
}

// format_error_response builds a contract-compliant error response with auto-detection.
static json format_error_response(const std::string& message, int status_code,
                                  const std::string& error_code_hint = "") {
    std::string error_code = error_code_hint;
    if (error_code.empty()) {
        std::string msg_lower = message;
        std::transform(msg_lower.begin(), msg_lower.end(), msg_lower.begin(), ::tolower);

        if (status_code == 400) {
            if (msg_lower.find("empty") != std::string::npos) {
                error_code = "EMPTY_TEXT";
            } else if (msg_lower.find("model") != std::string::npos) {
                error_code = "MODEL_NOT_FOUND";
            } else if (msg_lower.find("long") != std::string::npos ||
                       msg_lower.find("limit") != std::string::npos ||
                       msg_lower.find("exceed") != std::string::npos) {
                error_code = "TEXT_TOO_LONG";
            } else {
                error_code = "INVALID_TEXT";
            }
        } else {
            error_code = "INVALID_TEXT";
        }
    }

    std::string error_type = (status_code == 400) ? "ValidationError" : "GenerationError";
    return make_error_response(error_type, error_code, message);
}

// ============================================================================
// API KEY LOADING - Load Deepgram API key from environment
// ============================================================================

// load_env_file reads a .env file and sets environment variables.
static void load_env_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return;

    std::string line;
    while (std::getline(file, line)) {
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') continue;

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = line.substr(0, eq);
        std::string value = line.substr(eq + 1);

        // Trim whitespace
        while (!key.empty() && key.back() == ' ') key.pop_back();
        while (!value.empty() && value.front() == ' ') value.erase(value.begin());

        // Remove surrounding quotes from value
        if (value.size() >= 2 &&
            ((value.front() == '"' && value.back() == '"') ||
             (value.front() == '\'' && value.back() == '\''))) {
            value = value.substr(1, value.size() - 2);
        }

        setenv(key.c_str(), value.c_str(), 0); // 0 = don't overwrite existing
    }
}

// load_api_key reads the Deepgram API key from environment variables.
// Exits with a helpful error message if not found.
static std::string load_api_key() {
    const char* key = std::getenv("DEEPGRAM_API_KEY");
    if (!key || std::string(key).empty()) {
        std::cerr << "\nERROR: Deepgram API key not found!\n" << std::endl;
        std::cerr << "Please set your API key using one of these methods:\n" << std::endl;
        std::cerr << "1. Create a .env file (recommended):" << std::endl;
        std::cerr << "   DEEPGRAM_API_KEY=your_api_key_here\n" << std::endl;
        std::cerr << "2. Environment variable:" << std::endl;
        std::cerr << "   export DEEPGRAM_API_KEY=your_api_key_here\n" << std::endl;
        std::cerr << "Get your API key at: https://console.deepgram.com\n" << std::endl;
        std::exit(1);
    }
    return std::string(key);
}

// ============================================================================
// SESSION AUTH - Initialize session secret
// ============================================================================

// init_session_secret loads SESSION_SECRET from env or generates a random one.
static void init_session_secret() {
    const char* secret = std::getenv("SESSION_SECRET");
    if (secret && std::string(secret).length() > 0) {
        g_session_secret = std::string(secret);
    } else {
        g_session_secret = generate_random_hex(32);
    }
}

// ============================================================================
// DEEPGRAM API - Direct HTTP calls to the Deepgram TTS endpoint via libcurl
// ============================================================================

// writeCallback collects response data from libcurl into a string.
static size_t writeCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total = size * nmemb;
    auto* buffer = static_cast<std::string*>(userp);
    buffer->append(static_cast<char*>(contents), total);
    return total;
}

// generate_audio calls the Deepgram TTS API and returns the audio bytes.
// It sends a JSON body with the text and passes the model as a query parameter.
// On error, sets error_msg and returns an empty string.
static std::string generate_audio(const std::string& text, const std::string& model,
                                  std::string& error_msg, long& http_status) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        error_msg = "Failed to initialize HTTP client";
        http_status = 500;
        return "";
    }

    // Build URL with model query parameter
    std::string url = "https://api.deepgram.com/v1/speak?model=" + model;

    // Build JSON payload
    json payload = {{"text", text}};
    std::string body = payload.dump();

    // Set up headers
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, ("Authorization: Token " + g_api_key).c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");

    std::string response_data;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        error_msg = std::string("Failed to call Deepgram API: ") + curl_easy_strerror(res);
        http_status = 500;
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return "";
    }

    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (response_code < 200 || response_code >= 300) {
        error_msg = "Deepgram API error (status " + std::to_string(response_code) + "): " + response_data;
        http_status = response_code;
        return "";
    }

    http_status = 200;
    return response_data;
}

// ============================================================================
// AUTH MIDDLEWARE - JWT Bearer token validation
// ============================================================================

// extract_bearer_token extracts the token from an "Authorization: Bearer <token>" header.
// Returns empty string if header is missing or malformed.
static std::string extract_bearer_token(const crow::request& req) {
    auto it = req.headers.find("Authorization");
    if (it == req.headers.end()) return "";

    const std::string& header = it->second;
    const std::string prefix = "Bearer ";
    if (header.size() <= prefix.size() ||
        header.substr(0, prefix.size()) != prefix) {
        return "";
    }
    return header.substr(prefix.size());
}

// ============================================================================
// ROUTE HANDLERS - API endpoint implementations
// ============================================================================

// handle_session issues a signed JWT for session authentication.
// GET /api/session
static crow::response handle_session() {
    std::string token = create_jwt();

    crow::response res(200);
    res.set_header("Content-Type", "application/json");
    add_cors_headers(res);
    res.body = json{{"token", token}}.dump();
    return res;
}

// handle_text_to_speech converts text to speech audio via the Deepgram API.
// POST /api/text-to-speech?model=aura-2-thalia-en
//
// Accepts JSON body: {"text": "Hello world"}
// Returns binary audio data (audio/mpeg) on success.
static crow::response handle_text_to_speech(const crow::request& req) {
    crow::response res;
    add_cors_headers(res);

    // Auth check
    std::string token = extract_bearer_token(req);
    if (token.empty()) {
        res.code = 401;
        res.set_header("Content-Type", "application/json");
        res.body = make_error_response(
            "AuthenticationError", "MISSING_TOKEN",
            "Authorization header with Bearer token is required"
        ).dump();
        return res;
    }

    std::string jwt_error;
    if (!verify_jwt(token, jwt_error)) {
        res.code = 401;
        res.set_header("Content-Type", "application/json");
        res.body = make_error_response(
            "AuthenticationError", "INVALID_TOKEN", jwt_error
        ).dump();
        return res;
    }

    // Parse model from query parameter
    auto model_param = req.url_params.get("model");
    std::string model = model_param ? std::string(model_param) : DEFAULT_MODEL;

    // Parse JSON body
    json body;
    try {
        body = json::parse(req.body);
    } catch (...) {
        res.code = 400;
        res.set_header("Content-Type", "application/json");
        res.body = format_error_response("Invalid request body", 400, "INVALID_TEXT").dump();
        return res;
    }

    // Validate text field
    if (!body.contains("text") || !body["text"].is_string()) {
        res.code = 400;
        res.set_header("Content-Type", "application/json");
        res.body = format_error_response("Text parameter is required", 400, "EMPTY_TEXT").dump();
        return res;
    }

    std::string text = body["text"].get<std::string>();
    if (text.empty()) {
        res.code = 400;
        res.set_header("Content-Type", "application/json");
        res.body = format_error_response("Text parameter is required", 400, "EMPTY_TEXT").dump();
        return res;
    }

    // Check if text is only whitespace
    bool only_whitespace = true;
    for (char c : text) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            only_whitespace = false;
            break;
        }
    }
    if (only_whitespace) {
        res.code = 400;
        res.set_header("Content-Type", "application/json");
        res.body = format_error_response("Text must be a non-empty string", 400, "EMPTY_TEXT").dump();
        return res;
    }

    // Generate audio from text via Deepgram API
    std::string error_msg;
    long http_status = 0;
    std::string audio_data = generate_audio(text, model, error_msg, http_status);

    if (!error_msg.empty()) {
        CROW_LOG_ERROR << "Text-to-speech error: " << error_msg;

        std::string err_lower = error_msg;
        std::transform(err_lower.begin(), err_lower.end(), err_lower.begin(), ::tolower);

        int status_code = 500;
        std::string error_code;

        if (err_lower.find("model") != std::string::npos ||
            err_lower.find("not found") != std::string::npos) {
            status_code = 400;
            error_code = "MODEL_NOT_FOUND";
        } else if (err_lower.find("too long") != std::string::npos ||
                   err_lower.find("length") != std::string::npos ||
                   err_lower.find("limit") != std::string::npos ||
                   err_lower.find("exceed") != std::string::npos) {
            status_code = 400;
            error_code = "TEXT_TOO_LONG";
        } else if (err_lower.find("invalid") != std::string::npos ||
                   err_lower.find("malformed") != std::string::npos) {
            status_code = 400;
            error_code = "INVALID_TEXT";
        }

        res.code = status_code;
        res.set_header("Content-Type", "application/json");
        res.body = format_error_response(error_msg, status_code, error_code).dump();
        return res;
    }

    // Return binary audio data with proper content type
    res.code = 200;
    res.set_header("Content-Type", "audio/mpeg");
    res.body = audio_data;
    return res;
}

// handle_metadata returns project metadata from deepgram.toml.
// GET /api/metadata
static crow::response handle_metadata() {
    crow::response res;
    add_cors_headers(res);
    res.set_header("Content-Type", "application/json");

    try {
        auto config = toml::parse_file("deepgram.toml");
        auto meta = config["meta"];
        if (!meta) {
            res.code = 500;
            res.body = json{
                {"error", "INTERNAL_SERVER_ERROR"},
                {"message", "Missing [meta] section in deepgram.toml"}
            }.dump();
            return res;
        }

        // Convert TOML meta table to JSON
        json meta_json;
        auto* table = meta.as_table();
        if (table) {
            for (auto& [key, val] : *table) {
                if (val.is_string()) {
                    meta_json[std::string(key.str())] = std::string(val.as_string()->get());
                } else if (val.is_integer()) {
                    meta_json[std::string(key.str())] = val.as_integer()->get();
                } else if (val.is_boolean()) {
                    meta_json[std::string(key.str())] = val.as_boolean()->get();
                } else if (val.is_array()) {
                    json arr = json::array();
                    for (auto& elem : *val.as_array()) {
                        if (elem.is_string()) {
                            arr.push_back(std::string(elem.as_string()->get()));
                        }
                    }
                    meta_json[std::string(key.str())] = arr;
                }
            }
        }

        res.code = 200;
        res.body = meta_json.dump();
    } catch (const std::exception& e) {
        CROW_LOG_ERROR << "Error reading deepgram.toml: " << e.what();
        res.code = 500;
        res.body = json{
            {"error", "INTERNAL_SERVER_ERROR"},
            {"message", "Failed to read metadata from deepgram.toml"}
        }.dump();
    }

    return res;
}

// handle_health returns a simple health check response.
// GET /health
static crow::response handle_health() {
    crow::response res(200);
    res.set_header("Content-Type", "application/json");
    add_cors_headers(res);
    res.body = json{{"status", "ok"}}.dump();
    return res;
}

// ============================================================================
// SERVER START
// ============================================================================

int main() {
    // Load .env file (ignore error if not present)
    load_env_file(".env");

    // Load API key and initialize session
    g_api_key = load_api_key();
    init_session_secret();

    // Initialize libcurl globally
    curl_global_init(CURL_GLOBAL_DEFAULT);

    // Read port and host from environment
    const char* port_env = std::getenv("PORT");
    int port = port_env ? std::atoi(port_env) : 8081;

    const char* host_env = std::getenv("HOST");
    std::string host = host_env ? std::string(host_env) : "0.0.0.0";

    // Create Crow application
    crow::SimpleApp app;

    // CORS preflight handler for all routes
    CROW_ROUTE(app, "/api/session").methods(crow::HTTPMethod::OPTIONS)(
        [](const crow::request&) {
            crow::response res(204);
            add_cors_headers(res);
            return res;
        });

    CROW_ROUTE(app, "/api/text-to-speech").methods(crow::HTTPMethod::OPTIONS)(
        [](const crow::request&) {
            crow::response res(204);
            add_cors_headers(res);
            return res;
        });

    CROW_ROUTE(app, "/api/metadata").methods(crow::HTTPMethod::OPTIONS)(
        [](const crow::request&) {
            crow::response res(204);
            add_cors_headers(res);
            return res;
        });

    CROW_ROUTE(app, "/health").methods(crow::HTTPMethod::OPTIONS)(
        [](const crow::request&) {
            crow::response res(204);
            add_cors_headers(res);
            return res;
        });

    // Route: GET /api/session - Issue JWT
    CROW_ROUTE(app, "/api/session").methods(crow::HTTPMethod::GET)(
        [](const crow::request&) {
            return handle_session();
        });

    // Route: POST /api/text-to-speech - Convert text to audio (auth required)
    CROW_ROUTE(app, "/api/text-to-speech").methods(crow::HTTPMethod::POST)(
        [](const crow::request& req) {
            return handle_text_to_speech(req);
        });

    // Route: GET /api/metadata - Return [meta] from deepgram.toml
    CROW_ROUTE(app, "/api/metadata").methods(crow::HTTPMethod::GET)(
        [](const crow::request&) {
            return handle_metadata();
        });

    // Route: GET /health - Health check
    CROW_ROUTE(app, "/health").methods(crow::HTTPMethod::GET)(
        [](const crow::request&) {
            return handle_health();
        });

    // Print startup banner
    std::cout << std::endl;
    std::cout << std::string(70, '=') << std::endl;
    std::cout << "Backend API running at http://localhost:" << port << std::endl;
    std::cout << "GET  /api/session" << std::endl;
    std::cout << "POST /api/text-to-speech (auth required)" << std::endl;
    std::cout << "GET  /api/metadata" << std::endl;
    std::cout << "GET  /health" << std::endl;
    std::cout << std::string(70, '=') << std::endl;
    std::cout << std::endl;

    // Start the server
    app.bindaddr(host).port(port).multithreaded().run();

    // Cleanup libcurl
    curl_global_cleanup();

    return 0;
}
