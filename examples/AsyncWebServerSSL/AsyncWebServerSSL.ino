/*
 * AsyncTCPSSL - AsyncWebServerSSL example
 *
 * ESP32 HTTPS server using ESPAsyncWebServer + AsyncTCPSSL.
 * Serves a simple page and a JSON API over TLS 1.2 on port 443.
 *
 * Generate your own self-signed cert/key:
 *   openssl req -x509 -newkey rsa:2048 -nodes \
 *     -keyout server.key -out server.pem -days 3650 \
 *     -subj "/CN=esp32.local"
 *
 * Test with:
 *   curl -k https://<ESP32_IP>/api
 *
 * Compile with:
 *   compiler.cpp.extra_flags=-DASYNC_TCP_SSL_ENABLED=1
 */

#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>

const char *SSID     = "YOUR_SSID";
const char *PASSWORD = "YOUR_PASSWORD";

// Replace with your own PEM cert and key
static const char SERVER_CERT[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
REPLACE_WITH_YOUR_CERT_PEM
-----END CERTIFICATE-----
)EOF";

static const char SERVER_KEY[] PROGMEM = R"EOF(
-----BEGIN RSA PRIVATE KEY-----
REPLACE_WITH_YOUR_KEY_PEM
-----END RSA PRIVATE KEY-----
)EOF";

AsyncWebServer server(443);
AsyncWebServer httpserver(80);

const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AsyncWebServerSSL</title>
  <style>
    body { font-family: sans-serif; text-align: center; padding: 2em; }
    h1 { color: #2c3e50; }
    a { color: #2980b9; }
  </style>
</head>
<body>
  <h1>AsyncWebServerSSL</h1>
  <p>HTTPS is working!</p>
  <p><a href="/api">/api</a> - JSON endpoint</p>
</body>
</html>
)rawliteral";

void setup() {
  Serial.begin(115200);
  delay(500);

  WiFi.begin(SSID, PASSWORD);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.printf("\nIP: %s\n", WiFi.localIP().toString().c_str());

  // Serve a simple HTML page
  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(200, "text/html", index_html);
  });

  // JSON API endpoint
  server.on("/api", HTTP_GET, [](AsyncWebServerRequest *request) {
    AsyncJsonResponse *response = new AsyncJsonResponse();
    JsonObject root = response->getRoot();
    root["status"] = "ok";
    root["heap"] = ESP.getFreeHeap();
    root["uptime"] = millis() / 1000;
    response->setLength();
    request->send(response);
  });

  // Start HTTPS server
  server.beginSecure(SERVER_CERT, SERVER_KEY, NULL);
  Serial.printf("[Server] HTTPS on port 443\n");
  Serial.printf("Test: curl -k https://%s/api\n",
                WiFi.localIP().toString().c_str());

  // Optional: HTTP-to-HTTPS redirect
  httpserver.onNotFound([](AsyncWebServerRequest *request) {
    request->redirect("https://" + WiFi.localIP().toString() + request->url());
  });
  httpserver.begin();
  Serial.printf("[Server] HTTP redirect on port 80\n");
}

void loop() {
  delay(10000);
}
