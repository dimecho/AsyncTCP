/*
 * AsyncTCP - WebServerSSL example
 *
 * ESP32 HTTPS server using AsyncTCP + AsyncTCPTLS directly.
 * Serves a simple page and a JSON API over TLS 1.2 on port 443.
 * Includes a ready-to-use self-signed cert (key password: test123).
 *
 * Regenerate your own (RSA-2048):
 *   openssl req -x509 -newkey rsa:2048 \
 *     -passout pass:test123 -keyout server.key -out server.pem -days 3650 \
 *     -subj "/CN=esp32.local" \
 *     -addext "subjectAltName=DNS:esp32.local,IP:192.168.4.1"
 *
 * Test with:
 *   curl -k https://<ESP32_IP>/api
 *
 * Compile with:
 *   compiler.cpp.extra_flags=-DASYNC_TCP_SSL_ENABLED=1
 */

#include <WiFi.h>
#include <AsyncTCP.h>

const char *SSID     = "YOUR_SSID";
const char *PASSWORD = "YOUR_PASSWORD";

// Self-signed RSA-2048 cert for esp32.local — key password: test123
// Regenerate: openssl req -x509 -newkey rsa:2048 \
//   -passout pass:test123 -keyout server.key -out server.pem -days 3650 \
//   -subj "/CN=esp32.local" -addext "subjectAltName=DNS:esp32.local,IP:192.168.4.1"
static const char SERVER_CERT[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIDKzCCAhOgAwIBAgIUdcrSmRQHfj1jGuDmkB1xOVbdt64wDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLZXNwMzIubG9jYWwwHhcNMjYwODI1MTkwMzU1WhcNMzYw
ODIyMTkwMzU1WjAWMRQwEgYDVQQDDAtlc3AzMi5sb2NhbDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBALHDfpBW6MqSH55rLLFuY5eHYi5S/bH3du5Jdw5c
t7qmc55pIbe0zMBCHKzfua8KI/0OWq/kJBynXcda680pRJ5u9AVmqXEqVQxJ6FW/
vHtRDdBz7rEcGr1rtzmnP6KTxjaXc9AZPQloz18dTyxSwJq1h8sdl7Vtoz5bQzeG
FR2bWZU5z8PUeddVVsX9oUFAC2AfzV5wAC1KH+F8KRmVbGoon4T5T0dE66Sz2DQY
J8BvJUCjTh2E1r+tR8Y3wN9L1sw2InHsPOH1mzWNI2gBoWIqrHL9GSuLfYfUstbn
qA3eoeILluph/3s8XE7oLiEveeo3l1XVI0dZLBRcPcqNmYMCAwEAAaNxMG8wHQYD
VR0OBBYEFABAm1DHsG64G9CdObCOauNH9jKoMB8GA1UdIwQYMBaAFABAm1DHsG64
G9CdObCOauNH9jKoMA8GA1UdEwEB/wQFMAMBAf8wHAYDVR0RBBUwE4ILZXNwMzIu
bG9jYWyHBMCoBAEwDQYJKoZIhvcNAQELBQADggEBADvl8Gf13zSArF1dCgXFDtPs
xdnbTDT/dtLgOFA85JxPWCizzzAKJElU1ZuufOjOocTM8bxEv7XpicTHaK5RxNAi
77oAMYYeU5HcsU127gMrLpA7H9DU7MulwKfadGw5aa22YD8Fbue50SEx3OE5jHpL
++IMPKF/HoN5GyP5+yhd8HjadnA1BVv3ylAn+ZOH4szcUZ+vRb9OZsoWgjeiph1c
bEP7VWWNxcZSJS/geZP2xvZoSXgOGlzGfFz+MnY3TyIwo6O8W6uYHCQ7us8kEW4V
O6o3be94uiadaVZzhHe8i97oSUqpJHpvXce1r0rP/d7m78/2LDUX+YPYaV+D2X8=
-----END CERTIFICATE-----
)EOF";

static const char SERVER_KEY[] PROGMEM = R"EOF(
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFNTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQT1LwhLF3QJtPmEPo
paqR8gICCAAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEEBrUrlk3/9b7bU6b
5Z2H7doEggTQiN3qZeQO4fRXqx1TwoAdgOq37uqbkCPf5zXPg9oLNH85S7E9ndfS
x0PnUizxZ/BXsoTf28B5yqXnSMOsaeJr6aIHx9V5is+rVOQfdY8Rmt+xyidmhmC7
o4FJd3DWzF7aQi/PMJrNY5r3EnAqxxPy3kwjlfo42+ubYXHrB4xS4dHaQv/MoMq1
Mxb+SjP4/UcO+97zer6wSogDZdxQO+uvt37Y0gMKfpTn2QJnDnuu8WN/b1EKcSFm
jwEoLVIfF8J2i5W03zWCmVMK568R7eEkGDq4/aMnScEN2tYWt3gPk4kNK3qQ1fyN
PbobbtSQzstQ4sEiylZkL9JDHISJu7KNUc6JLZlUyhhmF1eTMWyWzUaXuO+OjRoq
JBdAPSjyJQDLiGIcfI4xuqXDssqTQy9WqKkbXCIBloahDPyM8akW7FgCT8gDw9i+
DiGJzyVTNfr7X3OWCJ5tuyCpQI4Mkyi5et1p0ESOS+ctfvRKe9yvRmpI0Kvrzs5S
40TncsQJi9WpFPOrE0BgpftMGN1fW2Mq7R43eZ29vMfY4WFf9yeMV73waFcXH621
dTnf8eDae0NMM3IpGher8hDtpVSdh3Np3VZsrtPRIdcAFjOodwLFgUzk1DXT+tvB
HJOUJwEd3tLHmxo3cuXn09SOY4cuHckka5Cmo9wkQxkCx8lCjdNgGmAa7op5WSvs
MTwij+s1eNk7mMZce+CFHRLU8tcl05fqI/tCEfjRwBa25vKMxG8/g19/HVANaMnL
tGS+ao3YeOxrFNzSYYB6FT16dc/P1g32BSIRnEgEULYFxQDhl/A+oiTDSHXoLl9d
djCvdMi2zX89UZ4sIZWgSYu4UlhQzLiOt7Fa4EO/S4Z5WimR9ag7yDZCtCSWBeUg
7dbGx4tgU4sLvF+hKAVcreHJoBeyWblL1JaY2NbLLJ8yucbV6MuvtQLmgO5pKF27
WOjPVHlQ6mMCcJ8FX8SuT6F/4ZeKAHOHQRTM85Ai9WBPaCnGlLoIK6DwOU+7LoV3
smWq4cx7qGUo2Nx7laITFxy4zggqsIxHJ9tckQDWkGHOClT+nrVhsBF59d/i4uen
3REGhW0IpJU/OhZnmbawDMh6nSW3VSQhE4wkC6lr0pFnOtlnYJzpdHibpQoUO8DD
SxzL8AG5Hdz/eORny88/a7kivmEFWQ3L1SX9cqHq5zXvuFWv6bYvKhhrwWUh13HK
MeeoeKqDGF+rt1jznZjcHJmSq5QI2HoaOhhj7QAUai72mi1b8ZtwYHF+ORnp1oi0
vCw9RKiidHYFQ3ugC5OreBvElzWBjv2Xlf2nHtBhvXFRzTowmEUORMlrWAEJ7ByB
QH72J8GsLR9+NNJiGPJ3OreQ6TsIhmJycyjOlfyz9qK5faz6XnoBzqdGe4iwWd1n
UkT9OrK6lrb1zIKRzVXgxKdopSQ6RKkk7x8SYyTZwLJwSBIx19tZJh7wmRVMNToz
SXOgJAcjB8T1Dz0eaiDT0kwFiaSqwngQXo70x+rKsriRwJ9EXrJ5OQZ61YWj75GJ
ynLof9teDiX4IxOY8brkJqAIkFasjQggJx9PAmEWOodHUinfmy3ppKDEjmmmlngN
CcL72QSXG4Pjb0QUXb8tnDfnrTPcffQbKgTrqvjFpPKDlATFaUeVz+8=
-----END ENCRYPTED PRIVATE KEY-----
)EOF";

AsyncServer *sslServer = NULL;

static void sendResponse(AsyncClient *client, int code, const char *contentType,
                         const char *body, size_t bodyLen) {
  char header[128];
  int headerLen = snprintf(header, sizeof(header),
    "HTTP/1.1 %s\r\n"
    "Content-Type: %s\r\n"
    "Content-Length: %u\r\n"
    "Connection: close\r\n"
    "\r\n",
    code == 200 ? "200 OK" : "301 Moved",
    contentType, (unsigned)bodyLen);
  client->write(header, headerLen);
  client->write(body, bodyLen);
}

static const char INDEX_PAGE[] PROGMEM = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WebServerSSL</title>
  <style>
    body { font-family: sans-serif; text-align: center; padding: 2em; }
    h1 { color: #2c3e50; }
    a { color: #2980b9; }
  </style>
</head>
<body>
  <h1>WebServerSSL</h1>
  <p>HTTPS is working!</p>
  <p><a href="/api">/api</a> - JSON endpoint</p>
</body>
</html>
)rawliteral";

void onClient(void *arg, AsyncClient *client) {
  if (!client) return;

  client->onData([](void *arg, AsyncClient *client, void *data, size_t len) {
    String request((const char *)data, len);

    if (request.startsWith("GET /api")) {
      char json[128];
      int jsonLen = snprintf(json, sizeof(json),
        "{\"status\":\"ok\",\"heap\":%u,\"uptime\":%lu}",
        ESP.getFreeHeap(), millis() / 1000);
      sendResponse(client, 200, "application/json", json, jsonLen);
    } else {
      sendResponse(client, 200, "text/html", INDEX_PAGE, sizeof(INDEX_PAGE) - 1);
    }
    client->close();
  });

  client->onError([](void *arg, AsyncClient *client, int8_t error) {
    Serial.printf("Connection error: %d\n", error);
    delete client;
  });

  client->onDisconnect([](void *arg, AsyncClient *client) {
    delete client;
  });
}

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

  sslServer = new AsyncServer(443);
  sslServer->onClient(onClient, NULL);
  sslServer->beginSecure(SERVER_CERT, SERVER_KEY, "test123");

  Serial.printf("[Server] HTTPS on port 443\n");
  Serial.printf("Test: curl -k https://%s/api\n",
                WiFi.localIP().toString().c_str());
}

void loop() {
  delay(10000);
}
