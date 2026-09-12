/*
 * AsyncTCP - OTAUpdaterSSL example
 *
 * HTTPS firmware updater over AsyncTCP + AsyncSecureSession, with platform-split
 * upload strategy:
 *
 *   - ESP32:   single raw POST of the whole binary. mbedTLS handles large
 *              inbound records, so the client sends one request.
 *   - ESP8266: chunked raw-octet-stream POSTs (~3 KB each). BearSSL on the
 *              device has a 4096-byte inbound TLS buffer (ASI_TLS_IOBUF_SZ),
 *              so the firmware is split into small chunks (X-Index/X-Total)
 *              and fed to Update.begin/write/end across the browser fetch()
 *              loop in the served page.
 *
 * The upload page (GET /) embeds an inline chunker: it POSTs each chunk as
 * a raw Blob with Content-Type: application/octet-stream plus X-Index,
 * X-Total and X-Name headers, and ack-waits between chunks. No multipart.
 *
 * Test:
 *   - build a .bin firmware for your board
 *   - connect to the AP, browse https://<ip>/update
 *   - pick the .bin and click "Update Firmware"
 *
 * Compile with:
 *   compiler.cpp.extra_flags=-DASYNC_TCP_SSL_ENABLED=1
 */

#ifdef ESP8266
#include <ESP8266WiFi.h>
#include <Updater.h>
#else
#include <WiFi.h>
#include <Update.h>
#endif
#include <AsyncTCP.h>

const char *AP_SSID     = "OTA-AP";
const char *AP_PASSWORD = "12345678";  // min 8 chars

// Platform upload strategy: ESP8266 chunks, ESP32 sends the file at once.
#if defined(ESP8266)
// Chunk size (raw bytes) - keep comfortably below the 4096-byte BearSSL
// inbound record buffer once TLS + HTTP headers are added.
#define OTA_CHUNK 1990
#else
#define OTA_CHUNK 0  // 0 => whole file in a single POST
#endif

// Self-signed server cert with an UNENCRYPTED `BEGIN PRIVATE KEY` and a blank
// key password — keeps this updater on the smallest code path (encrypted-key
// decrypt is off by default) while still working on both platforms. For an
// ENCRYPTED PRIVATE KEY example see WebServerSSL (needs the
// ASYNC_TCP_SSL_ENABLE_PKCS8_PASSWORD compile flag).
static const char SERVER_CERT[] PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIDQDCCAiigAwIBAgIUMfxRJfQJEUwIm7lKLXovbRrGL0QwDQYJKoZIhvcNAQEL
BQAwHTEbMBkGA1UEAwwSZXNwMzItc2VydmVyLmxvY2FsMB4XDTI2MDkwODIwMTgw
NloXDTM2MDkwNTIwMTgwNlowHTEbMBkGA1UEAwwSZXNwMzItc2VydmVyLmxvY2Fs
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv1WbyHIYuEpwfxX4Yv/2
XvK9gUkpYrHW4yMi/4dckZIaI9JYncGrJMGVmmCNnrm3wWZMJuMakDvUwxBVWvx2
iYfgrUB+07LpZc9mjogok+2ezDrfovlDS3PfKDLJZbXpeBhCBAiBoXmxKSQvwnoL
QBWAC11skPPsWrOgekcQpoz3Zj/GRW1YbYrUueOHL+dywE2z2IbqMu5EagaePGXE
mTjay3dbDuFVTKiAz2VbojYpHKQ2dTHq8qS067lQG53wEQo7zc38DszqtXhXwJ04
J6LGze5EWbXa0dzFN87KOY/oc+/DlytAu7zjuCfjZmDMEqe9AksG590kuLGRPWRu
QwIDAQABo3gwdjAdBgNVHQ4EFgQUI+Gq7Xf+a1eZ5cw0Z8NTHH3jIpEwHwYDVR0j
BBgwFoAUI+Gq7Xf+a1eZ5cw0Z8NTHH3jIpEwDwYDVR0TAQH/BAUwAwEB/zAjBgNV
HREEHDAaghJlc3AzMi1zZXJ2ZXIubG9jYWyHBMCoBAEwDQYJKoZIhvcNAQELBQAD
ggEBAD+hALQoZl+ejvYE7BCgH73QJ/zVU8M1Q/dxiNg6U7ujEDY5xlb6Wd5/Qf3M
0d3ImKaTneH3PbtvzVaqwZjd2jgZJVCSscBWsvH+NAVkNR4Bcr1TBFIk/q2iPhIW
nZxx9a/ou5L4+EIccH+062jEEdGNJzSAxRRStys8yOMpG3tG8otZ2SLZj/w081Gv
TJr/2Ue/t0GXNXUD5SbLJLP0Hyt6K7wHWGXvY58czPzfDSwRnCv4KfxVLfcJlOjD
VrYkt6orhwPCo/X0wXzxaogs6oue8X1riSj8D92konVQvbHyhbdHAbo5oWUo4d4i
7w6WRsh8cz5G8Ki6KPsxR+hJ8Wg=
-----END CERTIFICATE-----
)EOF";

static const char SERVER_KEY[] PROGMEM = R"EOF(
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/VZvIchi4SnB/
Ffhi//Ze8r2BSSlisdbjIyL/h1yRkhoj0lidwaskwZWaYI2eubfBZkwm4xqQO9TD
EFVa/HaJh+CtQH7Tsullz2aOiCiT7Z7MOt+i+UNLc98oMslltel4GEIECIGhebEp
JC/CegtAFYALXWyQ8+xas6B6RxCmjPdmP8ZFbVhtitS544cv53LATbPYhuoy7kRq
Bp48ZcSZONrLd1sO4VVMqIDPZVuiNikcpDZ1MerypLTruVAbnfARCjvNzfwOzOq1
eFfAnTgnosbN7kRZtdrR3MU3zso5j+hz78OXK0C7vOO4J+NmYMwSp70CSwbn3SS4
sZE9ZG5DAgMBAAECggEAX4OQ/QNYK8edWRPSpzk3+DYdPAkVy9sTdtf3hLBCGblh
qzg6XKZtlS++Sw6gI/h6LuWuZktA23fCwo3Izl7xnb5i/poPtga+VMCwZb664v3g
I/vP4D+mxGfXou2XdFrXbchOTE0iyUVCl1MlNGRQcXFKNmIw7DuYZb7+AYywVzNy
4CruQ/NTM35CkYaPhJEH+RKrFR4nD6MeEZndOzGAE6dtnZ8u7XSwfWPjnqppqpNr
i0xR4fXU5be/vkl+Bvx5Q8eTbGnSZPI3eYPIRvz4daNqoRwgu/1Lx9TdOF8e4Znq
OFIN8It8fs4Z4w4++B8Mcn4gmV8jg/ElkbhvVbVsgQKBgQDggYcYHQRU8kt70kEc
cc6PUeqM3xbaqqGSmp8UUE80lDpZ/MHmwhNQyJH6WFCeK32dMOh46eavTTvX+OUv
4cV5jxuAAkLkDUVHTYqMHfvAuXj49TbAqAVg78Bt0gGuObXVEDuW9rPSYW/tzWM6
RjDzxsAemfrHdBsfSjlwp3QnsQKBgQDaLNJbuSijBmz3UGq6CA3V3Kqrt8rsFlII
kTZoTFAw5Aoa+z3yptteDE0aniiM2P5MBFYB2nv5u4iO5wzepj9/3TokBehQQtjz
mQs8Ar4EIhsnXAdYb+GuVSnKwjH2dyjzymVYFOvjlVfA6ux1PmASwJHdYuaSv29w
3GDE/HBmMwKBgQDAufEDHkXNtoJeNUx34qr0FdpIPGseJES32cyeX6Le/DBrd7Pt
KMX0H3pRcuciISugeY/X3NOPwbmR2bTFugcQJ23wIgDSTSIf58z8I/EurQnQjpEG
KjcT1D1ZCWMv8ZLK6Th+jCIqhELV3e9E42S6oO/kVUMXXfC6l7lfoCDywQKBgH8m
NApEpIwuCH8xnKGCZB3JFqYw3NAuSey4RE8QeoOjwsfquDWcTKhI3v6uQc+j/r/q
nv1BiZMHWhR+Tx/LH6KzGVk5ICT2cF23SbbVmkvqXIzZs2Y0/f+NnmeOOXP8Ch/a
SqnEt5zQwm2p+9hwW6lSFTBCnUHU02ug47ypqg/FAoGBAKFtn/s9YprDgqFCGhgp
efXSyrxbk/IDSr4Ag/dq0syae2h9cIu38VRxqvfyGRYcjyRwtGU4AKuopjU9LDa/
bNko/SWt833zCVk15FRZzcC7jxUPLHuxtEeZxjBcHXoJlPcQqQUx4/miDWtw3ZrE
0yyNO93lC3sGo+KJuDynpU0d
-----END PRIVATE KEY-----
)EOF";

// ---------------------------------------------------------------------------
// Per-request HTTP state. Headers are buffered; the body is streamed straight
// into Update so a multi-hundred-KB file never sits in the heap.
// ---------------------------------------------------------------------------
struct OtaRequest {
  AsyncClient *client = NULL;
  String header;            // raw header bytes, buffered until "\r\n\r\n"
  String method, path;
  size_t contentLength = 0; // Content-Length of this request body
  size_t chunkIndex  = 0;   // X-Index
  size_t total       = 0;   // X-Total (total firmware size)
  String filename;          // X-Name (URL-encoded)
  size_t parsedBody  = 0;   // body bytes consumed so far
  bool   headersDone = false;
  bool   responded   = false;
};

// Firmware update session - spans the chunked requests on ESP8266.
static bool   fwSessionStarted = false;
static size_t fwExpectedBytes  = 0;
static size_t fwReceivedBytes  = 0;
static bool   fwOtaError       = false;

// The ESP8266 updater stages the new image via eboot_command and applies it
// at the next boot (same for the ESP32 partition swap), so reboot shortly
// after the success response has flushed.
static unsigned long fwRebootAt = 0;

// ---------------------------------------------------------------------------
// Upload page. C = OTA_CHUNK: ESP8266 chunks that size, ESP32 (C=0) sends the
// whole file in one request.
// ---------------------------------------------------------------------------
static const char PAGE_FMT[] =
R"rawliteral(<!DOCTYPE html><html><head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body { font-family: sans-serif; text-align: center; padding: 2em; }
#s { margin: 1em 0; font-weight: bold; }
</style></head><body>
<h1>HTTPS OTA</h1>
<div id="s"></div>
<form id="f">
<input type="file" name="firmware">
<button>Update Firmware</button>
</form>
<script>
const C=%d;
document.getElementById('f').addEventListener('submit', async ev => {
  ev.preventDefault();
  const f = ev.target, i = f.querySelector('input[type=file]').files[0];
  if (!i) return alert('choose a file');
  const t = i.size, n = C > 0 ? Math.ceil(t / C) : 1;
  const s = document.getElementById('s');
  const b = document.activeElement; if (b) b.disabled = 1;
  for (let x = 0; x < n; x++) {
    let r;
    try {
      r = await fetch('/update', { method:'POST',
        headers: {
          'X-Index': x,
          'X-Total': t,
          'X-Name': encodeURIComponent(i.name),
          'Content-Type': 'application/octet-stream'
        },
        body: C > 0 ? i.slice(x * C, Math.min(t, (x + 1) * C)) : i });
    } catch (e) {
      s.textContent = 'chunk ' + x + ' net error'; s.style.color = '#c00'; return;
    }
    if (!r.ok) {
      s.textContent = 'chunk ' + x + ' HTTP ' + r.status; s.style.color = '#c00'; return;
    }
    s.textContent = (x + 1) + '/' + n;
  }
  s.textContent = 'Update Success!'; s.style.color = '#0a0';
  setTimeout(() => location.href = '/', 2000);
});
</script>
</body></html>
)rawliteral";

static void sendResponse(AsyncClient *client, int code,
                         const char *body) {
  char header[96];
  size_t bodyLen = strlen(body);
  int headerLen = snprintf(header, sizeof(header),
    "HTTP/1.1 %s\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: %u\r\n"
    "Connection: close\r\n"
    "\r\n",
    code == 200 ? "200 OK" : "500 Internal Server Error",
    (unsigned)bodyLen);
  client->write((const uint8_t *)header, headerLen);
  client->write((const uint8_t *)body, bodyLen);
  client->close();
}

// ---------------------------------------------------------------------------
// Feed a body segment into the Update session.
// ---------------------------------------------------------------------------
static void handleBody(OtaRequest *r, const uint8_t *data, size_t len) {
  fwExpectedBytes = r->total;

  // Stale chunk-0 in the middle of a session means the browser restarted the
  // upload; a half-written firmware cannot be re-begun, so reboot.
  if (r->chunkIndex == 0 && fwSessionStarted) {
    Serial.println("[OTA] stale chunk-0, rebooting");
    ESP.restart();
  }

  if (!fwSessionStarted) {
    fwSessionStarted = true;
    fwReceivedBytes  = 0;
    fwOtaError       = false;
    bool ok;
#if defined(ESP8266)
    uint32_t maxSketchSpace = (ESP.getFreeSketchSpace() - 0x1000) & 0xFFFFF000;
    ok = Update.begin(maxSketchSpace, U_FLASH);
#else
    ok = Update.begin(UPDATE_SIZE_UNKNOWN, U_FLASH);
#endif
    if (!ok) {
      fwOtaError = true;
      String err = Update.errorString();
      Serial.printf("[OTA] Update.begin failed: %s\n", err.c_str());
    } else {
      Serial.printf("[OTA] begin: %s (%u bytes, chunk %u)\n",
                    r->filename.c_str(), (unsigned)r->total,
                    (unsigned)r->chunkIndex);
    }
  }

  if (!fwOtaError && len) {
    if (Update.write(data, len) != len) {
      fwOtaError = true;
      String err = Update.errorString();
      Serial.printf("[OTA] Update.write failed: %s\n", err.c_str());
    } else {
      fwReceivedBytes += len;
    }
  }
  r->parsedBody += len;

  // Last chunk (or ESP32 single request): complete and verify the update.
  if (fwExpectedBytes && fwReceivedBytes >= fwExpectedBytes) {
    const char *done = "OK";
    if (!fwOtaError) {
      if (!Update.end(true)) {
        fwOtaError = true;
        String err = Update.errorString();
        Serial.printf("[OTA] Update.end failed: %s\n", err.c_str());
      } else {
        done = "Update Success!";
      }
    }
    Serial.printf("[OTA] done: %s (%u bytes)\n",
                  fwOtaError ? "FAIL" : "SUCCESS", (unsigned)fwReceivedBytes);
    fwSessionStarted = false;
    fwExpectedBytes  = 0;
    sendResponse(r->client, fwOtaError ? 500 : 200, fwOtaError ? "Update failed!" : done);
    if (!fwOtaError) fwRebootAt = millis() + 1500;
    r->responded = true;
    return;
  }

  // Intermediate chunk: ack so the browser's fetch() proceeds to the next one.
  if (r->parsedBody >= r->contentLength) {
    sendResponse(r->client, 200, "OK");
    r->responded = true;
  }
}

// ---------------------------------------------------------------------------
// Raw request processing: buffer headers, then stream the body to Update.
// ---------------------------------------------------------------------------
static void processData(OtaRequest *r, AsyncClient *client,
                        const uint8_t *data, size_t len) {
  if (!r->headersDone) {
    r->header += String((const char *)data, len);
    int mark = r->header.indexOf("\r\n\r\n");
    if (mark < 0) {
      if (r->header.length() > 2048) r->header.remove(0, 1024);  // header cap
      return;
    }

    String head = r->header.substring(0, mark);
    int nl = head.indexOf("\r\n");
    String reqline = nl >= 0 ? head.substring(0, nl) : head;
    int sp1 = reqline.indexOf(' ');
    int sp2 = reqline.indexOf(' ', sp1 + 1);
    r->method = sp1 > 0 ? reqline.substring(0, sp1) : "";
    r->path   = (sp1 > 0 && sp2 > sp1) ? reqline.substring(sp1 + 1, sp2)
                                       : reqline.substring(sp1 + 1);

    int pos = nl + 2;
    while (pos < (int)head.length()) {
      int eol = head.indexOf("\r\n", pos);
      String line = eol >= 0 ? head.substring(pos, eol) : head.substring(pos);
      int colon = line.indexOf(':');
      if (colon > 0) {
        String name  = line.substring(0, colon);
        String value = line.substring(colon + 1);
        value.trim();
        if (name.equalsIgnoreCase("Content-Length")) r->contentLength = value.toInt();
        else if (name.equalsIgnoreCase("X-Total"))   r->total        = value.toInt();
        else if (name.equalsIgnoreCase("X-Index"))   r->chunkIndex   = value.toInt();
        else if (name.equalsIgnoreCase("X-Name"))    r->filename     = value;
      }
      if (eol < 0) break;
      pos = eol + 2;
    }

    r->headersDone = true;
    r->path.trim();

    if (r->path != "/update" || r->contentLength == 0) {
      // GET / (or any non-update request): serve the upload page.
      char page[1536];
      int pageLen = snprintf(page, sizeof(page), PAGE_FMT, (int)OTA_CHUNK);
      if (pageLen > (int)sizeof(page)) pageLen = (int)sizeof(page);
      char header[96];
      int headerLen = snprintf(header, sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n", pageLen);
      client->write((const uint8_t *)header, headerLen);
      client->write((const uint8_t *)page, pageLen);
      client->close();
      r->responded = true;
      return;
    }

    // Body bytes may already follow the header in this same TCP segment.
    size_t headLen = mark + 4;
    size_t bodyExtra = r->header.length() - headLen;
    const uint8_t *extra = (const uint8_t *)r->header.c_str() + headLen;
    if (r->path == "/update" && bodyExtra) {
      handleBody(r, extra, bodyExtra);
    }
    r->header = String();  // free header memory
    return;
  }

  // All bytes after the header marker are body payload.
  if (r->path == "/update") {
    handleBody(r, data, len);
  }
}

void onClient(void *arg, AsyncClient *client) {
  if (!client) return;

  OtaRequest *r = new OtaRequest();
  r->client = client;

  client->onData([](void *cbArg, AsyncClient *c, void *data, size_t len) {
    OtaRequest *rq = (OtaRequest *)cbArg;
    processData(rq, c, (const uint8_t *)data, len);
  }, r);

  client->onDisconnect([](void *cbArg, AsyncClient *c) {
    delete (OtaRequest *)cbArg;
  }, r);

  client->onError([](void *cbArg, AsyncClient *c, int8_t error) {
    Serial.printf("[OTA] TLS error: %d\n", error);
  }, r);
}

AsyncServer *sslServer = NULL;

void setup() {
  Serial.begin(115200);
  delay(500);

  WiFi.softAP(AP_SSID, AP_PASSWORD);
  delay(500);
  Serial.printf("\nAP SSID: %s  IP: %s\n", AP_SSID,
                WiFi.softAPIP().toString().c_str());

  sslServer = new AsyncServer(443);
  sslServer->onClient(onClient, NULL);
  sslServer->beginSecure(SERVER_CERT, SERVER_KEY, "");

  Serial.printf("[OTA] HTTPS updater on https://%s/update\n",
                WiFi.softAPIP().toString().c_str());
  Serial.printf("[OTA] upload strategy: chunk size = %d bytes per POST\n",
                (int)OTA_CHUNK);
}

void loop() {
  if (fwRebootAt && millis() >= fwRebootAt) {
    Serial.println("[OTA] rebooting to apply firmware");
    ESP.restart();
  }
  delay(100);
}
