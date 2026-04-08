#include <WiFi.h>
#include <FirebaseESP32.h>
#include <Keypad.h>
#include <ESP32Servo.h>
#include <WebServer.h>
#include <Preferences.h>
#include "time.h"
#include "secrets.h"

const String LOCK_ID = "brama_glowna";


Servo myServo;
const int SERVO_PIN = 13;
const int POS_OPEN = 0;
const int POS_CLOSE = 90;

const byte ROWS = 4;
const byte COLS = 4;
char keys[ROWS][COLS] = {
  {'1','2','3','A'},
  {'4','5','6','B'},
  {'7','8','9','C'},
  {'*','0','#','D'}
};
byte rowPins[ROWS] = {19, 18, 5, 17};
byte colPins[COLS] = {16, 4, 0, 2};
Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);


Preferences preferences;
WebServer server(80);
FirebaseData fbdo;
FirebaseAuth auth;
FirebaseConfig config;

String inputBuffer = "";
bool isDoorOpen = false;
unsigned long doorOpenTimestamp = 0;
const unsigned long AUTO_CLOSE_DELAY = 5000;

const char* ntpServer = "pool.ntp.org";
const long  gmtOffset_sec = 3600;
const int   daylightOffset_sec = 3600;


const char HTML_PAGE[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html lang="pl"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Smart Lock</title></head><body>
<div id="login-view">
  <h2>🔐 Zaloguj się</h2>
  <form action="/login" method="POST">
    <input type="text" name="login" placeholder="Login" required maxlength="32">
    <input type="password" name="pass" placeholder="Hasło" required maxlength="64">
    <button>Wejdź</button>
  </form>
  <p style="color:red;">%MSG%</p>
</div>

<div id="control-view" style="display:none;">
  <h2>Panel Sterowania</h2>
  <div>Witaj, <span id="user-display">...</span></div>
  <div id="status-box">Ładowanie...</div>
  <button onclick="openDoor()">OTWÓRZ DRZWI</button>
  <div id="admin-panel" style="display:none;">
    <button onclick="fetchLogs()">POBIERZ LOGI</button>
    <div id="logs-area" style="display:none;"></div>
  </div>
  <a href="/logout">WYLOGUJ</a>
</div>

<script>
let userRole="%ROLE%";
let userName="%USER%";

if(userRole==="ADMIN"||userRole==="USER"){
  document.getElementById('login-view').style.display='none';
  document.getElementById('control-view').style.display='block';
  document.getElementById('user-display').innerText=userName;
  if(userRole==="ADMIN") document.getElementById('admin-panel').style.display='block';
  setInterval(updateStatus,1000);
}
function updateStatus(){
  fetch('/status').then(r=>r.json()).then(data=>{
    document.getElementById('status-box').innerText=data.open?"OTWARTE 🔓":"ZAMKNIĘTE 🔒";
  });
}
function openDoor(){
  fetch('/open-api', {method:'POST'}).then(()=>setTimeout(updateStatus,200));
}
function fetchLogs(){
  const area=document.getElementById('logs-area');
  area.style.display='block';
  area.innerHTML="Pobieranie...";
  fetch('/get-logs').then(r=>r.text()).then(t=>area.innerHTML=t);
}
</script>
</body></html>
)rawliteral";


String getFormattedTime() {
  struct tm timeinfo;
  if(!getLocalTime(&timeinfo)) return "N/A";
  char b[40];
  strftime(b, sizeof(b), "%Y-%m-%d %H:%M:%S", &timeinfo);
  return String(b);
}

bool isSafeText(const String& s, size_t minLen, size_t maxLen) {
  if (s.length() < minLen || s.length() > maxLen) return false;
  for (size_t i=0; i<s.length(); i++) {
    char c = s[i];
    if (!(isalnum((unsigned char)c) || c=='_' || c=='-' || c=='.' || c=='@')) return false;
  }
  return true;
}

uint32_t simpleHash(const String& data) {
  uint32_t h = 2166136261u;
  for (size_t i=0; i<data.length(); i++) {
    h ^= (uint8_t)data[i];
    h *= 16777619u;
  }
  return h;
}

String makeSessionSig(const String& user, const String& role) {
  String raw = user + "|" + role + "|" + SESSION_SECRET;
  uint32_t h = simpleHash(raw);
  char out[11];
  snprintf(out, sizeof(out), "%08lx", (unsigned long)h);
  return String(out);
}


void openLock() {
  if (!isDoorOpen) {
    myServo.write(POS_OPEN);
    isDoorOpen = true;
    doorOpenTimestamp = millis();
  }
}

void closeLock() {
  if (isDoorOpen) {
    myServo.write(POS_CLOSE);
    isDoorOpen = false;
  }
}


void sendLog(const String& user, const String& method) {
  if (WiFi.status() != WL_CONNECTED) return;

  FirebaseJson json;
  json.set("timestamp", getFormattedTime());
  json.set("user", user);
  json.set("method", method);
  json.set("lock_id", LOCK_ID);

  if (!Firebase.pushJSON(fbdo, "/logs", json)) {
    Serial.println("[LOG] Firebase push failed: " + fbdo.errorReason());
  }
}

void checkPinInCloud(const String& pin) {
  if (pin.length() < 4 || pin.length() > 10) return;

  if (pin == EMERGENCY_PIN) {
    openLock();
    sendLog("ADMIN (Offline)", "PIN_MASTER");
    return;
  }

  if (WiFi.status() != WL_CONNECTED) return;

  String path = "/authorized_users/" + pin;
  if (!Firebase.getJSON(fbdo, path)) return;

  FirebaseJsonData dName;
  fbdo.jsonObject().get(dName, "name");
  if (dName.success && dName.typeNum == FirebaseJson::JSON_STRING) {
    String name = dName.stringValue;
    openLock();
    sendLog(name, "PIN");
  }
}

int verifyWebUser(const String& login, const String& password) {
  if (WiFi.status() != WL_CONNECTED) return 0;
  if (!isSafeText(login, 3, 32) || !isSafeText(password, 4, 64)) return 0;

  if (!Firebase.getJSON(fbdo, "/authorized_users")) {
    Serial.println("[AUTH] Firebase read failed: " + fbdo.errorReason());
    return 0;
  }

  FirebaseJson &json = fbdo.jsonObject();
  size_t len = json.iteratorBegin();
  String key, value = "";
  int type = 0;
  int result = 0;

  for (size_t i = 0; i < len; i++) {
    json.iteratorGet(i, type, key, value);

    FirebaseJson userJson;
    userJson.setJsonData(value);

    FirebaseJsonData dLogin, dPass, dRole;
    userJson.get(dLogin, "web_login");
    userJson.get(dPass, "web_pass");
    userJson.get(dRole, "role");

    if (dLogin.success && dPass.success && dRole.success) {
      if (dLogin.stringValue == login && dPass.stringValue == password) {
        result = (dRole.stringValue == "ADMIN") ? 2 : 1;
        break;
      }
    }
  }
  json.iteratorEnd();
  return result;
}


String getCookieValue(const String& name) {
  if (!server.hasHeader("Cookie")) return "";
  String cookie = server.header("Cookie");
  String search = name + "=";
  int start = cookie.indexOf(search);
  if (start == -1) return "";
  start += search.length();
  int end = cookie.indexOf(";", start);
  if (end == -1) end = cookie.length();
  return cookie.substring(start, end);
}

bool isSessionValid() {
  String user = getCookieValue("USER_LOGIN");
  String role = getCookieValue("ROLE");
  String sig  = getCookieValue("SIG");

  if (user.length() == 0 || role.length() == 0 || sig.length() == 0) return false;
  if (!(role == "ADMIN" || role == "USER")) return false;
  return sig == makeSessionSig(user, role);
}

int getRole() {
  if (!isSessionValid()) return 0;
  String r = getCookieValue("ROLE");
  if (r == "ADMIN") return 2;
  if (r == "USER") return 1;
  return 0;
}


void handleRoot() {
  String html = HTML_PAGE;
  int role = getRole();
  String user = getCookieValue("USER_LOGIN");

  html.replace("%ROLE%", role == 2 ? "ADMIN" : (role == 1 ? "USER" : "NONE"));
  html.replace("%USER%", user.length() ? user : "Gość");
  html.replace("%MSG%", server.hasArg("err") ? "Błędne dane!" : "");

  server.send(200, "text/html; charset=utf-8", html);
}

void handleLogin() {
  if (!server.hasArg("login") || !server.hasArg("pass")) {
    server.sendHeader("Location", "/?err=1");
    server.send(303);
    return;
  }

  String l = server.arg("login");
  String p = server.arg("pass");

  int roleId = verifyWebUser(l, p);
  if (roleId > 0) {
    String roleStr = (roleId == 2) ? "ADMIN" : "USER";
    String sig = makeSessionSig(l, roleStr);

    server.sendHeader("Set-Cookie", "USER_LOGIN=" + l + "; Path=/; HttpOnly; SameSite=Lax");
    server.sendHeader("Set-Cookie", "ROLE=" + roleStr + "; Path=/; HttpOnly; SameSite=Lax");
    server.sendHeader("Set-Cookie", "SIG=" + sig + "; Path=/; HttpOnly; SameSite=Lax");
    server.sendHeader("Location", "/");
    server.send(303);
    return;
  }

  server.sendHeader("Location", "/?err=1");
  server.send(303);
}

void handleLogout() {
  server.sendHeader("Set-Cookie", "USER_LOGIN=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
  server.sendHeader("Set-Cookie", "ROLE=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
  server.sendHeader("Set-Cookie", "SIG=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
  server.sendHeader("Location", "/");
  server.send(303);
}

void handleStatus() {
  server.send(200, "application/json", isDoorOpen ? "{\"open\":true}" : "{\"open\":false}");
}

void handleOpenApi() {
  int r = getRole();
  if (r == 0) {
    server.send(403, "text/plain", "Forbidden");
    return;
  }

  String userLogin = getCookieValue("USER_LOGIN");
  if (!isSafeText(userLogin, 1, 32)) userLogin = "Nieznany WWW";

  openLock();
  sendLog(userLogin, "WEB_WWW");
  server.send(200, "text/plain", "OK");
}

void handleGetLogs() {
  if (getRole() != 2) {
    server.send(403, "text/plain", "Brak Uprawnień");
    return;
  }

  if (!Firebase.getJSON(fbdo, "/logs")) {
    server.send(200, "text/plain", "Brak logów.");
    return;
  }

  // Proste i bezpieczniejsze wyświetlenie (surowy JSON)
  server.send(200, "application/json; charset=utf-8", fbdo.jsonString());
}


bool waitForSerialInput(unsigned long timeoutMs) {
  unsigned long start = millis();
  while (!Serial.available()) {
    if (millis() - start > timeoutMs) return false;
    delay(10);
  }
  return true;
}

void setupWiFi() {
  preferences.begin("wifi-conf", true);
  String ssid = preferences.getString("ssid", "");
  String pass = preferences.getString("pass", "");
  preferences.end();

  if (ssid == "") {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);
    Serial.println("Skanowanie...");
    int n = WiFi.scanNetworks();

    if (n <= 0) {
      Serial.println("Brak sieci Wi-Fi.");
      delay(2000);
      ESP.restart();
      return;
    }

    for (int i = 0; i < n; ++i) {
      Serial.printf("%d: %s\n", i + 1, WiFi.SSID(i).c_str());
    }

    Serial.println("Wpisz NUMER sieci:");
    if (!waitForSerialInput(WIFI_FALLBACK_TIMEOUT_MS)) {
      Serial.println("Timeout inputu serial.");
      ESP.restart();
      return;
    }
    int c = Serial.parseInt();
    Serial.read();

    if (c < 1 || c > n) {
      Serial.println("Niepoprawny numer sieci.");
      ESP.restart();
      return;
    }

    Serial.println("Hasło:");
    if (!waitForSerialInput(WIFI_FALLBACK_TIMEOUT_MS)) {
      Serial.println("Timeout inputu hasła.");
      ESP.restart();
      return;
    }

    String p = Serial.readStringUntil('\n');
    p.trim();

    preferences.begin("wifi-conf", false);
    preferences.putString("ssid", WiFi.SSID(c - 1));
    preferences.putString("pass", p);
    preferences.end();

    Serial.println("Zapisano. Restart...");
    delay(1000);
    ESP.restart();
    return;
  }

  Serial.print("Łączenie z: ");
  Serial.println(ssid);
  WiFi.begin(ssid.c_str(), pass.c_str());

  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
    attempts++;
    if (attempts > 40) {
      Serial.println("\n[BŁĄD] Nie można połączyć. Reset ustawień Wi-Fi!");
      preferences.begin("wifi-conf", false);
      preferences.clear();
      preferences.end();
      delay(1000);
      ESP.restart();
      return;
    }
  }

  Serial.println("\nIP: " + WiFi.localIP().toString());
}


void setup() {
  Serial.begin(115200);

  myServo.setPeriodHertz(50);
  myServo.attach(SERVO_PIN, 500, 2400);
  myServo.write(POS_CLOSE);

  setupWiFi();
  configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);

  config.database_url = FIREBASE_HOST;
  config.signer.tokens.legacy_token = FIREBASE_AUTH;
  Firebase.begin(&config, &auth);
  Firebase.reconnectWiFi(true);

  const char* h[] = {"Cookie"};
  server.collectHeaders(h, 1);

  server.on("/", HTTP_GET, handleRoot);
  server.on("/login", HTTP_POST, handleLogin);
  server.on("/logout", HTTP_GET, handleLogout);
  server.on("/status", HTTP_GET, handleStatus);
  server.on("/open-api", HTTP_POST, handleOpenApi);
  server.on("/get-logs", HTTP_GET, handleGetLogs);

  server.begin();
}

void loop() {
  server.handleClient();

  if (isDoorOpen && (millis() - doorOpenTimestamp > AUTO_CLOSE_DELAY)) {
    closeLock();
  }

  char key = keypad.getKey();
  if (key) {
    if (key == '#') {
      checkPinInCloud(inputBuffer);
      inputBuffer = "";
    } else if (key == '*') {
      inputBuffer = "";
    } else {
      if (inputBuffer.length() < 10) inputBuffer += key;
    }
  }
}
