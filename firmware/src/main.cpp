#include <Arduino.h>
#include <vector>
#include <string>
#include <esp_wifi.h>
#include <Web3.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <TcpBridge.h>
#include <freertos/queue.h>

TaskHandle_t Task1;
TaskHandle_t Task2;

#if 1 // switch this to '0' to remove Serial output to improve performance
#define debug(x) Serial.print(x)
#define debugLn(x) Serial.println(x)
#else
#define debug(x) 
#define debugLn(x)
#endif

// LED pins
const int led1 = 2;
const int led2 = 4;

#define DOOR_CONTRACT "0xeAC4F618232B5cA1C895B6e5468363fdd128E873" //insert your NFT here: see ../contract/contracts/usage/STLDoor.sol
#define DEVICE_PRIVATE_KEY "0000000000000000000000000000000000000000000000000000000000000000" //create a private key. You can use MetaMask/ethers/web3j etc.
                                                                                              //Once created you need to update the IoT address in the TokenScript
#define ISSUER_ADDRESS  "e761eb6e829de49deab008120733c1e35acf77db"
#define ISSUER_IS_VALID "0000000000000000000000000000000000000001"
#define DOOR_EVENT_ID "devcon6" //eventId in your created attestation

void Task1code( void * pvParameters );
void Task2code( void * pvParameters );
void updateChallenge();
void setupWifi();

const char* seedWords[] = { "Apples", "Oranges", "Grapes", "DragonFruit", "BreadFruit", "Pomegranate", "Aubergine", "Fungi", "Falafel", "Cryptokitty", "Kookaburra", "Elvis", "Koala", 0 };

string currentChallenge;

TcpBridge* tcpConnection;

const char* apiRoute = "api/";

typedef enum DoorCommand
{
  cmd_none,
  cmd_startBlueTooth,
  cmd_disconnectBlueTooth,
  cmd_unlock,
  cmd_lock,
  cmd_query,
  cmd_statusReturn,
  cmd_end
} DoorCommand;

typedef enum ConnectionState
{
    DISCONNECTED,
    RECONNECT,
    WAIT_FOR_CONNECTION,
    CONNECTED,
    WAIT_FOR_COMMAND_COMPLETION,
    WAIT_FOR_DISCONNECT,
    DISCONNECT,
} ConnectionState;

enum LockComms
{
  lock_command,
  unlock_command,
  wait_for_command_complete,
  idle
};

enum APIRoutes
{
  api_unknown,
  api_getChallenge,
  api_checkSignature,
  api_checkSignatureLock,
  api_checkMarqueeSig,
  api_end
};

typedef struct 
{
  const char *ssid;
  const char *password;
} WiFiCredentials;

std::vector<WiFiCredentials> wiFiCredentials 
{
  {"<SSID>", "<Password>"},
  {"<backup hotspot SSID>", "<Password>"}, //in case the main wifi goes down you can still supply connection via a hotspot
};

std::map<std::string, APIRoutes> s_apiRoutes;

void Initialize()
{
  s_apiRoutes["getChallenge"] = api_getChallenge;
  s_apiRoutes["checkSignature"] = api_checkSignature;
  s_apiRoutes["checkSignatureLock"] = api_checkSignatureLock;
  s_apiRoutes["end"] = api_end;
}

ConnectionState state = DISCONNECTED;
Web3* web3;
KeyID* keyID;
LockComms lockStatus = idle;
DoorCommand command = cmd_none;
DoorCommand nextCmd = cmd_none;
long callTime = 0;
long infoTime = millis();
bool isConnected;
static volatile long unlockTime = 0;
static volatile bool isLocked;

void changeState(ConnectionState newState)
{
  debug("New State: ");
  switch (newState)
  {
  case DISCONNECTED:
    debugLn("Disconnected");
    break;

  case RECONNECT:
    debugLn("Reconnect");
    break;

  case WAIT_FOR_CONNECTION:
    debugLn("Wait for connection");
    break;

  case CONNECTED:
    debugLn("Connected");
    break;

  case WAIT_FOR_COMMAND_COMPLETION:
    debugLn("Wait for command completion");
    break;

  case DISCONNECT:
    debugLn("Disconnect");
    break;

  case WAIT_FOR_DISCONNECT:
    debugLn("Wait for disconnect");
    break; 
  }

  state = newState;
}

boolean checkCommsTime(long &checkTime, long seconds, const char *message = "")
{
  if (checkTime > 0 && millis() > (checkTime + 1000 * seconds))
  {
    if (message[0] != 0)
    {
      debugLn(message);
    }
    checkTime = millis();
    return true;
  }
  else
  {
    return false;
  }
}

bool equalsIgnoreCase(const string& a, const string& b)
{
    unsigned int sz = a.size();
    if (b.size() != sz)
        return false;
    for (unsigned int i = 0; i < sz; ++i)
        if (tolower(a[i]) != tolower(b[i]))
            return false;
    return true;
}

bool StringNonZero(std::string *checkString)
{
  return std::string::npos != checkString->find_first_not_of('0');
}

bool QueryBalance(const char* contractAddr, std::string* userAddress, std::string* attestation, std::string* attestationSig, std::string* resultStr)
{
  debugLn("Checking Attestation");
  // transaction
  bool hasToken = false;
  bool attestationValid = false;

  Contract contract(web3, contractAddr);
  string func = "verifyEASAttestation(struct,bytes)";
  string param = contract.SetupContractData(func.c_str(), attestation, attestationSig);
  Contract::ReplaceFunction(param, "verifyEASAttestation((bytes32,address,uint64,uint64,bool,bytes32,bytes),bytes)");
  string result = contract.ViewCall(&param);

  //parse the result to find the returns
  vector<string> *vectorResult = Util::ConvertResultToArray(&result);

  if (vectorResult->size() < 4)
  {
    debugLn("Return param not valid - does the contract implement 'verifyAttestation(bytes) ?");
    *resultStr = "View Contract not implemented correctly";
    return false;
  }

  debugLn(vectorResult->at(0).c_str()); //issuer is valid
  debugLn(vectorResult->at(1).c_str()); //issuer (not required)
  debugLn(vectorResult->at(2).c_str()); //subjectAddress (must match user address)
  debugLn(vectorResult->at(3).c_str()); //attestation within valid time (bool)
  debugLn(vectorResult->at(4).c_str()); //revocation time (if revoked)

  string addr1 = vectorResult->at(2).substr(24, 40);
  hasToken = equalsIgnoreCase(addr1, userAddress->substr(2));
  attestationValid = vectorResult->at(0).at(63) == '1';
  attestationValid = attestationValid & vectorResult->at(3).at(63) == '1';
  bool isRevoked = StringNonZero(&vectorResult->at(4));

  delete vectorResult;

  if (!hasToken)
  {
    *resultStr = "Attestation issued to different User: 0x";
    *resultStr += addr1;
  }

  if (!attestationValid)
  {
    *resultStr = "Issuer not valid: add issuer onto keychain.";
  }

  if (!isRevoked)
  {
    *resultStr = "Attestation has been revoked.";
  }

  if (!hasToken || !attestationValid || isRevoked)
  {
    return false;
  }

  //Now decode the attestation content
  //decodeAttestationData((address,uint64,uint64,bool,bytes32,bytes,uint256,bytes32))
  func = "decodeAttestationData(struct)";
  param = contract.SetupContractData(func.c_str(), attestation);
  Contract::ReplaceFunction(param, "decodeAttestationData((bytes32,address,uint64,uint64,bool,bytes32,bytes))");

  result = contract.ViewCall(&param);

  //(string memory eventId, string memory ticketId, uint8 ticketClass, bytes memory commitment)
  vectorResult = Util::ConvertResultToArray(&result);
  result = web3->getResult(&result);
  uint32_t lengthEventId = uint256_t(vectorResult->at(4));

  char* eventStr = (char*) alloca(lengthEventId + 1);
  eventStr[lengthEventId] = 0;

  string dump = Util::ConvertHexToASCII(result.substr(0xa0*2, lengthEventId*2).c_str(), lengthEventId*2);

  delete vectorResult;

  if (equalsIgnoreCase(dump, DOOR_EVENT_ID))
  {
    return true;
  }
  else
  {
    *resultStr = "Incorrect eventId; must be ";
    *resultStr += DOOR_EVENT_ID;
    return false;
  }
}

bool QueryBalance(const char* contractAddr, std::string* userAddress)
{
  // transaction
  bool hasToken = false;
  Contract contract(web3, contractAddr);
  string func = "balanceOf(address)";
  string param = contract.SetupContractData(func.c_str(), userAddress);
  string result = contract.ViewCall(&param);

  debugLn(result.c_str());

  // break down the result
  uint256_t baseBalance = web3->getUint256(&result);

  if (baseBalance > 0)
  {
    hasToken = true;
    debugLn("Has token");
  }

  return hasToken;
}

std::string handleTCPAPI(APIReturn* apiReturn)
{
  debugLn(apiReturn->apiName.c_str());
  string address;
  string resultStr;

  switch (s_apiRoutes[apiReturn->apiName])
  {
  case api_getChallenge:
    debugLn(currentChallenge.c_str());
    return currentChallenge;
  case api_checkSignature:
  {
    debug("Sig: ");
    debugLn(apiReturn->params["sig"].c_str());
    address = Crypto::ECRecoverFromPersonalMessage(&apiReturn->params["sig"], &currentChallenge);
    int unlockSeconds = strtol(apiReturn->params["openTime"].c_str(), NULL, 10);
    debug("EC-Addr: ");
    debugLn(address.c_str());
    std::string attn = apiReturn->params["attn"];
    std::string attnSig = apiReturn->params["attnSig"];
    debug("Attn: ");
    debugLn(attn.c_str());
    debug("AttnSig: ");
    debugLn(attnSig.c_str());
    boolean attestationValid = QueryBalance(DOOR_CONTRACT, &address, &attn, &attnSig, &resultStr);
    updateChallenge(); // generate a new challenge after each check
    if (attestationValid)
    {
      lockStatus = unlock_command;
      command = cmd_unlock;
      return string("pass");
    }
    else
    {
      return string("fail: " + resultStr);
    }
  }
  break;
  case api_checkSignatureLock:
  {
    debug("Sig: ");
    debugLn(apiReturn->params["sig"].c_str());
    address = Crypto::ECRecoverFromPersonalMessage(&apiReturn->params["sig"], &currentChallenge);
    int unlockSeconds = strtol(apiReturn->params["openTime"].c_str(), NULL, 10);
    debug("EC-Addr: ");
    debugLn(address.c_str());
    boolean hasToken = QueryBalance(DOOR_CONTRACT, &address);
    updateChallenge(); // generate a new challenge after each check
    if (hasToken)
    {
      //command = cmd_lock;
      return string("pass");
    }
    else
    {
      return string("fail");
    }
  }
  break;
  case api_unknown:
  case api_end:
    break;
  }

  return string("");
}

void setup() 
{
  Serial.begin(115200); 
  pinMode(led1, OUTPUT);
  pinMode(led2, OUTPUT);

  //create a task that will be executed in the Task1code() function, with priority 1 and executed on core 0
  xTaskCreatePinnedToCore(
                    Task1code,   /* Task function. */
                    "Task1",     /* name of task. */
                    10000,       /* Stack size of task */
                    NULL,        /* parameter of the task */
                    1,           /* priority of the task */
                    &Task1,      /* Task handle to keep track of created task */
                    0);          /* pin task to core 0 */                  
  delay(500); 

  //create a task that will be executed in the Task2code() function, with priority 1 and executed on core 1
  xTaskCreatePinnedToCore(
                    Task2code,   /* Task function. */
                    "Task2",     /* name of task. */
                    10000,       /* Stack size of task */
                    NULL,        /* parameter of the task */
                    1,           /* priority of the task */
                    &Task2,      /* Task handle to keep track of created task */
                    1);          /* pin task to core 1 */
    delay(500);

    Initialize();
}

void checkBlueToothStatus()
{
  switch (command)
    {
    case cmd_none:
      break;
    case cmd_startBlueTooth:
      command = cmd_none;
      debugLn("Starting Bluetooth connection");
      if (state == DISCONNECTED)
        changeState(RECONNECT);
      break;
    case cmd_disconnectBlueTooth:
      command = cmd_none;
      if (state == CONNECTED)
      {
        changeState(DISCONNECT);
      }
      else
      {
        nextCmd = command;
      }
      break;
    case cmd_unlock:
      unlockTime = millis() + 10000;
      command = cmd_none;

      break;
    case cmd_lock:
      command = cmd_none;

      break;
    case cmd_query:
      command = cmd_none;

      break;
    case cmd_statusReturn:
      command = cmd_none;
      // shouldn't see this on this end
      break;
    default:
      command = cmd_none;
      debug("Unknown command: ");
      debugLn(command);
      break;
    }
}

void checkState()
{
  switch (state)
    {
    case DISCONNECTED:
      // wait for instruction
      break;

    case RECONNECT:
      checkCommsTime(infoTime, 20, "Has connection");
      callTime = millis();
      changeState(WAIT_FOR_CONNECTION);
      nextCmd = cmd_query;
      break;

    case WAIT_FOR_CONNECTION:
      checkCommsTime(infoTime, 20, "Wait for link");
      // TODO: Add timeout
      break;

    case CONNECTED:
      // link established, get status
      checkCommsTime(infoTime, 20, "Link established");
      if (checkCommsTime(callTime, 40))
      {
        // timeout if no call received for 40 seconds
        debugLn("Connection timeout, close");
        changeState(DISCONNECT);
      }
      break;

    case WAIT_FOR_COMMAND_COMPLETION:
      checkCommsTime(infoTime, 20, "Wait for call completion ...");
      // TODO: Timeout
      break;

    case DISCONNECT:
      changeState(WAIT_FOR_DISCONNECT);
      break;

    case WAIT_FOR_DISCONNECT:
      if (checkCommsTime(infoTime, 5))
      {
        debugLn("Connected: Wait for disconnect");
        debug("Lock is ");
        if (isLocked)
          debugLn("Locked");
        else
          debugLn("Unlocked");
      }
      // TODO: Timeout
      break;
    }
}

//Task1code: blinks an LED every 1000 ms
void Task1code( void * pvParameters ){
  
  debug("Task1 running on core ");
  debugLn(xPortGetCoreID());

  delay(1000);

  debugLn("Try BlueTooth");

  // Start listening on Bluetooth
  int ledState = HIGH;
  int ledStateCount = 0;
  long resetTime = millis() + 1000 * 60 * 60 * 24;

  for(;;)
  {
    delay(250);
    if (unlockTime > 0)
    {
      ledState = HIGH;
      if (millis() > unlockTime)
      {
        debugLn("LOCK");
        isLocked = true;
        unlockTime = 0;
      }
    }
    else if (ledStateCount % (isLocked ? 8 : 2) == 0)
    {
      ledState = (ledState == HIGH) ? LOW : HIGH;
      ledStateCount = 0;
    }

    ledStateCount++;
  
    digitalWrite(led1, ledState);

    checkBlueToothStatus();
    checkState();

    if (millis() > resetTime)
    {
      ESP.restart();
    }
  }
}

//Task2code: blinks an LED every 700 ms
void Task2code( void * pvParameters )
{
  debug("Task2 running on core ");
  debugLn(xPortGetCoreID());

  isLocked = true;

  setupWifi();

  web3 = new Web3(SEPOLIA_ID);
  keyID = new KeyID(web3, DEVICE_PRIVATE_KEY);
  updateChallenge();
  
  tcpConnection = new TcpBridge();
  tcpConnection->setKey(keyID, web3);
  tcpConnection->startConnection();

  int ledState = HIGH;
      
  for(;;)
  {
    digitalWrite(led2, ledState);
    delay(500);
    ledState = (ledState == HIGH) ? LOW : HIGH;
    setupWifi();
    tcpConnection->checkClientAPI(&handleTCPAPI);
  }
}

void loop() 
{
  vTaskDelete (NULL);
}

void updateChallenge()
{
  // generate a new challenge
  int size = 0;
  while (seedWords[size] != 0)
    size++;
  debugLn(size);
  char buffer[32];

  int seedIndex = random(0, size);
  currentChallenge = seedWords[seedIndex];
  currentChallenge += "-";
  long challengeVal = random32();
  currentChallenge += itoa(challengeVal, buffer, 16);

  debug("Challenge: ");
  debugLn(currentChallenge.c_str());
}

bool wifiConnect(const char* ssid, const char* password)
{
  if (WiFi.status() == WL_CONNECTED)
  {
    return true;
  }

  debugLn();
  debug("Connecting to ");
  debugLn(ssid);

  if (WiFi.status() != WL_CONNECTED)
  {
    esp_wifi_set_ps(WIFI_PS_MAX_MODEM);
    WiFi.begin(ssid, password);
  }

  int wificounter = 0;
  while (WiFi.status() != WL_CONNECTED && wificounter < 20)
  {
    for (int i = 0; i < 500; i++)
    {
      delay(1);
    }
    debug(".");
    wificounter++;
  }

  if (WiFi.status() != WL_CONNECTED)
  {
    debug("-");
    return false;
  }
  else
  {
    return true;
  }
}

void setupWifi()
{
  if (WiFi.status() == WL_CONNECTED)
  {
    return;
  }

  delay(100);

  WiFi.enableSTA(true);
  WiFi.mode(WIFI_STA);

  bool connected = false;
  int index = 0;

  while (!connected)
  {
    connected = wifiConnect(wiFiCredentials[index].ssid, wiFiCredentials[index].password);
    if (++index > wiFiCredentials.size())
    {
      break;
    } 
  }

  if (!connected)
  {
    debugLn("Restarting ...");
    ESP.restart(); // targetting 8266 & Esp32 - you may need to replace this
  }

  esp_wifi_set_max_tx_power(78); // save a little power if your unit is near the router. If it's located away then use 78 - max
  delay(10);

  debugLn("");
  debugLn("WiFi connected.");
  debugLn("IP address: ");
  debugLn(WiFi.localIP());
}