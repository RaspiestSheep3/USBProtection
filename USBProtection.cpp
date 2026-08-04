// USBProtection.cpp : Defines the entry point for the application.
//

#include "USBProtection.h"

using namespace std;

//Structures
struct Condition {
    uint8_t type = 0;
    /*
    0 - Invalid
    1 - Owner
    2 - Time
    3 - Known
    4 - VID
    5 - PID
    6 - System Mode
    7 - Custom Name
    */
    string RHS = "";
    char sign = '=';
};

struct ASTNode {
    Condition* condition = NULL; //If NULL, assume naturally true - this is for ALLOW / DENY stuff
    ASTNode* ifBlock = NULL; //If the end of the chain, NULL
    ASTNode* elseBlock = NULL; //NULL if not an IF thing
    uint8_t allowCode = 0;
    /*
        0 - Invalid
        1 - ALLOW
        2 - REQUEST
        3 - DENY
    */
};

struct USBStatus {
    //This is not strictly required but keeps things neater IMO
    string owner = "";
    bool known = false;
    string VID = "";
    string PID = "";
    uint8_t systemMode;
    string customName = "";
};

//System settings
string policyPath;
string knownCombinationsFilePath;
string knownKeypairsPath;
uint8_t systemMode;
ASTNode root;

//Helpers
string GenerateSubstr(string str, char start, char end) {
    string out = "";
    for (int i = str.find(start) + 1; i < str.length(); i++) {
        if (str[i] == end) break;
        out += str[i];
    }

    return out;
}

string PadAndTrimStr(string str, int finalLen, char padChr = '|') {
    //Left aligned
    string strNew = str.substr(0, finalLen);
    while (strNew.length() < finalLen) strNew += padChr;
    return strNew;
}

void DBCCParser(uint64_t* bufferInt, string* bufferStr, string dbcc) {
    string VID = dbcc.substr(12, 4);
    string PID = dbcc.substr(21, 4);
    string serial = dbcc.substr(26, 16);

    bufferStr[0] = VID;
    bufferStr[1] = PID;
    bufferStr[2] = serial;

    cout << "VID : " << VID << "\nPID : " << PID << "\nSerial : " << serial << endl;

    bufferInt[0] = stoull(VID, 0, 16);
    bufferInt[1] = stoull(PID, 0, 16);
    bufferInt[2] = stoull(serial, 0, 16);
}

void GenerateRSAKeys(RSA* rsaKeypair) {
    //https://mojoauth.com/keypair-generation/generate-keypair-using-rsa-with-cpp#2-generating-the-rsa-key-pair

    //This nonsense is required by OPENSSL
    auto bn = BN_new();
    BN_set_word(bn, 65537); //Traditional e for RSA
    RSA_generate_key_ex(rsaKeypair, 4096, bn, NULL); //Max security w/ RSA

    string folderPath;
    cout << "PEM folder path : ";
    cin >> folderPath;
    cout << endl;

    string privatePath = folderPath + "/private.pem";
    string publicPath = folderPath + "/public.pem";

    FILE* privateKeyFile = fopen(privatePath.c_str(), "w");
    PEM_write_RSAPrivateKey(privateKeyFile, rsaKeypair, NULL, NULL, 0, NULL, NULL);
    fclose(privateKeyFile);

    FILE* publicKeyFile = fopen(publicPath.c_str(), "w");
    PEM_write_RSAPublicKey(publicKeyFile, rsaKeypair);
    fclose(publicKeyFile);
}

RSA* LoadPublicKey(const string& folder, string extension = "/public.pem")
{
    ifstream file(folder + extension);

    string pem{
        istreambuf_iterator<char>(file),
        istreambuf_iterator<char>()
    };

    file.close();

    BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());

    RSA* rsa = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);

    BIO_free(bio);

    return rsa;
}

RSA* LoadPrivateKey(const string& folder)
{
    ifstream file(folder + "/private.pem");

    string pem{
        istreambuf_iterator<char>(file),
        istreambuf_iterator<char>()
    };

    file.close();

    BIO* bio = BIO_new_mem_buf(pem.data(), pem.size());

    RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);

    BIO_free(bio);

    return rsa;
}

bool RSASign(RSA* rsa,
    const unsigned char* Msg,
    size_t MsgLen,
    unsigned char** EncMsg,
    size_t* MsgLenEnc) {
    //https://gist.github.com/irbull/08339ddcd5686f509e9826964b17bb59

    EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
    EVP_PKEY* priKey = EVP_PKEY_new();
    //EVP_PKEY_assign_RSA(priKey, rsa);
    EVP_PKEY_set1_RSA(priKey, rsa);
    if (EVP_DigestSignInit(m_RSASignCtx, NULL, EVP_sha256(), NULL, priKey) <= 0) {
        return false;
    }
    if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
        return false;
    }
    if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <= 0) {
        return false;
    }
    *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
    if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
        return false;
    }

    EVP_PKEY_free(priKey);
    EVP_MD_CTX_free(m_RSASignCtx);
    return true;
}
    
string sha256(const string& str)
{
    //https://stackoverflow.com/questions/2262386/generate-sha256-with-openssl-and-c
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

//AI
// Convert binary bytes to Hex string
string BytesToHex(const unsigned char* data, size_t len) {
    stringstream ss;
    for (size_t i = 0; i < len; ++i) {
        ss << hex << setw(2) << setfill('0') << (int)data[i];
    }
    return ss.str();
}

// Convert Hex string back to binary bytes
vector<unsigned char> HexToBytes(const string& hexStr) {
    vector<unsigned char> bytes;
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        string byteString = hexStr.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), NULL, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

//functions
void FormASTTreeLayer(ASTNode* node, vector<string> scope) {
    cout << "============" << endl;
    cout << "Forming AST Layer" << endl;

    cout << "Scope size : " << scope.size() << endl;
    cout << "Scope : " << endl;
    for (string line : scope) cout << line << endl;
    
    /*We can say a scope has either an IF / ELSE setup or not
    If it does, we need to consider the IF/ELSE pair together
    If it doesnt, its a simple ALLOW/REQUEST/DENY node*/
    if (scope[0].substr(0,2) == "IF") {
        //In this case we are dealing with an IF,ELSE clause
        string conditionStr = GenerateSubstr(scope[0], '[', ']');
        string conditionTypeStr = GenerateSubstr(conditionStr, '~', '~');
        uint8_t conditionType = 0;
        char conditionSign = '=';

        if (conditionTypeStr == "OWNER") conditionType = 1;
        else if (conditionTypeStr == "TIME") {
            conditionType = 2;
            if (conditionStr.find('>') != string::npos) conditionSign = '>';
            else if (conditionStr.find('<') != string::npos) conditionSign = '<';
        }
        else if (conditionTypeStr == "KNOWN") conditionType = 3;
        else if (conditionTypeStr == "VID") conditionType = 4;
        else if (conditionTypeStr == "PID") conditionType = 5;
        else if (conditionTypeStr == "SYSTEM_MODE") conditionType = 6;
        else if (conditionTypeStr == "CUSTOM_NAME") conditionType = 7;

        node->condition = new Condition{
            conditionType,
            GenerateSubstr(conditionStr, '#', '#'),
            conditionSign
        };

        //Visualising the condition
        cout << "Condition : " << endl;
        cout << "Type : " << to_string(node->condition->type) << endl;
        cout << "RHS : " << node->condition->RHS << endl;
        cout << "Sign : " << node->condition->sign << endl;

        //Counting out the IF scope using depths
        uint64_t scopeDepth = 1;
        vector<string> ifScope = {};
        uint64_t ifBlockEnd = 1;
        for (int i = 1; i < scope.size(); i++) {
            if (scope[i].find('{') != string::npos) scopeDepth++;
            else if (scope[i].find('}') != string::npos) scopeDepth--;
            if (scopeDepth == 0) break;
            ifScope.push_back(scope[i]);

            cout << "IF Scope Section : " << scope[i] << endl;
            ifBlockEnd++;
        }

        node->ifBlock = new ASTNode();
        FormASTTreeLayer(node->ifBlock, ifScope);

        cout << "IF Block end " << ifBlockEnd << endl;

        //EL will not always exist - we first need to work out if it exists 
        if ((scope.size() > ifBlockEnd + 1) && (scope[ifBlockEnd + 1].substr(0, 2) == "EL")) {
            //Counting out the EL scope using depths
            scopeDepth = 1;
            vector<string> elScope = {};
            for (int i = ifBlockEnd + 2; i < scope.size(); i++) {
                if (scope[i].find('{') != string::npos) scopeDepth++;
                else if (scope[i].find('}') != string::npos) scopeDepth--;
                if (scopeDepth == 0) break;
                elScope.push_back(scope[i]);

                cout << "EL Scope Section : " << scope[i] << endl;
            }

            node->elseBlock = new ASTNode();
            FormASTTreeLayer(node->elseBlock, elScope);
        }
    }
    else {
        //In this case we are dealing with an ALLOW/REQUETS/DENY sitauton
        cout << "ALLOW Scope : " << scope[0] << endl;
        if (scope[0] == ":ALLOW:") node->allowCode = 1;
        else if (scope[0] == ":REQUEST:") node->allowCode = 2;
        else node->allowCode = 3;
    }

    cout << "-------" << endl;
}

bool CheckCondition(Condition* condition, USBStatus* status) {
    cout << "Checking Condition of type " << to_string(condition->type) << endl;

    if (condition->type == 1) {
        //Owner 
        return (status->owner == condition->RHS);
    }
    else if (condition->type == 2) {
        //Time
        time_t currentTimestamp = time(NULL);

        struct tm comparisonDatetime = *localtime(&currentTimestamp);;
        comparisonDatetime.tm_hour = stoi((condition->RHS).substr(0,2));
        comparisonDatetime.tm_min = stoi((condition->RHS).substr(3, 2));
        comparisonDatetime.tm_sec = stoi((condition->RHS).substr(6, 2));
        time_t comparisonTimestamp = mktime(&comparisonDatetime);

        double difference = difftime(comparisonTimestamp, currentTimestamp);
        if ((difference > 0 && condition->sign == '>') 
            || (difference < 0 && condition->sign == '<')
            || (difference == 0 && condition->sign == '=')) return true;
        else return false;
    }
    else if (condition->type == 3) {
        //Known
        return(status->known == (condition->RHS == "true"));
    }
    else if (condition->type == 4) {
        //VID
        return (status->VID == condition->RHS);
    }
    else if (condition->type == 5) {
        //PID
        return (status->PID == condition->RHS);
    }
    else if (condition->type == 6) {
        //System Mode
        return (to_string(status->systemMode) == condition->RHS);
    }
    else if (condition->type == 7) {
        //Custom name
        return (status->customName == condition->RHS);
    }

    return false; //Backup failure condition
}

uint8_t NodePolicyCheck(USBStatus* status, ASTNode* node) {
    cout << "---" << endl;
    cout << "Node Policy Check" << endl;
    cout << "Node overview :" << endl;
    cout << "Node : " << (node != nullptr) << endl;
    if (node == nullptr) throw 1000;
    cout << "Condition : " << (node->condition != nullptr) << endl;
    cout << "IF block : " << (node->ifBlock != nullptr) << endl;
    cout << "EL block : " << (node->elseBlock != nullptr) << endl;
    cout << "Allow Code : " << to_string(node->allowCode) << endl;
    uint8_t out = 0; //Safer to assume invalid unless proved otherwise
    
    try {
        if (node->condition != nullptr) {
            if (CheckCondition(node->condition, status)) out = NodePolicyCheck(status, node->ifBlock);
            else if (node->elseBlock != nullptr) out = NodePolicyCheck(status, node->elseBlock);
        }
        else out = node->allowCode;
    }
    catch (...) {
        cout << "Node Policy Check failed" << endl;
        
    }
    return out;
}

uint8_t DoesUSBMatchPolicy(USBStatus* status, ASTNode* rootNode) {
    /*
        - Policy parameters
            - Owner ex
            - Time ex
            - Known ex
            - VID
            - PID
            - System Mode ex
        - Outs
            - Allow
            - Block
            - Request
        - Default = blocked as this seems logical
    */
    uint8_t out = 0;

    cout << "Step 1 complete" << endl;

    out = NodePolicyCheck(status, rootNode);
    if (out == 0) out = 3; //Safest to deny unless states otehrwise
    cout << "Policy Check results : " << to_string(out) << endl;

    return out;
}

void EjectUSB(string formattedID) {
    //Format goal - USB\VID_1234&PID_5678\SERIAL
    cout << "Formatted ID : " << formattedID << endl;

    //Gemini, not me
    DEVINST devInst;
    CONFIGRET cr = CM_Locate_DevNodeA(&devInst, (DEVINSTID_A)formattedID.c_str(), CM_LOCATE_DEVNODE_NORMAL);

    if (cr == CR_SUCCESS) {
        PNP_VETO_TYPE vetoType = PNP_VetoTypeUnknown;
        CHAR vetoName[MAX_PATH] = {0};

        // 3. Request safe removal
        cr = CM_Request_Device_EjectA(devInst, &vetoType, vetoName, MAX_PATH, 0);

        if (cr == CR_SUCCESS) {
            cout << "[+] Device safely ejected due to policy violation." << endl;
        }
        else {
            // A "veto" means Windows blocked the ejection (e.g., a file is currently open)
            cout << "[-] Failed to eject device. Windows Veto Type: " << vetoType << endl;
        }
    }
    else cout << "Not found " << endl;
}

bool IsReadWrite(string formattedID) {
    bool isReadWrite = false;

    DEVINST devInst;
    CONFIGRET cr = CM_Locate_DevNodeA(&devInst, (DEVINSTID_A)formattedID.c_str(), CM_LOCATE_DEVNODE_NORMAL);
    if (cr == CR_SUCCESS) {
        //AI
        char serviceName[MAX_PATH] = { 0 };
        ULONG len = sizeof(serviceName);

        cr = CM_Get_DevNode_Registry_PropertyA(
            devInst,
            CM_DRP_SERVICE,
            NULL,
            serviceName,
            &len,
            0
        );

        if (cr == CR_SUCCESS) {
            string service(serviceName);
            for (char& c : service) c = toupper(c);
            if (service == "USBSTOR" || service == "UASPSTOR") isReadWrite = true;
        }
    }

    return isReadWrite;
}

//AI
bool RSAVerify(RSA* rsa, const unsigned char* Msg, size_t MsgLen, const unsigned char* Sig, size_t SigLen) {
    EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();
    EVP_PKEY* pubKey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pubKey, rsa);

    bool result = false;
    if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) > 0) {
        if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) > 0) {
            result = (EVP_DigestVerifyFinal(m_RSAVerifyCtx, Sig, SigLen) == 1);
        }
    }

    EVP_PKEY_free(pubKey);
    EVP_MD_CTX_free(m_RSAVerifyCtx);
    return result;
}

void HandleUSB(DEV_BROADCAST_DEVICEINTERFACE* dev, DEV_BROADCAST_VOLUME* readWriteDev) {
    cout << "DBCC NAME : " << dev->dbcc_name << endl;
    uint64_t bufferInt[3] = { 0 };
    string bufferStr[3];
    DBCCParser(bufferInt, bufferStr, dev->dbcc_name);

    string VID = bufferStr[0];
    string PID = bufferStr[1];
    string serial = bufferStr[2];
    string formattedID = "USB\\VID_" + VID + "&PID_" + PID + "\\" + serial;

    string deviceOwner = "UNKNOWN";
    if (readWriteDev != nullptr) {
        //We can try read the read write storage thing
        cout << "Attempting to read device owner" << endl;
        DWORD unitMask = readWriteDev->dbcv_unitmask;
        char volLetter = 'A';

        while (true) {
            if (unitMask & 0x01) break;
            else {
                volLetter++;
                unitMask = unitMask >> 1;
            }
        }

        cout << "Vol letter : " << volLetter << endl;
        string signaturePath = string(1, volLetter) + ":\\signature.sig";
        cout << "Signature path : " << signaturePath << endl;

        //Signature verification
        ifstream fSig;
        fSig.open(signaturePath);
        string signatureBuffer[6];
        string buf;

        int i = 0;
        while (getline(fSig, buf)) {
            signatureBuffer[i] = buf;
            i++;
        }
        fSig.close();

        //Check 1 - is the hash correct
        bool shouldContinue = true;
        string combinedNoHash = signatureBuffer[1] + signatureBuffer[2] + signatureBuffer[3] + signatureBuffer[4];
        string hash = sha256(combinedNoHash);
        if (hash != signatureBuffer[0]) {
            cout << "Hashes do not align" << endl;
            shouldContinue = false;
        }

        //Stripping the buffer stuff of the padding we added
        //Custom strip function beacause this language is afwful
        for (int i = 0; i < 6; i++) {
            string bufferItem = signatureBuffer[i];
            while (bufferItem[bufferItem.length() - 1] == '|') bufferItem = bufferItem.substr(0, bufferItem.length() - 1);
            signatureBuffer[i] = bufferItem;
        }

        //We cannot use the USB for the public key - this must have been sent out of channel - see todo.txt
        //Check 2 - was the signature properly signed
        if (shouldContinue) {
            string ownerPublicKeyPath = knownKeypairsPath + "\\" + signatureBuffer[1] + ".pem";

            cout << "Looking for " << signatureBuffer[1] << " @ " << ownerPublicKeyPath << endl;

            //2.1 - do we know the keypair - if not we can tret it as unknown
            ifstream ownerPublicKeyPem(ownerPublicKeyPath);
            if (!ownerPublicKeyPem.good()) {
                cout << "Owner unknown" << endl;
                shouldContinue = false;
            }
            else {
                RSA *ownerPublic = RSA_new();
                ownerPublic = LoadPublicKey(ownerPublicKeyPath, "");
                cout << "Carrying out verification - testing" << endl;
                cout << "Is owner public nullptr : " << (ownerPublic == nullptr) << endl;

                //2.2 - Is the signature correct
                string combinedWithHash = hash + combinedNoHash;
                vector<unsigned char> signatureBytes = HexToBytes(signatureBuffer[5]);

                bool verified = RSAVerify(
                    ownerPublic,
                    reinterpret_cast<const unsigned char*>(combinedWithHash.c_str()),
                    combinedWithHash.length(),
                    signatureBytes.data(),
                    signatureBytes.size()
                );

                cout << "Verification result " << verified << endl;
                shouldContinue = verified;
            }
            ownerPublicKeyPem.close();
        }

        if (shouldContinue) {
            //We are verified in this case
            cout << "Verfied and fully correct" << endl;
            deviceOwner = signatureBuffer[1];
            cout << "Device owner : " << deviceOwner << endl;
        }
        else {
            //We are not verified
            cout << "Not allowed - verification failed \nEjection imminent" << endl;
            EjectUSB(formattedID);
        }

    }
    
    else cout << "Device owner unknown" << endl;

    //Known systems storage
    fstream f;
    f.open(knownCombinationsFilePath);
    string fileBuffer;
    string name = "";

    while (getline(f, fileBuffer)) {
        if (
            (fileBuffer.substr(0, 04) == VID)
            && (fileBuffer.substr(4, 04) == PID)
            && (fileBuffer.substr(8, 16) == serial)
        ) {
            //We know this device already
            name = fileBuffer.substr(24, string::npos);

            cout << "Name : " << name << endl;
            break;
        }
    }

    if (name == "") {

        cout << "New USB. Name : ";
        cin >> name;
        cout << endl;

        string out = VID + PID + serial + name + "\n";
        cout << "Out : " << out;

        //File nosnesnse
        f.clear();
        f.seekp(0, ios::end);
        f << out;
    }

    f.close();

    //We need to work out how to mesh this with the above code for learning new devices
    USBStatus usbStatus = {
        deviceOwner,
        name != "",
        VID,
        PID,
        systemMode,
        name,
    };

    uint8_t result = DoesUSBMatchPolicy(&usbStatus, &root);
    cout << "Policy Result : " << to_string(result) << endl;

    if (result == 2) {
        cout << "Request for the following device : " << endl;
        cout << "--------------------------------" << endl;
        cout << "Previously known? : ";
        if (usbStatus.known) cout << "True" << endl;
        else cout << "False" << endl;
        cout << "Owner : " << usbStatus.owner << endl;
        cout << "VID : " << VID << endl;
        cout << "PID : " << PID << endl;
        cout << "Serial : " << serial << endl;
        cout << "Name : " << name << endl;
        cout << "--------------------------------" << endl;

        string allowInput;
        cout << "\nAllow? (Y/N) : ";
        cin >> allowInput;
        cout << endl;
        if(!(allowInput == "Y" || allowInput == "y")) EjectUSB(formattedID);
    }
    else if (result == 3) {
        cout << "Denial" << endl;
        EjectUSB(formattedID);
    }
}


void GenerateSignature(RSA*& keypair, string* signatureInfo, string folderPath) {
    cout << "Generating signature" << endl;
    //Data preprocessing
    signatureInfo[0] = PadAndTrimStr(signatureInfo[0], 128);
    signatureInfo[1] = PadAndTrimStr(signatureInfo[1], 128);

    time_t timestamp = time(NULL);
    tm * ptm = gmtime(&timestamp);
    char buffer[32];
    strftime(buffer, sizeof(buffer), "%S%M%H%d%m%Y", ptm);
    signatureInfo[2] = buffer;

    string combinedNoHash = signatureInfo[0] + signatureInfo[1] + signatureInfo[2] + signatureInfo[3];

    string hash = sha256(combinedNoHash);
    cout << "Hash : " << hash << endl;

    string combinedWithHash = hash + combinedNoHash;

    unsigned char* signature = nullptr;
    size_t signatureLen = 0;

    bool result = RSASign(keypair, reinterpret_cast<const unsigned char*>(combinedWithHash.c_str()), combinedWithHash.length(), &signature, &signatureLen);

    string signatureHex = BytesToHex(signature, signatureLen);

    //Writing to output
    /*Structure:
      - Hash
      - Owner
      - Device name, to be used if no other name is registered
      - Timestamp
      - Extra comments
      - Signature
    */
    ofstream f;
    f.open(folderPath + "/signature.sig");
    f << (hash + "\n");
    f << (signatureInfo[0] + "\n");
    f << (signatureInfo[1] + "\n");
    f << (signatureInfo[2] + "\n");
    f << (signatureInfo[3] + "\n");
    f << signatureHex;
    
    f.close();

    //Creating a copy of the public key in the USB section - this will be used for the logs
    FILE* publicKeyFile = fopen((folderPath + "/public.pem").c_str(), "w");
    PEM_write_RSAPublicKey(publicKeyFile, keypair);
    fclose(publicKeyFile);
}

//Windows stuff
vector<DEV_BROADCAST_DEVICEINTERFACE*> buffer = {};

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) { //I think this triggers when a windows thing occurs
    if (msg == WM_DEVICECHANGE) {
        PDEV_BROADCAST_HDR lpHdr = (PDEV_BROADCAST_HDR)lParam;

        switch (wParam) {
        case DBT_DEVICEARRIVAL: //USB was plugged in
            std::cout << "[+] A device was plugged in! ";
            /*
            We have an issue here where the VOLUME send is sent after the INTERFACE one
            However, for my headphones it only sends the INTERFACE, so ew can't wire HandleUSB up to the VOLUME
            The current soloutin is to use a buffer
            */

            if (lpHdr && lpHdr->dbch_devicetype == DBT_DEVTYP_VOLUME) {
                cout << "Test fire" << endl;
                auto readWriteDev = ((DEV_BROADCAST_VOLUME*)lpHdr);
                DEV_BROADCAST_DEVICEINTERFACE* dev = buffer[0];
                buffer.erase(buffer.begin());

                HandleUSB(dev, readWriteDev);
            }

            else if (lpHdr && lpHdr->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE) { //DBT describes plug-and-play stuff
                std::cout << "(USB Interface Detected)\n";
            
                auto dev = ((DEV_BROADCAST_DEVICEINTERFACE*)lpHdr);
                
                uint64_t bufferInt[3] = { 0 };
                string bufferStr[3];
                DBCCParser(bufferInt, bufferStr, dev->dbcc_name);

                string VID = bufferStr[0];
                string PID = bufferStr[1];
                string serial = bufferStr[2];

                string formattedID = "USB\\VID_" + VID + "&PID_" + PID + "\\" + serial;
                bool isReadWrite = IsReadWrite(formattedID);
                cout << "Is read write : " << isReadWrite << endl;
                if (isReadWrite) buffer.push_back(dev);
                else HandleUSB(dev, nullptr);
            }
            else {
                std::cout << "\n";
            }

            break;


        case DBT_DEVICEREMOVECOMPLETE: //USB removed
            std::cout << "[-] A device was removed! ";
            if (lpHdr && lpHdr->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE) {
                std::cout << "(USB Interface Disconnected)\n";
            }
            else {
                std::cout << "\n";
            }
            break;
        }
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

int main() {
    string inputBuffer;

    cout << "Boot Mode : \n1 - Register USB \n2 - CheckUSB \n3 - USB Scanning" << endl;
    cout << "Chosen boot mode : ";
    cin >> inputBuffer;
    if (stoi(inputBuffer) == 1) {
        //Register USB Mode

        //RSA key genreation stuff
        RSA *keypair = RSA_new();

        cout << "Should generate new RSA keypair ? (Y/N) : ";
        cin >> inputBuffer;
        cout << endl;

        if (inputBuffer == "Y" || inputBuffer == "y") GenerateRSAKeys(keypair);
        else {
            cout << "Keypair Folder Path : ";
            cin >> inputBuffer;
            cout << endl;
            
            keypair = LoadPrivateKey(inputBuffer);
        }

        //Signign the file
        /*
        We want to include :
            Hash - 64 characters (hex)
            Owner - 128 characters
            Name - 128 characters
            Timestamp - ssmmHHDDMMYYYY - 14 characters
            - Sum : 334 characters
            Comments - All subsequent characters
                - General informatoin, descriptions etc.
                - Not required
        */
        string signatureInfo[4];
        
        cout << "Owner (max 128 chrs, do not use |) : ";
        cin >> signatureInfo[0];
        cout << endl;

        cout << "Device Name (max 128 chrs, do not use |) : ";
        cin >> signatureInfo[1];
        cout << endl;

        cout << "Extra Comments (not required, no newline characters) : ";
        cin >> signatureInfo[3];
        cout << endl;

        cout << "USB Path : ";
        cin >> inputBuffer;
        cout << endl;


        GenerateSignature(keypair, signatureInfo, inputBuffer);

    }
    else if (stoi(inputBuffer) == 2) {

    }
    else if (stoi(inputBuffer) == 3) {
        //USB Scanning Mode

        cout << "Known Keypairs Path : ";
        cin >> knownKeypairsPath;
        cout << endl;

        cout << "Known Combinations Path : ";
        cin >> knownCombinationsFilePath;
        cout << endl;

        cout << "Policy Path : ";
        cin >> policyPath;
        cout << endl;

        cout << "System Policy Mode : ";
        cin >> inputBuffer;
        cout << endl;
        systemMode = stoi(inputBuffer);

        //Writing the policy

        //Loading in the policy path data
        ifstream f(policyPath);
        string policy;
        string buffer;
        while (getline(f, buffer)) { policy += (buffer + "\n"); }
        f.close();

        //Cleaning up the policy
        size_t pos = policy.find("    ");
        string replace = "    ";
        string replacer = "";
        while (pos != string::npos) {
            policy.replace(pos, replace.size(), replacer);
            pos = policy.find(replace, pos + replacer.size());
        }

        cout << "Policy : " << policy << endl;

        vector<string> policyVector = {};

        buffer = "";
        for (int i = 0; i < policy.length(); i++) {
            if (policy[i] == '\n') {
                if (buffer != "\n" && buffer != "") policyVector.push_back(buffer); //IF statement removes blank lines to keep things llean
                buffer = "";
            }
            else buffer += policy[i];
        }

        //Forming the AST
        FormASTTreeLayer(&root, policyVector);

        cout << "Listening for USB plugin events... Press Ctrl+C to exit.\n\n";

        //The below code was generated by AI and detects USBs being plugged in
        // 1. Register a dummy window class to receive system messages
        WNDCLASS wc = {};
        wc.lpfnWndProc = WndProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.lpszClassName = "USBDetectorClass";
        RegisterClass(&wc);

        // 2. Create a hidden background window
        HWND hwnd = CreateWindowEx(
            0, "USBDetectorClass", "USB Detector",
            0, 0, 0, 0, 0,
            NULL,
            NULL, NULL, NULL
        );

        if (!hwnd) {
            std::cerr << "Failed to create background message window.\n";
            return 1;
        }

        // 3. Register to receive specific notifications for USB Hubs/Devices
        DEV_BROADCAST_DEVICEINTERFACE notificationFilter = {};
        notificationFilter.dbcc_size = sizeof(DEV_BROADCAST_DEVICEINTERFACE);
        notificationFilter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
        notificationFilter.dbcc_classguid = GUID_DEVINTERFACE_USB_DEVICE; // Fires for ALL USB devices

        HDEVNOTIFY hDevNotify = RegisterDeviceNotification(
            hwnd,
            &notificationFilter,
            DEVICE_NOTIFY_WINDOW_HANDLE
        );

        if (!hDevNotify) {
            std::cerr << "Failed to register device notifications. Error: " << GetLastError() << "\n";
            return 1;
        }

        // 4. Standard Windows Message Loop to keep the thread alive and processing
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg); //This calls the WndProc
        }

        // Cleanup when exiting
        UnregisterDeviceNotification(hDevNotify);
        return 0;
    }
}