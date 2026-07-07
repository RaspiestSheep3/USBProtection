// USBProtection.cpp : Defines the entry point for the application.
//

#include "USBProtection.h"

using namespace std;

//System settings
string policyPath;

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

void HandleUSB(DEV_BROADCAST_DEVICEINTERFACE* dev) {
    cout << "DBCC NAME : " << dev->dbcc_name << endl;
    uint64_t bufferInt[3] = { 0 };
    string bufferStr[3];
    DBCCParser(bufferInt, bufferStr, dev->dbcc_name);

    //Known systems storage
    //TODO - encrypt this
    fstream f;
    f.open("KnownCombinations.txt");
    string fileBuffer;
    string name = "";

    while (getline(f, fileBuffer)) {
        if (
                (fileBuffer.substr(0, 04) == bufferStr[0])
            &&  (fileBuffer.substr(4, 04) == bufferStr[1])
            &&  (fileBuffer.substr(8, 16) == bufferStr[2])
            ){
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

        string out = bufferStr[0] + bufferStr[1] + bufferStr[2] + name + "\n";
        cout << "Out : " << out;
        f << out;
    }

    f.close();

}

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
};

string GenerateSubstr(string str, char start, char end) {
    string out = "";
    for (int i = str.find(start) + 1; i < str.length(); i++) {
        if (str[i] == end) break;
        out += str[i];
    }

    return out;
}

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

uint8_t DoesUSBMatchPolicy() {
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
    ASTNode nodeA;
    FormASTTreeLayer(&nodeA, policyVector);

    cout << "Step 1 complete" << endl;

    //!TEMPORARY - TO FIX
    USBStatus testStatus = {
        "TestOwner1",
        true,
        "1234",
        "1234",
        1
    };

    out = NodePolicyCheck(&testStatus, &nodeA);
    if (out == 0) out = 3; //Safest to deny unless states otehrwise
    cout << "Policy Check results : " << to_string(out) << endl;

    return out;
}

//Windows stuff
LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) { //I think this triggers when a windows thing occurs
    if (msg == WM_DEVICECHANGE) {
        PDEV_BROADCAST_HDR lpHdr = (PDEV_BROADCAST_HDR)lParam;

        switch (wParam) {
        case DBT_DEVICEARRIVAL: //USB was plugged in
            std::cout << "[+] A device was plugged in! ";
            if (lpHdr && lpHdr->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE) { //DBT describes plug-and-play stuff
                std::cout << "(USB Interface Detected)\n";

                auto dev = ((DEV_BROADCAST_DEVICEINTERFACE*)lpHdr);

                HandleUSB(dev);
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
    cout << "Policy Path : ";
    cin >> policyPath;

    DoesUSBMatchPolicy();

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
        HWND_MESSAGE, // Makes it a message-only background window
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