#include "DSP-Client.h"
using boost::asio::ip::tcp;

// Reads transfer.json, authenticates with the server, and uploads all listed files.
int main()
{
    std::string serverIP;
    std::string port;
    std::string name;
    std::vector<std::string> filesToSend;

    std::ifstream transferFile("transfer.json");
    if (!transferFile.is_open()) {
        std::cerr << "Error: failed to open transfer.json." << std::endl;
        return 1;
    }

    std::stringstream rawBuffer;
    rawBuffer << transferFile.rdbuf();
    transferFile.close();

    // Parse server settings and file list from transfer.json
    try {
        std::string cleanJson = fixJsonBackslashes(rawBuffer.str());
        std::stringstream jsonStream(cleanJson);

        boost::property_tree::ptree pt;
        boost::property_tree::read_json(jsonStream, pt);

        if (pt.find("server") != pt.not_found()) {
            serverIP = pt.get<std::string>("server.ip");
            port = pt.get<std::string>("server.port");
            name = pt.get<std::string>("server.client");
        }
        else {
            serverIP = pt.get<std::string>("ip");
            port = pt.get<std::string>("port");
            name = pt.get<std::string>("client");
        }

        if (name.empty() || name.length() > 100) {
            std::cerr << "Error: client name in transfer.json must be between 1 and 100 characters." << std::endl;
            return 1;
        }

        for (const auto& item : pt.get_child("files")) {
            std::string filePath = item.second.get_value<std::string>();
            if (!filePath.empty()) {
                filesToSend.push_back(filePath);
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error parsing transfer.json: " << e.what() << std::endl;
        return 1;
    }

    if (filesToSend.empty()) {
        std::cerr << "Error: No files specified in transfer.json." << std::endl;
        return 1;
    }

    ClientState state;
    for (int i = 0; i < 32; i++) {
        state.aesKey[i] = 0;
    }


    boost::asio::io_context io_context;
    tcp::socket s(io_context);
    tcp::resolver resolver(io_context);

    try {
        boost::asio::connect(s, resolver.resolve(serverIP, port));
        std::cout << "Connected to server " << serverIP << ":" << port << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to connect to server: " << e.what() << std::endl;
        return 1;
    }

    // Attempt reconnection (827) if me.info exists, otherwise attempt registration (825).
    std::ifstream meFile("me.info");
    bool Registered = meFile.is_open();
    if (Registered) {
        int row = 1;
        std::string line;
        std::string privKey = "";

        while (std::getline(meFile, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }

            if (row == 1) {
                if (line.length() > 100) {
                    std::cerr << "clients' name in the file me.info is too long." << std::endl;
                    return 1;
                }
                else {
                    name = line;
                }
            }
            else if (row == 2) {
                try {
                    for (int i = 0; i < 16 && (i * 2 + 1) < line.length(); i++) {
                        std::string byteStr = line.substr(i * 2, 2);
                        state.clientID[i] = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
                    }
                }
                catch (std::exception& e) {
                    std::cerr << "Failed to parse Client ID from me.info: " << e.what() << std::endl;
                    return 1;
                }
            }
            else if (row >= 3) {
                privKey += line;
            }

            row++;
        }
        meFile.close();

        // If private key wasn't in me.info, try reading from priv.key
        if (privKey.empty()) {
            std::ifstream privFile("priv.key");
            if (privFile.is_open()) {
                while (std::getline(privFile, line)) {
                    if (!line.empty() && line.back() == '\r') {
                        line.pop_back();
                    }
                    privKey += line;
                }
                privFile.close();
            }
        }
        if (!privKey.empty()) {
            try {
                CryptoPP::StringSource ss(privKey, true, new CryptoPP::Base64Decoder);
                state.rsapriv.Load(ss);
            }
            catch(std::exception& e) {
                std::cerr << "Failed to load private key from me.info: " << e.what() << std::endl;
                return 1;
            }
        }

        std::cout << "Attempting login (827) as " << name << std::endl;
        sendRequest(s, 827, state, name);
        receiveResponse(s, state);

        if (state.lastReceivedCode == 1606) {
            std::cout << "Reconnection failed (1606), registering as a new user." << std::endl;
            Registered = false;
        }
        else if (state.lastReceivedCode != 1605) {
            std::cerr << "Unexpected server response during login: " << state.lastReceivedCode << std::endl;
            return 1;
        }
    }
    // If me.info doesnt exists or 827 returned 1606, attempt registration
    if (!Registered) {
        std::cout << "Registering new user (825) as " << name << std::endl;
        sendRequest(s, 825, state, name);
        receiveResponse(s, state);

        if (state.lastReceivedCode != 1600) {
            std::cerr << "Registration failed with code: " << state.lastReceivedCode << std::endl;
            return 1;
        }

        std::string publicKeyStr = createRSAPairAndReturnPublicKey(state);

        std::cout << "Sending RSA public key (826)" << std::endl;
        sendRequest(s, 826, state, name, publicKeyStr);
        receiveResponse(s, state);

        if (state.lastReceivedCode != 1602) {
            std::cerr << "Sending public key failed with code: " << state.lastReceivedCode << std::endl;
            return 1;
        }

        saveMeInfo(name, state);
    }

    decryptAESKey(state);

    // Upload each file from transfer.json with up to 4 CRC retry attempts per file
    for (std::string& filePath : filesToSend) {
        std::ifstream testOpen(filePath, std::ios::binary);
        if (!testOpen.is_open()) {
            std::cerr << "Error: Failed to open the file " << filePath << ". Skipping to the next file." << std::endl;
            continue;
        }
        testOpen.close();

        state.fileReceivedSuccessfully = false;

        std::string fileNameOnly = filePath;
        size_t lastSlash = filePath.find_last_of("/\\");
        if (lastSlash != std::string::npos) {
            fileNameOnly = filePath.substr(lastSlash + 1);
        }

        std::cout << "Uploading file " << fileNameOnly << std::endl;
        bool protocolError = false;

        for (int tries = 1; tries <= 4; tries++) {

            if (!encryptFile(filePath, state)) {
                protocolError = true;
                break;
            }

            sendRequest(s, 828, state, fileNameOnly, "", 0x00010000); // 0x00010000 packs packet_number = 0 (lower 16 bits) and total_packets = 1 (upper 16 bits)
            receiveResponse(s, state);

            if (state.lastReceivedCode != 1603) {
                std::cerr << "Server rejected upload of " << fileNameOnly << " with code: " << state.lastReceivedCode << std::endl;
                protocolError = true;
                break;
            }

            if (state.clientCRC == state.lastReceivedCksum)
            {
                state.fileReceivedSuccessfully = true;
                sendRequest(s, 900, state, fileNameOnly);
                break;
            }
            else if (tries < 4) {
                std::cout << "CRC mismatch on attempt " << tries << " for " << fileNameOnly << ", retrying (901)" << std::endl;
                sendRequest(s, 901, state, fileNameOnly);
            }
            else {
                std::cout << "CRC mismatch on final attempt (4) for " << fileNameOnly << ", aborting file (902)" << std::endl;
                sendRequest(s, 902, state, fileNameOnly);
            }

        }

        if (protocolError) {
            continue;
        }

        // Wait for server ACK (1604) after 900 or 902
        receiveResponse(s, state);

        if (state.fileReceivedSuccessfully) {
            std::cout << "The file " << fileNameOnly << " was sent and received successfully (1604)." << std::endl;
        }
        else {
            std::cout << "The file " << fileNameOnly << " was not received successfully (CRC check failed 4 times)." << std::endl;
        }
    }

    return 0;
}


void sendRequest(tcp::socket& socket, uint16_t code, ClientState& state, const std::string& name, const std::string& key, const uint32_t packetInfo) {

    RequestHeader header;

    for (int i = 0; i < 16; i++) {
        header.clientID[i] = (code == 825) ? 0 : state.clientID[i];
    }

    header.version = 3;
    header.code = code;
    std::vector<uint8_t> payload;
    std::vector<boost::asio::const_buffer> buffers;

    if (code == 825 || code == 827 || code == 900 || code == 901 || code == 902) {
        addStringToBuffer(payload, name, 255);

    }
    else if (code == 826) {
        addStringToBuffer(payload, name, 255);
        addStringToBuffer(payload, key, 160, false, true);
    }
    else if (code == 828) {
        addUint32ToBuffer(payload, state.encrypted_file.size());
        addUint32ToBuffer(payload, state.origFileSize);
        addUint32ToBuffer(payload, packetInfo);
        addStringToBuffer(payload, name, 255);
        addFileDataToBuffer(payload, state.encrypted_file);
    }

    header.payloadSize = static_cast<uint32_t>(payload.size());

    buffers.push_back(boost::asio::buffer(&header, sizeof(header)));
    buffers.push_back(boost::asio::buffer(payload));

    boost::asio::write(socket, buffers);
}


void receiveResponse(tcp::socket& socket, ClientState& state) {

    std::vector<uint8_t> headerBuffer(7);
    boost::asio::read(socket, boost::asio::buffer(headerBuffer));

    state.lastReceivedVersion = headerBuffer[0];
    state.lastReceivedCode = extractUint16(headerBuffer, 1);
    state.lastReceivedPayloadSize = extractUint32(headerBuffer, 3);

    if (state.lastReceivedPayloadSize > 0) {
        std::vector<uint8_t> payloadBuffer(state.lastReceivedPayloadSize);
        boost::asio::read(socket, boost::asio::buffer(payloadBuffer));

        uint16_t code = state.lastReceivedCode;

        if (code == 1600 || code == 1602 || code == 1603 || code == 1604 || code == 1605 || code == 1606) {
            if (state.lastReceivedPayloadSize >= 16) {
                for (int i = 0; i < 16; i++) {
                    state.clientID[i] = payloadBuffer[i];
                }
            }
        }
        if (code == 1602 || code == 1605) {
            int keySize = state.lastReceivedPayloadSize - 16;
            if (keySize > 0) {
                state.encrypted_aes.resize(keySize);
                for (int i = 0; i < keySize; i++) {
                    state.encrypted_aes[i] = payloadBuffer[16 + i];
                }
            }
        }
        else if (code == 1603) {
            if (state.lastReceivedPayloadSize >= 279) {
                state.lastReceivedContentSize = extractUint32(payloadBuffer, 16);

                state.lastReceivedFileName = "";
                for (int i = 0; i < 255; i++) {
                    if (payloadBuffer[20 + i] == '\0') {
                        break;
                    }
                    state.lastReceivedFileName.push_back(payloadBuffer[20 + i]);
                }

                state.lastReceivedCksum = extractUint32(payloadBuffer, 275);
            }
        }
    }
}


void addStringToBuffer(std::vector<uint8_t>& buffer, const std::string& str, size_t size, bool dynamic, bool isBinary) {
    if (dynamic) {
        buffer.insert(buffer.end(), str.begin(), str.end());
    }
    else {
        // Save at least 1 byte for the null terminator on ASCII strings
        size_t maxSize = (isBinary) ? size : size - 1;
        size_t copySize = std::min(str.size(), maxSize);
        buffer.insert(buffer.end(), str.begin(), str.begin() + copySize);
        size_t nullsSize = size - copySize;
        buffer.insert(buffer.end(), nullsSize, 0);
    }
}

void addUint32ToBuffer(std::vector<uint8_t>& buffer, uint32_t value) {
    buffer.push_back(value & 0xFF);
    buffer.push_back((value >> 8) & 0xFF);
    buffer.push_back((value >> 16) & 0xFF);
    buffer.push_back((value >> 24) & 0xFF);
}

void addFileDataToBuffer(std::vector<uint8_t>& buffer, std::vector<uint8_t>& data) {
    buffer.insert(buffer.end(), data.begin(), data.end());
}

uint16_t extractUint16(std::vector<uint8_t>& buffer, uint16_t offset) {
    return (uint16_t)buffer[offset] | ((uint16_t)buffer[offset + 1] << 8);
}

uint32_t extractUint32(std::vector<uint8_t>& buffer, uint32_t offset) {
    return (uint32_t)buffer[offset] | ((uint32_t)buffer[offset + 1] << 8) | ((uint32_t)buffer[offset + 2] << 16) | ((uint32_t)buffer[offset + 3] << 24);
}

std::string createRSAPairAndReturnPublicKey(ClientState& state) {
    CryptoPP::AutoSeededRandomPool rng;
    state.rsapriv.GenerateRandomWithKeySize(rng, 1024);
    CryptoPP::RSA::PublicKey publicKey(state.rsapriv);

    std::string publicKeyStr;
    CryptoPP::StringSink ss(publicKeyStr);
    publicKey.Save(ss);

    return publicKeyStr;
}

void decryptAESKey(ClientState& state) {
    try {
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(state.rsapriv);

        std::string decryptedKey;

        CryptoPP::StringSource s(state.encrypted_aes.data(), state.encrypted_aes.size(), true
            , new CryptoPP::PK_DecryptorFilter(rng, decryptor, new CryptoPP::StringSink(decryptedKey)));

        if (decryptedKey.size() == 32) {
            for (int i = 0; i < 32; i++) {
                state.aesKey[i] = decryptedKey[i];
            }
        }
        else {
            std::cerr << "Decryption failed, decrypted key size is " << decryptedKey.size() << std::endl;
        }
    }
    catch (std::exception& e) {
        std::cerr << "Decryption failed: " << e.what() << std::endl;
    }
}

bool encryptFile(std::string& path, ClientState& state) {
    state.encrypted_file.clear();

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << path << std::endl;
        return false;
    }

    std::vector<uint8_t> fileData((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    if (fileData.empty()) {
        std::cerr << "File is empty: " << path << std::endl;
        return false;
    }

    state.origFileSize = static_cast<uint32_t>(fileData.size());
    state.clientCRC = memcrc(reinterpret_cast<char*>(fileData.data()), fileData.size());

    std::cout << "Local CRC calculated: " << state.clientCRC << std::endl;

    try {
        uint8_t IV[16];
        for (int i = 0; i < 16; i++) {
            IV[i] = 0;
        }

        CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(state.aesKey, 32, IV);

        state.encrypted_file.clear();

        CryptoPP::VectorSource v(fileData, true, new CryptoPP::StreamTransformationFilter(encryptor, new CryptoPP::VectorSink(state.encrypted_file)));
    }
    catch (const std::exception& e) {
        state.encrypted_file.clear();
        std::cerr << "File encryption failed: " << e.what() << std::endl;
        return false;
    }

    return true;
}

unsigned long memcrc(char* b, size_t n) {
    unsigned int v = 0, c = 0;
    unsigned long s = 0;
    unsigned int tabidx;

    for (int i = 0; i < n; i++) {
        tabidx = (s >> 24) ^ (unsigned char)b[i];
        s = UNSIGNED((s << 8)) ^ crctab[0][tabidx];
    }

    while (n) {
        c = n & 0377;
        n = n >> 8;
        s = UNSIGNED(s << 8) ^ crctab[0][(s >> 24) ^ c];
    }
    return (unsigned long)UNSIGNED(~s);
}

void saveMeInfo(const std::string& name, ClientState& state) {
    std::string base64PrivKey;
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(base64PrivKey), false);
    state.rsapriv.Save(encoder);
    encoder.MessageEnd();

    std::ofstream outMe("me.info");
    if (outMe.is_open()) {
        outMe << name << std::endl;

        for (int i = 0; i < 16; i++) {
            outMe << std::hex << std::setw(2) << std::setfill('0') << (int)state.clientID[i];
        }
        outMe << std::dec << std::endl;
        outMe << base64PrivKey << std::endl;
        outMe.close();
    }

    std::ofstream outPriv("priv.key");
    if (outPriv.is_open()) {
        outPriv << base64PrivKey << std::endl;
        outPriv.close();
    }
}


std::string fixJsonBackslashes(const std::string& rawJson) {
    std::string out;
    out.reserve(rawJson.size() * 2);
    for (size_t i = 0; i < rawJson.size(); ++i) {
        if (rawJson[i] == '\\') {
            if (i + 1 < rawJson.size() && (rawJson[i + 1] == '\\' || rawJson[i + 1] == '\"' || rawJson[i + 1] == '/')) {
                out += rawJson[i];
                out += rawJson[i + 1];
                ++i;
            }
            else {
                out += "\\\\";
            }
        }
        else {
            out += rawJson[i];
        }
    }
    return out;
}