#include "DSP-Client.h"
using boost::asio::ip::tcp;

void sendRequest(tcp::socket& socket, uint16_t code, ClientState& state, const std::string& name, const std::string& key = "", const uint32_t contectSize = 0,
    const uint32_t origFileSize = 0, const uint32_t packetInfo = 0, const std::string& encryptedFile = "") {

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
        addUint32ToBuffer(payload, contectSize);
        addUint32ToBuffer(payload, origFileSize);
        addUint32ToBuffer(payload, packetInfo);
        addStringToBuffer(payload, name, 255);
        addStringToBuffer(payload, name, 0, true);
    }

    header.payloadSize = static_cast<uint32_t>(payload.size());

    buffers.push_back(boost::asio::buffer(&header, sizeof(header)));
    buffers.push_back(boost::asio::buffer(payload));

    boost::asio::write(socket, buffers);
}

void receiveResponse(tcp::socket& socket, uint8_t receivedVersion, uint16_t receivedCode, uint32_t receivedPayloadSize, ClientState& state,
        uint8_t AES_key[] = 0, const uint32_t contectSize = 0, const uint8_t fileName[255] = 0, const uint32_t Cksum = 0) {

    std::vector<uint8_t> headerBuffer(7);
    boost::asio::read(socket, boost::asio::buffer(headerBuffer));

    receivedVersion = headerBuffer[0];
    receivedCode = extractUint16(headerBuffer, 1);
    receivedPayloadSize = extractUint32(headerBuffer, 3);

    if (receivedPayloadSize > 0) {
        std::vector<uint8_t> payloadBuffer(receivedPayloadSize);
        boost::asio::read(socket, boost::asio::buffer(payloadBuffer));

        if (receivedCode == 1600 || receivedCode == 1602 || receivedCode == 1603 || receivedCode == 1604 || receivedCode == 1605 || receivedCode == 1606) {
            if (receivedPayloadSize == 16) {
                for (int i = 0; i < 16; i++) {
                    state.clientID[i] = payloadBuffer[i];
                }
            }
        }   
        if (receivedCode == 1602) {
            int keySize = receivedPayloadSize - 16;
            if (keySize > 0) {
                state.encrypted_aes.resize(keySize);
                for (int i = 0; i < keySize; i++) {
                    state.encrypted_aes[i] = payloadBuffer[16 + i];
                }
            }
        }
    }
}

int main()
{
    std::ifstream meFile("me.info");
    std::string line;
    std::vector<std::string> me_info_content;

    // if me.info exists
    if (meFile.is_open()) {

    }
    // if me.info doesnt exists
    else {
        std::ifstream transferFile("transfer.json");
        std::string serverIP;
        std::string port;
        std::string name;
        int line_counter = 1;

        if (transferFile.is_open()) {
            while (std::getline(transferFile, line)) {
                if (line.find("\"ip\"") != std::string::npos) {
                    serverIP = extractStringValJSON(line);
                }
                else if (line.find("\"port\"") != std::string::npos) {
                    port = extractIntValJSON(line);
                }
                else if (line.find("\"client\"") != std::string::npos) {
                    name = extractStringValJSON(line);
                }
            }

            transferFile.close();

            boost::asio::io_context io_context;
            tcp::socket s(io_context);
            tcp::resolver resolver(io_context);

            boost::asio::connect(s, resolver.resolve(serverIP, port));

            ClientState state;

            sendRequest(s, 825, state, name);

            uint8_t version = 0;
            uint16_t code = 0;
            uint32_t payloadSize = 0;

            receiveResponse(s, version, code, payloadSize, state);

            std::string publicKeyStr = createRSAPairAndReturnPublicKey(state);

            sendRequest(s, 826, state, name, publicKeyStr);

            receiveResponse(s, version, code, payloadSize, state);
            
        }
        else {
            std::cerr << "Error: failed to open transfer.json." << std::endl;
        }


    }

    return 0;
}



std::string extractStringValJSON(std::string& line) {
    int colonPos = line.find(":");

    if (colonPos != std::string::npos) {
        int firstQuotePos = line.find("\"", colonPos);

        if (firstQuotePos != std::string::npos) {
            int secondQuotePos = line.find("\"", firstQuotePos + 1);

            if (secondQuotePos != std::string::npos) {
                return line.substr(firstQuotePos + 1, secondQuotePos - firstQuotePos - 1);
            }
        }
    }

    return "";
}

std::string extractIntValJSON(std::string& line) {
    int colonPos = line.find(":");

    if (colonPos != std::string::npos) {
        int commaPos = line.find(",", colonPos + 1);

        if (commaPos != std::string::npos) {
            return line.substr(colonPos + 2, commaPos - (colonPos + 2));
        }
    }
    return "";
}

void addStringToBuffer(std::vector<uint8_t>& buffer, const std::string& str, size_t size, bool dynamic, bool isBinary) {
    if (dynamic) {
        buffer.insert(buffer.end(), str.begin(), str.end());
    }
    else {
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