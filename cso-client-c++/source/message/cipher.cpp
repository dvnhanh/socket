#include "..\..\header\message\cipher.h"
#include <string>
#include<iostream>
using namespace std;

#define MAX_CONNECTION_NAME_LENGTH 36

Cipher::Cipher() {
    data = nullptr;
    name = nullptr;
}

Cipher::~Cipher() {
    delete[] data;
    delete[] name;
}

void Cipher::setMsgID(uint64_t msgID) {
    this->msgID = msgID;
}

void Cipher::setMsgTag(uint64_t msgTag) {
    this->msgTag = msgTag;
}

void Cipher::setMsgType(MessageType msgType)
{
    this->msgType = msgType;
}

void Cipher::setIsFirst(bool isFirst) {
    this->isFirst = isFirst;
}

void Cipher::setIsLast(bool isLast) {
    this->isLast = isLast;
}

void Cipher::setIsRequest(bool isRequest) {
    this->isRequest = isRequest;
}

void Cipher::setIsEncrypted(bool isEncrypted) {
    this->isEncrypted = isEncrypted;
}

void Cipher::setIV(uint8_t iv[12]) {
    memcpy(this->iv, iv, 12);
}

void Cipher::setSign(uint8_t sign[32]) {
    memcpy(this->sign, sign, 32);
}

void Cipher::setAuthenTag(uint8_t authenTag[16]) {
    memcpy(this->authenTag, authenTag, 16);
}

void Cipher::setName(char* name, uint8_t lenName) {
    this->name = name;
    this->lenName = lenName;
}

void Cipher::setData(uint8_t* data, uint64_t sizeData) {
    this->data = data;
    this->sizeData = sizeData;
}

uint64_t Cipher::getMsgID() {
    return msgID;
}

uint64_t Cipher::getMsgTag() {
    return msgTag;
}

MessageType Cipher::getMsgType() {
    return msgType;
}

bool Cipher::getIsFirst() {
    return isFirst;
}

bool Cipher::getIsLast() {
    return isLast;
}

bool Cipher::getIsRequest()
{
    return isRequest;
}

bool Cipher::getIsEncrypted() {
    return isEncrypted;
}

uint8_t* Cipher::getIV()
{
    return iv;
}

uint8_t* Cipher::getSign() {
    return sign;
}

uint8_t* Cipher::getAuthenTag() {
    return authenTag;
}

char* Cipher::getName() {
    return name;
}

uint8_t Cipher::getLengthName()
{
    return lenName;
}

uint8_t* Cipher::getData() {
    return data;
}

uint64_t Cipher::getSizeData() {
    return sizeData;
}

Result<uint8_t*> Cipher::intoBytes() {
    if (getIsEncrypted()) {
        return buildCipherBytes(
            getMsgID(),
            getMsgTag(),
            getMsgType(),
            getIsFirst(),
            getIsLast(),
            getIsRequest(),
            getName(),
            getLengthName(),
            getIV(),
            getData(),
            getSizeData(),
            getAuthenTag()
        );
    }
    return buildNoCipherBytes(
        getMsgID(),
        getMsgTag(),
        getMsgType(),
        getIsFirst(),
        getIsLast(),
        getIsRequest(),
        getName(),
        getLengthName(),
        getData(),
        getSizeData(),
        getSign()
    );
}

Result<uint8_t*> Cipher::getRawBytes() {
    return buildRawBytes(
        getMsgID(),
        getMsgTag(),
        getMsgType(),
        getIsEncrypted(),
        getIsFirst(),
        getIsLast(),
        getIsRequest(),
        getName(),
        getLengthName(),
        getData(),
        getSizeData()
    );
}

Result<uint8_t*> Cipher::getAad() {
    return buildAad(
        getMsgID(),
        getMsgTag(),
        getMsgType(),
        getIsEncrypted(),
        getIsFirst(),
        getIsLast(),
        getIsRequest(),
        getName(),
        getLengthName()
    );
}

Result<Cipher*> Cipher::parseBytes(uint8_t* buffer, uint64_t size) {
    Result<Cipher*> result;
    uint8_t fixedLen = 10;
    uint8_t posAuthenTag = 10;
    if (size < fixedLen) {
        result.errorCode = 1;
        return result;
    }

    uint8_t flag = buffer[8];
    bool isEncrypted = (flag & 0x80) != 0;

    uint64_t msgID = (uint64_t)buffer[7] << 56 | (uint64_t)buffer[6] << 48 | (uint64_t)buffer[5] << 40 | (uint64_t)buffer[4] << 32 |
        (uint64_t)buffer[3] << 24 | (uint64_t)buffer[2] << 16 | (uint64_t)buffer[1] << 8 | (uint64_t)buffer[0];
    uint8_t lenName = buffer[9];
    uint64_t msgTag = 0;
    if ((flag & 0x08) != 0) {
        fixedLen += 8;
        posAuthenTag += 8;
        if (size < fixedLen) {
            result.errorCode = 1;
            return result;
        }
        msgTag =
            (uint64_t)buffer[17] << 56 | (uint64_t)buffer[16] << 48 | (uint64_t)buffer[15] << 40 | (uint64_t)buffer[14] << 32 |
            (uint64_t)buffer[13] << 24 | ((uint64_t)buffer[12] << 16) | (uint64_t)buffer[11] << 8 | (uint64_t)buffer[10];

    }
    if (isEncrypted) {
        fixedLen += 28; // authenTag (16) + iv (12)
    }
    if (size < (fixedLen + lenName) || lenName == 0 || lenName > MAX_CONNECTION_NAME_LENGTH) {
        result.errorCode = 1;
        return result;
    }
    uint8_t authenTag[16];
    uint8_t iv[12];
    uint8_t sign[32];
    if (isEncrypted) {
        int posIV = posAuthenTag + 16;
        memcpy(authenTag, buffer+posAuthenTag, 16);
        memcpy(iv, buffer+posIV, 12);
    }
    else {
        int posSign = fixedLen;
        fixedLen += 32;
        if (size < (fixedLen + lenName)) {
            result.errorCode = 1;
            return result;
        }
        memcpy(sign, buffer+ posSign, 32);
    }

    // Parse name 
    int posData = fixedLen + lenName;
    char* name = new char[lenName+1];
    if (lenName > 0) {
        name[lenName] = '\0';
        memcpy(name, buffer + fixedLen, lenName); 
    }
    // Parse data
    int lenData = size - posData;
    uint8_t* data = nullptr;

    if (lenData > 0) {
        data = new uint8_t[lenData];
        memcpy(data, buffer+posData, lenData);
    }
    Cipher* cipher = new Cipher();
    cipher->msgID = msgID;
    cipher->msgType = (MessageType)(flag & 0x07);
    cipher->msgTag = msgTag;
    cipher->isFirst = (flag & 0x40) != 0;
    cipher->isLast = (flag & 0x20) != 0;
    cipher->isRequest = (flag & 0x10) != 0;
    cipher->isEncrypted = isEncrypted;
    cipher->setName(name, lenName);
    cipher->setIV(iv);
    cipher->setData(data, lenData);
    cipher->setAuthenTag(authenTag);
    cipher->setSign(sign);

    result.errorCode = 0;
    result.data = cipher;
    return result;
}

Result<uint8_t*> Cipher::buildRawBytes(uint64_t msgID, uint64_t msgTag, MessageType msgType, bool isEncrypted, bool isFirst, bool isLast, bool isRequest, char* name, uint8_t lenName, uint8_t* data, uint64_t sizeData) {
    Result<uint8_t*> result;
    if (lenName == 0 || lenName > MAX_CONNECTION_NAME_LENGTH) {
        result.errorCode = 1;
        return result;
    }
    uint8_t bEncrypted = 0;
    uint8_t bFirst = 0;
    uint8_t bLast = 0;
    uint8_t bRequest = 0;
    uint8_t bUseTag = 0;

    if (isEncrypted) {
        bEncrypted = 1;
    }
    if (isFirst) {
        bFirst = 1;
    }
    if (isLast) {
        bLast = 1;
    }
    if (isRequest) {
        bRequest = 1;
    }

    int fixedLen = 10;
    if (msgTag > 0) {
        bUseTag = 1;
        fixedLen += 8;
    }
    int lenBuffer = fixedLen + lenName + sizeData;
    uint8_t* buffer = new uint8_t[lenBuffer];
     buffer[0] = (uint8_t)(msgID);
     buffer[1] = (uint8_t)(msgID >> 8);
     buffer[2] = (uint8_t)(msgID >> 16);
     buffer[3] = (uint8_t)(msgID >> 24);
     buffer[4] = (uint8_t)(msgID >> 32);
     buffer[5] = (uint8_t)(msgID >> 40);
     buffer[6] = (uint8_t)(msgID >> 48);
     buffer[7] = (uint8_t)(msgID >> 56);
     buffer[8] = (uint8_t)(bEncrypted << 7 | bFirst << 6 | bLast << 5 | bRequest << 4 | bUseTag << 3 | (uint8_t)msgType);
    buffer[9] = ((uint8_t)lenName);

    if (msgTag > 0) {
        buffer[10] = (uint8_t)(msgTag);
        buffer[11] = (uint8_t)(msgTag >> 8);
        buffer[12] = (uint8_t)(msgTag >> 16);
        buffer[13] = (uint8_t)(msgTag >> 24);
        buffer[14] = (uint8_t)(msgTag >> 32);
        buffer[15] = (uint8_t)(msgTag >> 40);
        buffer[16] = (uint8_t)(msgTag >> 48);
        buffer[17] = (uint8_t)(msgTag >> 56);
    }
    memcpy(buffer + fixedLen, name, lenBuffer - fixedLen);
    if (sizeData > 0) {
        memcpy(buffer + (fixedLen + lenName), data, lenBuffer - (fixedLen + lenName));
    }

    result.data = buffer;
    result.errorCode = 0;
    return result;
}

Result<uint8_t*> Cipher::buildAad(uint64_t msgID, uint64_t msgTag, MessageType msgType, bool isEncrypted, bool isFirst, bool isLast, bool isRequest, char* name, uint8_t lenName) {
    Result<uint8_t*> result;
    if (lenName == 0 || lenName > MAX_CONNECTION_NAME_LENGTH) {
        result.data = nullptr;
        result.errorCode = 1;
        return result;
    }
    uint8_t bEncrypted = 0;
    uint8_t bFirst = 0;
    uint8_t bLast = 0;
    uint8_t bRequest = 0;
    uint8_t bUseTag = 0;
    if (isEncrypted) {
        bEncrypted = 1;
    }
    if (isFirst) {
        bFirst = 1;
    }
    if (isLast) {
        bLast = 1;
    }
    if (isRequest) {
        bRequest = 1;
    }

    int fixedLen = 10;
    if (msgTag > 0) {
        bUseTag = 1;
        fixedLen += 8;
    }
    int lenBuffer = fixedLen + lenName;
    uint8_t* buffer = new uint8_t[lenBuffer];
    buffer[0] = (uint8_t)(msgID);
    buffer[1] = (uint8_t)(msgID >> 8);
    buffer[2] = (uint8_t)(msgID >> 16);
    buffer[3] = (uint8_t)(msgID >> 24);
    buffer[4] = (uint8_t)(msgID >> 32);
    buffer[5] = (uint8_t)(msgID >> 40);
    buffer[6] = (uint8_t)(msgID >> 48);
    buffer[7] = (uint8_t)(msgID >> 56);
    buffer[8] = (uint8_t)(bEncrypted << 7 | bFirst << 6 | bLast << 5 | bRequest << 4 | bUseTag << 3 | (uint8_t)msgType);
    buffer[9] = ((uint8_t)lenName);

    if (msgTag > 0) {
        buffer[10] = (uint8_t)(msgTag);
        buffer[11] = (uint8_t)(msgTag >> 8);
        buffer[12] = (uint8_t)(msgTag >> 16);
        buffer[13] = (uint8_t)(msgTag >> 24);
        buffer[14] = (uint8_t)(msgTag >> 32);
        buffer[15] = (uint8_t)(msgTag >> 40);
        buffer[16] = (uint8_t)(msgTag >> 48);
        buffer[17] = (uint8_t)(msgTag >> 56);
    }
    memcpy(buffer + fixedLen, name, lenBuffer - fixedLen);
    result.data = buffer;
    result.errorCode = 0;
    return result;
}

Result<uint8_t*> buildBytes(uint64_t msgID, uint64_t msgTag, MessageType msgType, bool isEncrypted, bool isFirst, bool isLast, bool isRequest, char* name, uint8_t lenName, uint8_t iv[12], uint8_t* data, uint64_t sizeData, uint8_t authenTag[16], uint8_t sign[32]) {
    Result<uint8_t*> result;
    if (lenName == 0 || lenName > MAX_CONNECTION_NAME_LENGTH)
    {
        result.data = nullptr;
        result.errorCode = 1;

        return result;
    }

    uint8_t bEncrypted = 0;
    uint8_t bFirst = 0;
    uint8_t bLast = 0;
    uint8_t bRequest = 0;
    uint8_t bUseTag = 0;
    if (isEncrypted)
    {
        bEncrypted = 1;
    }
    if (isFirst) {
        bFirst = 1;
    }
    if (isLast) {
        bLast = 1;
    }
    if (isRequest) {
        bRequest = 1;
    }

    int fixedLen = 10;
    if (msgTag > 0) {
        bUseTag = 1;
        fixedLen += 8;
    }
    int lenBuffer = fixedLen + 32 + 12 + 16 + lenName + sizeData;
    uint8_t* buffer = new uint8_t[lenBuffer];
    buffer[0] = (uint8_t)(msgID);
    buffer[1] = (uint8_t)(msgID >> 8);
    buffer[2] = (uint8_t)(msgID >> 16);
    buffer[3] = (uint8_t)(msgID >> 24);
    buffer[4] = (uint8_t)(msgID >> 32);
    buffer[5] = (uint8_t)(msgID >> 40);
    buffer[6] = (uint8_t)(msgID >> 48);
    buffer[7] = (uint8_t)(msgID >> 56);
    buffer[8] = (uint8_t)(bEncrypted << 7 | bFirst << 6 | bLast << 5 | bRequest << 4 | bUseTag << 3 | (uint8_t)msgType);
    buffer[9] = ((uint8_t)lenName);

    if (msgTag > 0) {
        buffer[10] = (uint8_t)(msgTag);
        buffer[11] = (uint8_t)(msgTag >> 8);
        buffer[12] = (uint8_t)(msgTag >> 16);
        buffer[13] = (uint8_t)(msgTag >> 24);
        buffer[14] = (uint8_t)(msgTag >> 32);
        buffer[15] = (uint8_t)(msgTag >> 40);
        buffer[16] = (uint8_t)(msgTag >> 48);
        buffer[17] = (uint8_t)(msgTag >> 56);
    }

    int posData = fixedLen + 16;
    if (isEncrypted) {
        memcpy(buffer + fixedLen, authenTag, lenBuffer - fixedLen);
        memcpy(buffer + posData, iv, lenBuffer - posData);
        posData += 12;
    }
    else {
        memcpy(buffer + fixedLen, sign, lenBuffer - fixedLen);
        posData += 32;
    }
    memcpy(buffer + posData, name, lenBuffer - posData);
    posData += lenName;
    if (sizeData > 0) {
        memcpy(buffer + posData, data, lenBuffer - posData);
    }

    result.data = buffer;
    result.errorCode = 0;
    return result;
}

Result<uint8_t*> Cipher::buildCipherBytes(uint64_t msgID, uint64_t msgTag, MessageType msgType, bool isFirst, bool isLast, bool isRequest, char* name, uint8_t lenName, uint8_t iv[12], uint8_t* data, uint64_t sizeData, uint8_t authenTag[16]) {

    return buildBytes(msgID, msgTag, msgType, true, isFirst, isLast, isRequest, name, lenName, iv, data, sizeData, authenTag, nullptr);
}

Result<uint8_t*> Cipher::buildNoCipherBytes(uint64_t msgID, uint64_t msgTag, MessageType msgType, bool isFirst, bool isLast, bool isRequest, char* name, uint8_t lenName, uint8_t* data, uint64_t sizeData, uint8_t sign[32]) {
    return  buildBytes(msgID, msgTag, msgType, false, isFirst, isLast, isRequest, name, lenName, nullptr, data, sizeData, nullptr, sign);
}
                                       












