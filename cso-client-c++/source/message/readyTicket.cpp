#include "..\..\header\message\readyTicket.h"

// ParseBytes converts bytes to ReadyTicket
// Flag is_ready: 1 byte
// Idx Read: 8 bytes
// Mark Read: 4 bytes
// Idx Write: 8 bytes
ReadyTicket::ReadyTicket()
{
	
}

ReadyTicket::~ReadyTicket()
{
}

void ReadyTicket::setIsReady(bool IsReady)
{
	this->IsReady = IsReady;
}

void ReadyTicket::setIdxRead(uint64_t IdxRead)
{
	this->IdxRead = IdxRead;
}

void ReadyTicket::setMaskRead(uint32_t MaskRead)
{
	this->MaskRead = MaskRead;
}

void ReadyTicket::setIdxWrite(uint64_t IdxWrite)
{
	this->IdxWrite = IdxWrite;
}

uint64_t ReadyTicket::getIdxRead()
{
	return IdxRead;
}

uint64_t ReadyTicket::getIsReady()
{
	return  IsReady;
}

uint32_t ReadyTicket::getMaskRead()
{
	return MaskRead;
}

uint64_t ReadyTicket::getIdxWrite()
{
	return IdxWrite;
}

Result<ReadyTicket*> ReadyTicket::parseBytes(uint8_t buffer[], uint64_t sizeData)
{
	Result<ReadyTicket*> result;
	if (sizeData != 21) {
		result.data = nullptr;
		result.errorCode = 1;

		return result;
	}

	uint64_t idxRead = (uint64_t)buffer[8] << 56 | (uint64_t)buffer[7] << 48 | (uint64_t)buffer[6] << 40 | (uint64_t(buffer[5]) << 32) |
		(uint64_t)buffer[4] << 24 | (uint64_t)buffer[3] << 16 | (uint64_t)buffer[2] << 8 |(uint64_t)buffer[1];

	uint32_t maskRead = (uint32_t)buffer[12] << 24 | (uint32_t)buffer[11] << 16 | (uint32_t)buffer[10] << 8 | (uint32_t)buffer[9];
	uint64_t idxWrite =
		(uint64_t)buffer[20] << 56 | (uint64_t)buffer[19] << 48 | (uint64_t)buffer[18] << 40 | (uint64_t)buffer[17] << 32 |
		(uint64_t)buffer[16] << 24 | (uint64_t)buffer[15] << 16 | (uint64_t)buffer[14] << 8 | (uint64_t)buffer[13];

	ReadyTicket* readyTicket =  new ReadyTicket;


	readyTicket->setIsReady(buffer[0] == 1);
	readyTicket->setIdxRead(idxRead);
	readyTicket->setMaskRead(maskRead);
	readyTicket->setIdxWrite(idxWrite);

	result.data = readyTicket;
	result.errorCode = 0;

	return result;
}
