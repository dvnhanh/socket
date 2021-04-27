#ifndef _MESSAGE_READY_TICKET_H_
#define _MESSAGE_READY_TICKET_H_
#pragma once
#include<iostream>
#include <stdint.h>
#include "type.h"
#include "result.h"


// ReadyTicket is information of ready ticket
class ReadyTicket
{
private:
	 bool IsReady;
	 uint64_t IdxRead;
	 uint32_t MaskRead;
	 uint64_t IdxWrite;
public:
	ReadyTicket();
	~ReadyTicket();

	void setIsReady(bool IsReady);
	void setIdxRead(uint64_t IdxRead);
	void setMaskRead(uint32_t MaskRead);
	void setIdxWrite(uint64_t IdxWrite);

	uint64_t getIdxRead();
	uint64_t getIsReady();
	uint32_t getMaskRead();
	uint64_t getIdxWrite();
	static Result<ReadyTicket*> parseBytes(uint8_t buffer[], uint64_t sizeData);
};
#endif

