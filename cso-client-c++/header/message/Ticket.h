#ifndef _MESSAGE_TICKET_H_
#define _MESSAGE_TICKET_H_
#pragma once
#include<iostream>
#include<cstdint>
#include "result.h"

//  Ticket is information of register connection
class Ticket
{
private:
	uint16_t id;
	uint8_t* token;
	uint64_t lenToken;
public:
	void setId(uint16_t id);
	void setToken(uint8_t* token); 
	void setLenTocken(uint64_t lenToken);

	uint16_t getId();
	uint8_t* getToken();
	uint64_t  getLenToken();

	static Result<Ticket*> parseBytes(uint8_t buffer[], uint64_t sizeData);
	static Result<uint8_t*> buildBytes(uint16_t id, uint8_t* token, uint64_t sizeData);

};
#endif


