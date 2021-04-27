#include "..\..\header\message\Ticket.h"
#include<iostream>
using namespace std;
void Ticket::setId(uint16_t id)
{
	this->id = id;
}

void Ticket::setToken(uint8_t* token)
{
	this->token = token;
}

void Ticket::setLenTocken(uint64_t)
{
	this->lenToken = lenToken;
}

uint16_t Ticket::getId()
{
	return id;
}

uint8_t* Ticket::getToken()
{
	return token;
}

uint64_t Ticket::getLenToken()
{
	return lenToken;
}

// ParseBytes converts bytes to Ticket
// ID: 2 bytes
// Token: next 32 bytes

Result<Ticket*> Ticket::parseBytes(uint8_t buffer[], uint64_t sizeData)
{
	Result<Ticket*> result;
	if (sizeData != 34) {
		result.data = nullptr;
		result.errorCode = 1;

		return result;
	}

	Ticket* ticket = new Ticket();
	uint8_t* token = new uint8_t[sizeData - 2];
	ticket->id = (uint16_t)buffer[1] << 8 | (uint16_t)buffer[0];
	memcpy(token, buffer + 2, sizeData - 2); 
	ticket->setToken(token);

	result.data = ticket;
	result.errorCode = 0;
	return result;
}

// BuildBytes returns bytes of Ticket
Result<uint8_t*> Ticket::buildBytes(uint16_t id, uint8_t* token, uint64_t lenToken)
{
	Result<uint8_t*> result;
	if (lenToken != 32) {
		result.data = nullptr;
		result.errorCode = 1;

		return result;
	}
	uint8_t* buffer = new uint8_t[34];
	buffer[0] = uint8_t(id);
	buffer[1] = uint8_t(id >> 8);

	memcpy(buffer + 2, token, 32); // Size of buffer - 2.
	result.data = buffer;
	result.errorCode = 0;

	return result;
}
