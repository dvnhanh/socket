#include "..\..\header\message\cipher.h"
#include "..\..\header\message\readyTicket.h"
#include "..\..\header\message\type.h"
#include "..\..\header\message\Ticket.h"
#include <stdlib.h>
#include <time.h>
#include<iostream>
#define max 20

using namespace std;

char gConnName[] = "goldeneye_technologies";
char name[] = "Goldeneye Technologies";

// set up test.
uint64_t sizeGConnName = 22; 
uint64_t sizeName = 22;

uint8_t* testName(char name[]) {
	uint8_t* arr = new uint8_t[sizeName];

	for (int i = 0; i < 23; i++) {
		arr[i] = int(name[i]);
	}
	return arr;
}

void testBuildRawBytes() {
	Result<uint8_t*> result;
	uint8_t expectedRawBytes[]{ 0, 4, 0, 0, 0, 0, 0, 0, 251, 22, 1, 4, 0, 0, 0, 0, 0, 0, 103, 111, 108, 100, 101, 110, 101, 121, 101, 95, 116, 101, 99, 104, 110, 111, 108, 111, 103, 105, 101, 115, 71, 111, 108, 100, 101, 110, 101, 121, 101, 32, 84, 101, 99, 104, 110, 111, 108, 111, 103, 105, 101, 115 };
	result = Cipher::buildRawBytes(
		1024,
		1025,
		Single,
		true,
		true,
		true,
		true,
		gConnName,
		sizeGConnName,
		testName(name),
		sizeName
	);
	if (result.errorCode != 0) {
		cout << "[TestBuildRawBytes] get raw bytes failed\n";
	}
	
	for (int i = 0; i < 62; i++) {
		if (expectedRawBytes[i] != result.data[i]) {
			cout << "[TestBuildRawBytes] invalid RawBytes\n";
			break;
		}
	}
}

void testParseCipherBytes() {
	// Cipher
	bool expectedIsEncrypted = true;
	bool expectedIsFirst = true;
	bool expectedIsLast = true;
	 bool expectedIsRequest = true;
	 uint64_t expectedMessageID = 1024;
	 uint64_t expectedMessageTag = 1025;
	 int	expectedMessageType = Single;
	 char* expectedName = gConnName;
	// expectedSign := TypeSingle
	 uint8_t epxectedIV[]{52, 69, 113, 36, 207, 171, 168, 50, 162, 40, 224, 187};
	uint8_t epxectedAuthenTag[]{106, 232, 205, 181, 53, 106, 177, 50, 190, 131, 144, 7, 101, 44, 27, 45};
	uint8_t* expectedData = testName(name);

	 uint8_t expectedAad[]{0, 4, 0, 0, 0, 0, 0, 0, 251, 22, 1, 4, 0, 0, 0, 0, 0, 0, 103, 111, 108, 100, 101, 110, 101, 121, 101, 95, 116, 101, 99, 104, 110, 111, 108, 111, 103, 105, 101, 115};

	uint8_t input[]{0, 4, 0, 0, 0, 0, 0, 0, 251, 22, 1, 4, 0, 0, 0, 0, 0, 0, 106, 232, 205, 181, 53, 106, 177, 50, 190, 131, 144, 7, 101, 44, 27, 45, 52, 69, 113, 36, 207, 171, 168, 50, 162, 40, 224, 187, 103, 111, 108, 100, 101, 110, 101, 121, 101, 95, 116, 101, 99, 104, 110, 111, 108, 111, 103, 105, 101, 115, 71, 111, 108, 100, 101, 110, 101, 121, 101, 32, 84, 101, 99, 104, 110, 111, 108, 111, 103, 105, 101, 115};

	Result<Cipher*> result;
	result = Cipher::parseBytes(input, 91);

	if ( result.errorCode !=0){
		cout << "[TestParseCipherBytes] parse bytes failed\n";
	}
	if (result.data->getIsEncrypted() != expectedIsEncrypted){
		cout << "[TestParseCipherBytes] invalid property IsEncrypted\n";
	}
	if (result.data->getIsFirst() != expectedIsFirst){
		cout <<"[TestParseCipherBytes] invalid property IsFirst\n"; 
	}
	if (result.data->getIsLast() != expectedIsLast){
		cout << "[TestParseCipherBytes] invalid property IsLast\n";
	}
	if (result.data->getIsRequest() != expectedIsRequest){
		cout << "[TestParseCipherBytes] invalid property IsRequest\n";
	}
	if (result.data->getMsgID() != expectedMessageID){
		cout << "[TestParseCipherBytes] invalid property MessageID\n";
	}

	if (result.data->getMsgTag() != expectedMessageTag){
		cout << "[TestParseCipherBytes] invalid property MessageTag\n";
	}
	if (int(result.data->getMsgType()) != expectedMessageType) {
		cout << "[TestParseCipherBytes] invalid property MessageType\n";
	}
	if (result.data->getLengthName() != sizeName) {
		cout << "[TestParseCipherBytes] invalid property Name\n";
	}
	for (int i = 0; i < result.data->getLengthName(); i++) {
		if (result.data->getName()[i] != expectedName[i]) {
			cout << "[TestParseCipherBytes] invalid property Name\n";
			break;
		}
	}
	for (int i = 0; i < 12; i++) {
		if (result.data->getIV()[i] != epxectedIV[i]) {
			cout << "[TestParseCipherBytes] invalid property IV\n";
			break;
		}
	}
	for (int i = 0; i < 16; i++) {
		if (result.data->getAuthenTag()[i] != epxectedAuthenTag[i]) {
			cout << "[TestParseCipherBytes] invalid property AuthenTag\n";
			break;
		}
	}					
}

void testReadyTicketParse() {
	uint8_t input[]{ 1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255 };
	 
	Result<ReadyTicket*> result;
	result = ReadyTicket::parseBytes(input , 21);

  
	if (result.errorCode != 0 ){
		cout << "[TestParseBytes] parse bytes failed";
	}
	if (result.data->getIsReady() == false) {
		cout << "[TestParseBytes] invalid property IsReady";
	}
	if (result.data->getIdxRead() != 18446744073709551615) {
		cout << "[TestParseBytes] invalid property IdxRead";
	}
	if (result.data->getMaskRead() != 4294967295) {
		cout << "[TestParseBytes] invalid property MaskRead";
	}
	if (result.data->getIdxWrite()!= 18446744073709551614) {
		cout << "[TestParseBytes] invalid property IdxWrite";
	}

	uint8_t input1[]{ 0, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255 };
	result = ReadyTicket::parseBytes(input1, 21);
	if (result.errorCode != 0){
		cout << "[TestParseBytes] parse bytes failed";
	}
	if (result.data->getIsReady() == true) {
		cout << "[TestParseBytes] invalid property IsReady";
	}
	if (result.data->getIdxRead() != 18446744073709551614) {
		cout << "[TestParseBytes] invalid property IdxRead";
	}
	if (result.data->getMaskRead() != 4294967295) {
		cout << "[TestParseBytes] invalid property MaskRead";
	}
	if (result.data->getIdxWrite() != 18446744073709551615) {
		cout << "[TestParseBytes] invalid property IdxWrite";
	}
}

void testParseNoCipherBytes() {
	// Cipher
	bool expectedIsEncrypted = false;
	bool expectedIsFirst = true;
	bool expectedIsLast = true;
	bool expectedIsRequest = true;
	uint64_t expectedMessageID = 1024;
	uint64_t expectedMessageTag = 1025;
	int	expectedMessageType = Single;
	char* expectedName = gConnName;
	// expectedSign := TypeSingle
	uint8_t epxectedSign[]{ 140, 57, 139, 30, 167, 65, 206, 46, 33, 131, 181, 152, 42, 206, 205, 79, 59, 223, 16, 25, 61, 95, 68, 163, 49, 147, 106, 188, 66, 151, 202, 88 };
	uint8_t* expectedData = testName(name);

	uint8_t expectedAad[]{ 0, 4, 0, 0, 0, 0, 0, 0, 123, 22, 1, 4, 0, 0, 0, 0, 0, 0, 103, 111, 108, 100, 101, 110, 101, 121, 101, 95, 116, 101, 99, 104, 110, 111, 108, 111, 103, 105, 101, 115 };

	uint8_t input[]{ 0, 4, 0, 0, 0, 0, 0, 0, 123, 22, 1, 4, 0, 0, 0, 0, 0, 0, 140, 57, 139, 30, 167, 65, 206, 46, 33, 131, 181, 152, 42, 206, 205, 79, 59, 223, 16, 25, 61, 95, 68, 163, 49, 147, 106, 188, 66, 151, 202, 88, 103, 111, 108, 100, 101, 110, 101, 121, 101, 95, 116, 101, 99, 104, 110, 111, 108, 111, 103, 105, 101, 115, 71, 111, 108, 100, 101, 110, 101, 121, 101, 32, 84, 101, 99, 104, 110, 111, 108, 111, 103, 105, 101, 115 };

	Result<Cipher*> result;
	result = Cipher::parseBytes(input, 94);

	if (result.errorCode != 0) {
		cout << "[TestParseCipherBytes] parse bytes failed\n";
	}
	if (result.data->getIsEncrypted() != expectedIsEncrypted) {
		cout << "[TestParseCipherBytes] invalid property IsEncrypted\n";
	}
	if (result.data->getIsFirst() != expectedIsFirst) {
		cout << "[TestParseCipherBytes] invalid property IsFirst\n";
	}
	if (result.data->getIsLast() != expectedIsLast) {
		cout << "[TestParseCipherBytes] invalid property IsLast\n";
	}
	if (result.data->getIsRequest() != expectedIsRequest) {
		cout << "[TestParseCipherBytes] invalid property IsRequest\n";
	}
	if (result.data->getMsgID() != expectedMessageID) {
		cout << "[TestParseCipherBytes] invalid property MessageID\n";
	}

	if (result.data->getMsgTag() != expectedMessageTag) {
		cout << "[TestParseCipherBytes] invalid property MessageTag\n";
	}
	if (int(result.data->getMsgType()) != expectedMessageType) {
		cout << "[TestParseCipherBytes] invalid property MessageType\n";
	}
	if (result.data->getLengthName() != sizeName) {
		cout << "[TestParseCipherBytes] invalid property Name\n";
	}
	for (int i = 0; i < result.data->getLengthName(); i++) {
		if (result.data->getName()[i] != expectedName[i]) {
			cout << "[TestParseCipherBytes] invalid property Name\n";
			break;
		}
	}

	for (int i = 0; i < 32; i++) {
		if (result.data->getSign()[i] != epxectedSign[i]) {
			cout << "[TestParseCipherBytes] invalid property sign\n";
			break;
		}
	}

	if (result.data->getAad().errorCode != 0){
		cout << "[TestParseNoCipherBytes] get aad failed";
	}
	for (int i = 0; i < sizeName; i++) {
		if (result.data->getAad().data[i] != expectedAad[i]) {
			cout << "[TestParseCipherBytes] invalid property Aad\n";
			break;
		}
	}

	for (int i = 0; i < sizeName; i++) {
		if (result.data->getData()[i] != expectedData[i]) {
			cout << "[TestParseCipherBytes] invalid property data\n";
			break;
		}
	}
}

void testBuildAad() {
	Result<uint8_t*> result;
	uint8_t expectedAad[]{ 0, 4, 0, 0, 0, 0, 0, 0, 251, 22, 1,
		4, 0, 0, 0, 0, 0, 0, 103, 111, 108, 100,
		101, 110, 101, 121, 101, 95, 116, 101, 99, 104,
		110, 111, 108, 111, 103, 105, 101, 115 };
	result = Cipher::buildAad(
		1024,
		1025,
		Single,
		true,
		true,
		true,
		true,
		gConnName,
		sizeGConnName
	);
	if (result.errorCode != 0) {
		cout << "[TestBuildAad] build aad failed\n";
	}
	for (int i = 0; i < 40 ; i++) {
		if (expectedAad[i] != result.data[i])
			cout << "[TestBuildAad] invalid Aad\n";
	}
	/*Cipher*(*runcase) (
		uint64_t,
		uint64_t,
		MessageType,
		uint8_t[],
		uint8_t*,
		uint64_t,
		uint8_t[],
		uint8_t sign[],
		bool,
		bool,
		bool,
		bool
		) = runner;
	runcases(runcase);*/
}

void testTicketParseBytes() {
	uint8_t  expectedToken[]{ 213, 132, 113, 225, 37, 37, 160, 13, 148, 229, 56, 218, 115, 1, 210, 66, 139, 49, 12, 110, 98, 125, 191, 231, 51, 72, 235, 166, 185, 76, 66, 238 };
	uint8_t input[]{ 255, 255, 213, 132, 113, 225, 37, 37, 160, 13, 148, 229, 56, 218, 115, 1, 210, 66, 139, 49, 12, 110, 98, 125, 191, 231, 51, 72, 235, 166, 185, 76, 66, 238 };
	Result<Ticket*> result;
	result = Ticket::parseBytes(input, 34);
	if  (result.errorCode != 0){
		cout << "[TestParseBytes] parse bytes failed";
	}
	if (result.data->getId() != 65535) {
		cout << "[TestParseBytes] invalid ID";
	}

	for (int i = 0; i < 32; i++) {
		if (result.data->getToken()[i] != expectedToken[i]){
			cout << "[TestParseBytes] invalid Token\n";
		}
	}
	
}

void main() {
	testBuildRawBytes();
	testParseCipherBytes();
	testBuildAad();
	testParseNoCipherBytes();
	testReadyTicketParse();
	testTicketParseBytes();
}



