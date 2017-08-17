/*
* DLLMain.cpp is the code for the custom password filter that is to be utilised by
* LSA to check the validity of password requests.
* The DLL binary searches through over 330 million locally stored hashes
* and subsequently selects
* whether or not the password is valid, based on whether or not it exists as a
* previously breached password.
* Content Author:  JacksonVD
* Contact: jacksonvd.com
* Date Written:    17-08-17
*/

// Various includes - includes sha.h, filters.h and hex.h from Crypto++

#include "stdafx.h"
#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <SubAuth.h>
#include <string>
#include <iostream>
#include <fstream>
#include <cstring>
#include <algorithm>
#include <sha.h>
#include <filters.h>
#include <hex.h>


using namespace std;

#pragma comment(lib, "Ws2_32.lib")


// Visual Studio DLL Boilerplate

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}


std::string GetRecord(std::ifstream& inFile, int pos)
{
	// Create buffer character array of SHA1 hash length + 1
	char buffer[41] = { 0 };
	// Clear possible flags in the stream
	inFile.clear();
	// Set the stream to the reuired position
	inFile.seekg(((long long)(pos) * 42), std::ios::beg);
	inFile.clear();
	// Ignore the new line character
	inFile.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
	// Read 40 char into buffer
	inFile.read(buffer, 40);

	// Return buffer as a string
	return buffer;
}

/*
* This function will be called by LSA - the function imports calling account information, including the prospective password
* and exports a Boolean value (either TRUE or FALSE). This return value is then used by LSA in determining whether or not
* the password has passed the in-place password policy. 
*/

extern "C" __declspec(dllexport) BOOLEAN __stdcall PasswordFilter(PUNICODE_STRING accountName,
	PUNICODE_STRING fullName,
	PUNICODE_STRING password,
	BOOLEAN operation) {
	// Declare and initialise the returnValue Boolean expresion as false by default
	BOOLEAN passwordMatch = TRUE;

	// Long and convoluted way of getting password String from PUNICODE_STRING
	std::wstring wStrBuffer(password->Buffer, password->Length / sizeof(WCHAR));
	const wchar_t *wideChar = wStrBuffer.c_str();
	std::wstring wStr(wideChar);
	std::string str(wStr.begin(), wStr.end());

	// Generate an SHA1 hash of the requesting password string through Crypto++
	CryptoPP::SHA1 sha1;
	std::string hash = "";
	CryptoPP::StringSource(str, true, new CryptoPP::HashFilter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));

	// String array of the file names + locations - you may customise if you wish
	string str1[3] = { "C:\\pwned-passwords-1.0.txt", "C:\\pwned-passwords-update-1.txt", "C:\\pwned-passwords-update-2.txt" };
	string SearchVal = hash;
	int ii = 0;
	// do-while loop to iterate through the files while not found
		do
		{
			// Create a file stream, reading the current file as a binary file, starting from the end
			ifstream file(str1[ii].c_str(), ios::binary | ios::ate);
			int lower = 0;

			// Get the number of bytes in the file
			std::fstream::pos_type bytes = file.tellg();
			file.clear();

			// Get total passwords by dividing by SHA length + 2 - 1
			int totalPasswords = (bytes / 42) - 1;


			int upper = totalPasswords;

			// Classic Binary Search function
			while (lower <= upper) 
			{
				// Set the middle of stream to the lower + upper + 1, all divided by 2
				auto pos = (lower + upper + 1) / 2;
				// Set buffer string to return value from GetRecord function
				std::string buffer2 = GetRecord(file, pos);

				// If the two values are equal..
				if (SearchVal.compare(buffer2) == 0)
				{
					// Set the lower and upper bounds to 1 and 0 respectively, to stop searching
					lower = 1; 
					upper = 0; 
					// Set passwordMatch boolean to false - password found
					passwordMatch = FALSE;
				}
				// If the requesting password hash is greater than the current hash
				else if (SearchVal.compare(buffer2) > 0)
				{
					// Set lower equal to the middle value + 1
					lower = pos + 1;
				}
				// If the requesting password hash is lower than the current hash
				else if (SearchVal.compare(buffer2) < 0)
				{
					// Set upper equal to the middle value - 1
					upper = pos - 1;
				}

			}
			// Iterate ii to change the file count
			ii++;
		} while (passwordMatch && ii < 3);

	// Return passwordMatch Boolean to LSA
	return passwordMatch;

}