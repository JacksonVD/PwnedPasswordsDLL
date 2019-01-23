/*
* DLLMain.cpp is the code for the custom password filter that is to be utilised by
* LSA to check the validity of password requests.
* The DLL binary searches through over 517 million locally stored hashes
* and subsequently selects
* whether or not the password is valid, based on whether or not it exists as a
* previously breached password.
* Content Author:  Jackson Van Dyke
* Contact: jacksonvd.com
* Date Written:    17-08-17
* Last Modified: 23-01-19
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

#include <sha.h>
#include <filters.h>
#include <hex.h>

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

/*
 * Function to return the current record from the text file being read by the PasswordFilter function 
 */

std::string getRecord(std::ifstream& inFile, int position)
{
	// Create buffer character array of SHA1 hash length + 1
	char buffer[41] = { 0 };
	// Clear possible flags in the stream
	inFile.clear();

	// Set the stream to the required position
	inFile.seekg(((long long)(position) * 42), inFile.beg);
	inFile.clear();

	// Ignore the new line character
	inFile.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');

	// Read 40 chararacters into the buffer string
	inFile.read(buffer, 40);

	std::string strBuffer(buffer);

	// Return buffer as a string
	return strBuffer;
}

/*
* This function will be called by LSA - the function imports calling account information, including the prospective password
* and exports a Boolean value (either TRUE or FALSE). This return value is then used by LSA in determining whether or not
* the password has passed the in-place password policy. 
*/

extern "C" __declspec(dllexport) BOOLEAN __stdcall PasswordFilter(PUNICODE_STRING accountName,
	PUNICODE_STRING fullName,
	PUNICODE_STRING password,
	BOOLEAN operation)
{
	// Declare and initialise the returnValue Boolean expresion as false by default
	BOOLEAN passwordNotFound = TRUE;

	// Long and convoluted way of getting password String from PUNICODE_STRING
	std::wstring wStrBuffer(password->Buffer, password->Length / sizeof(WCHAR));
	const wchar_t *wideChar = wStrBuffer.c_str();
	std::wstring wStr(wideChar);
	std::string pwdString(wStr.begin(), wStr.end());
	std::string hash;

	// Generate an SHA1 hash of the requesting password string through Crypto++
	CryptoPP::SHA1 sha1;
	CryptoPP::StringSource(pwdString, true, new CryptoPP::HashFilter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));
	
	// String array of the file names + locations - you may customise if you wish
	// If you wish to use the original 3 files, define files as so, and comment out the new files value. I've finally got around to updating this for the current version (v3)!
	// std::string files[3] = { "C:\\pwned-passwords-1.0.txt", "C:\\pwned-passwords-update-1.txt", "C:\\pwned-passwords-update-2.txt" };
	std::string files[1] = { "C:\\pwnedpasswords\\pwned-passwords-ordered-by-hash.txt" };
	std::string searchValue = hash;
	int ii = 0;

	// Do-while loop to iterate through the files while not found
	do
	{
		// Create a file stream, reading the current file as a binary file, starting from the end
		std::ifstream file(files[ii].c_str(), std::ios::binary | std::ios::ate);
		int lower = 0;

		// Get the number of bytes in the file
		std::fstream::pos_type bytes = file.tellg();
		file.clear();

		// Get total passwords by dividing by SHA length + 2 - 1
		int totalPasswords = (bytes / 42) - 1;

		int upper = totalPasswords;

		// Binary search function
		while (lower <= upper) 
		{
			// Set the middle of stream to the lower + upper + 1, all divided by 2
			auto position = (lower + upper + 1) / 2;

			// Set buffer string to return value from GetRecord function
			std::string buffer = getRecord(file, position);

			// If the two values are equal..
			if (searchValue.compare(buffer) == 0)
			{
				// Set the lower and upper bounds to 1 and 0 respectively, to stop searching
				lower = 1; 
				upper = 0; 
				// Set passwordMatch boolean to false - password found
				passwordNotFound = FALSE;
			}
			// If the requesting password hash is greater than the current hash
			else if (searchValue.compare(buffer) > 0)
			{
				// Set lower equal to the middle value + 1
				lower = position + 1;
			}
			// If the requesting password hash is lower than the current hash
			else if (searchValue.compare(buffer) < 0)
			{
				// Set upper equal to the middle value - 1
				upper = position - 1;
			}

		}

		// For whatever reason, the first line is skipped. This should stop that.
		if (upper == -1)
		{
			file.close();
			std::ifstream file(files[ii].c_str(), std::ios::binary);
			char buffer[41] = "";

			// Read 40 chararacters into the buffer string
			file.getline(buffer, 41);

			std::string buff(buffer);

			if (buff.compare(searchValue) == 0)
			{
				passwordNotFound = FALSE;
			}
		}

		file.close();

		// Iterate ii to change to the next file
		ii++;
	} while (passwordNotFound && ii < _countof(files));

	// Return passwordNotFound Boolean to LSA
	return passwordNotFound;
}