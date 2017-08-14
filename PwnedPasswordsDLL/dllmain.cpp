/* DLLMain.cpp is the code for the custom password filter that is to be utilised by
* LSA to check the validity of password requests.
* The DLL sends a GET request to the HaveIBeenPwned API, and subsequently selects
* whether or not the password is valid, based on whether or not it exists as a
* previously breached password.
* Content Author:  JacksonVD
* Contact: jacksonvd.com
* Date Written:    14-08-17
*/

#include "stdafx.h"
#include <Windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <SubAuth.h>
#include <curl/curl.h>
#include <string>

#pragma comment(lib, "libcurl_a.lib")
#pragma comment(lib, "Ws2_32.lib")

long flags = CURL_GLOBAL_ALL;
CURLcode curlcode = curl_global_init(flags);

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
* This function will be called by LSA - the function imports calling account information, including the prospective password
* and exports a Boolean value (either TRUE or FALSE). This return value is then used by LSA in determining whether or not
* the password has passed the in-place password policy.

*/

extern "C" __declspec(dllexport) BOOLEAN __stdcall PasswordFilter(PUNICODE_STRING accountName,
	PUNICODE_STRING fullName,
	PUNICODE_STRING password,
	BOOLEAN operation) {
	// Declare and initialise the returnValue Boolean expresion as false by default
	BOOLEAN returnValue = FALSE;

	// Long and convoluted way of getting password String from PUNICODE_STRING
	std::wstring wStrBuffer(password->Buffer, password->Length / sizeof(WCHAR));
	const wchar_t *wideChar = wStrBuffer.c_str();
	std::wstring wStr(wideChar);
	std::string str(wStr.begin(), wStr.end());

	// Declare and initialise CURL
	CURL *curl = curl_easy_init();
	// Initialise URL String as being the API address + the password
	std::string URL("https://haveibeenpwned.com/api/v2/pwnedpassword/" + str + "?truncateResponse=true");

	int http_status_code; // Declare the http_status_code variable
	if (curl) { // If cURL has been initialised..
		CURLcode res;
		curl_easy_setopt(curl, CURLOPT_URL, URL.c_str()); // Set the URL for CURL to the URL string
		curl_easy_setopt(curl, CURLOPT_USERAGENT, "API Scraper/1.0"); // Troy requires a user-agent when calling API


		res = curl_easy_perform(curl); // Perform the request on the above URL with the above user-agent
		if (res == CURLE_OK) { // If no errors occurred..
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status_code); // Retrieve the HTTP status code
			if (http_status_code == 404) { // If the status code is 404 (i.e. password doesn't exist in pwned passwords data) THEN..
				returnValue = TRUE; // Set returnValue Boolean to true (password is fine to use as it doesn't exist as a previously breached password)
			}
		}
		curl_easy_cleanup(curl); // Clean-up for cURL
	}
	return returnValue; // Return the Boolean value to LSA
}