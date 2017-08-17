# Introduction

PwnedPasswordsDLL is a DLL that allows password requests through any form of Active Directory integration to be checked against over 330 million previously breached passwords.

Check out https://jacksonvd.com/checking-for-breached-passwords-in-active-directory/ for more information on the background of the tool.

# Compiling the Code (Visual Studio)

The code is heavily reliant on the Crypto++ library in order to convert the calling password to a SHA1 hash.  I have also only tested the code on x64 architecture, so I'm not sure if it will even work on 32-bit systems.

Compiling the code is quite simple in Visual Studio -

1. Download the PwnedPasswordsDLL source from here
2. Download Crypto++ from the following link (https://www.cryptopp.com/#download)
3. Build Crypto++ as a library in x64 mode - the following link is a good resource on compiling it for use in Visual Studio (http://programmingknowledgeblog.blogspot.com.au/2013/04/compiling-and-integrating-crypto-into.html)
4. Include the Crypto++ header directories through Project –> PwnedPasswordsDLL Properties –> Configuration Properties –> VC++ Directories. Edit the Include Directories and add the include directory
5. Then, edit the Library Directories and add the Debug directory from the x64\Outputdirectory.
6. Add cryptlib.lib to your Additional Dependencies list under Project –> PwnedPasswordsDLL Properties –> Configuration Properties –> Linker–>Input–> Additional Dependencies
7. Change Runtime Library to Multi-threaded Debug (/MTd) underProject –> PwnedPasswordsDLL Properties –> Configuration Properties –>  C/C++–> Code Generation
8. All that's left now is to Build and then test out the DLL!

# Implementing the DLL

The implementation of the DLL is the easy part, save for downloading some rather large text files - whether you've compiled the code yourself or downloaded a release, the implementation process is the same.

Note: These instructions need to be followed on all Domain Controllers in the domain if you wish to implement this for Active Directory, as any of them may end up servicing a password change request.

As the solution is entirely on-premises, you need to download the 3 breached passwords zip files from https://haveibeenpwned.com/passwords and extract the plain-text documents to the C drive (the file path is customisable if you compile the code yourself, but not if you download the Release). 

1. Download and extract the breached password lists, as per the instructions above
2. The DLL itself needs to be placed in your system root directory (generally C:\Windows\System32).
3. The DLL name needs to be added to the multi-string “Notification Packages” subkey under HKLM\System\CurrentControlSet\Control\LSA - note that you only need to add the name of the DLL, not including the file extension.
4. To ensure that the DLL works alongside your Group Policy password filtering settings,  ensure that the Passwords must meet complexity requirements policy setting is enabled through your relevant GPO(s).
5. Reboot the PC(s). Any password change request should now be filtered through the DLL.
