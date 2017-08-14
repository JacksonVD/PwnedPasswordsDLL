# Introduction

Check out https://jacksonvd.com/checking-for-breached-passwords-with-active-directory for more information on the background of the tool.

# Compiling the Code (Visual Studio)

1. Grab the following precompiled libcurl binaries for Windows (https://github.com/HazeProductions/libcurl)

2. Include the libcurl header files through Project –> (Project name) Properties –> Configuration Properties –> VC++ Directories. Edit the Include Directories and add the include directory

3. Then, edit the Library Directories and add the static-release-x64 directory from the lib directory.

4. Add libcurl_a.lib ws2_32.lib winmm.lib wldap32.lib to your Additional Dependencies list under Project –> (Project name) Properties –> Configuration Properties –> Linker–>Input–> Additional Dependencies

5. Add CURL_STATICLIB to your Preprocessor Definitions under Project –> (Project name) Properties –> Configuration Properties –>  C/C++–> Preprocessor–> Preprocessor Definitions

6. All that's left now is to Build and then test out the DLL!

# Implementing the DLL

The implementation of the DLL is the easy part - whether you've compiled the code yourself or downloaded a release, the implementation process is the same.

Please note that you will need to follow these instructions for all Domain Controllers on the network, as any of them may end up servicing a password change request.

1. The DLL itself needs to be placed in your system root directory (generally C:\Windows\System32).

2. The DLL name needs to be added to the multi-string “Notification Packages” subkey under HKLM\System\CurrentControlSet\Control\LSA - note that you only need to add the name of the DLL, not including the file extension.

3. FIREWALL SETTINGS

4. To ensure that the DLL works alongside your Group Policy password filtering settings,  ensure that the Passwords must meet complexity requirements policy setting is enabled through your Domain Controllers GPO.

5. Reboot the PC. Any password change request should now be filtered through the HaveIBeenPwned API.
