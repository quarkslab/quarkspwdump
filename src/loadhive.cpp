//-----------------------------------------------------------
// Load Hive v1.0
// Copyright (C) 2001, MATCODE Software
// http://www.matcode.com
// Author: Vitaly Evseenko
// E-Mail: ve@matcode.com
//-----------------------------------------------------------

// Load Hive creates a subkey under HKEY_LOCAL_MACHINE and
// and load a specified registry file (hive) into that subkey. 
// A registry file (hive) is a discrete body of keys, subkeys,
// and values that is rooted at the top of the registry hierarchy.
//
// LoadHive can be used together with REMOTE DRiVE
// (http://www.matcode.com/remdrv.htm) to edit registry
// on failed to boot Windows NT/2000 or Windows XP machine.
//
// Typicaly hives are located for Windows NT/2000/XP at:
// \%SystemRoot%\System32\config - Local system configuration
// \Documents and Settings\%UserName%\NTUSER.DAT - HKEY_CURRENT_USER (in Win2000/XP)
// \%SystemRoot%\Profiles\%UserName%\NTUSER.DAT - HKEY_CURRENT_USER (in WinNT)
//
// for Windows 95/98/ME at:
// \%WinDir%\system.dat - Local system configuration
// \%WinDir%\user.dat - HKEY_CURRENT_USER
// if there is present more different users that
// in the \%WinDir%\Profiles\%UserName%\user.dat - HKEY_CURRENT_USER for them

#include <tchar.h>
#include <windows.h>
#include <stdio.h>
#include <commctrl.h>
#pragma hdrstop
#include "loadhive.h"


int LoadHive(LPTSTR lpszHiveName)
{
	long WINAPI iError;
	HKEY hExistKey;
	LPTSTR error;


	// Before check this key
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, SUBKEY_SYSTEM_HIVE, 0, KEY_READ, &hExistKey) == ERROR_SUCCESS)
		RegCloseKey(hExistKey);

	if (GetVersion() < 0x80000000)
	{
		HANDLE hToken;
		TOKEN_PRIVILEGES TokenPrivileges;

		// In order to use this program for Win95/98/ME as well as for WinNT/2000/XP
		// we have to load unsupported under Win95/98/ME export dynamically.

		BOOL(__stdcall *NT_OpenProcessToken)(HANDLE ProcessHandle,
			DWORD DesiredAccess, PHANDLE TokenHandle);

		BOOL(__stdcall *NT_LookupPrivilegeValue)(LPCTSTR lpSystemName,
			LPCTSTR lpName, PLUID lpLuid);

		BOOL(__stdcall *NT_AdjustTokenPrivileges)(HANDLE TokenHandle,
			BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState,
			DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState,
			PDWORD ReturnLength);

		HINSTANCE hAdvApi = GetModuleHandle(_TEXT("ADVAPI32.DLL"));
		if (hAdvApi == NULL)
			return GetLastError();

		NT_OpenProcessToken = (BOOL(__stdcall *)(HANDLE ProcessHandle,
			DWORD DesiredAccess, PHANDLE TokenHandle))
			GetProcAddress(hAdvApi, "OpenProcessToken");

		NT_LookupPrivilegeValue = (BOOL(__stdcall *)(LPCTSTR lpSystemName,
			LPCTSTR lpName, PLUID lpLuid))
			GetProcAddress(hAdvApi, "LookupPrivilegeValue"MODIFY_NAME);

		NT_AdjustTokenPrivileges = (BOOL(__stdcall *)(HANDLE TokenHandle,
			BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState,
			DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState,
			PDWORD ReturnLength))
			GetProcAddress(hAdvApi, "AdjustTokenPrivileges");


		if (!NT_AdjustTokenPrivileges || !NT_LookupPrivilegeValue || !NT_OpenProcessToken)
		{
			puts("Unable to load necessary export function(s) from ADVAPI32.dll.");
			return -1;
		}

		NT_OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
		NT_LookupPrivilegeValue(NULL, SE_RESTORE_NAME, &(TokenPrivileges.Privileges[0].Luid));

		TokenPrivileges.PrivilegeCount = 1;
		TokenPrivileges.Privileges[0].Attributes = 2;

		NT_AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

		if (hToken)
			CloseHandle(hToken);
	}

	if ((iError = RegLoadKey(HKEY_LOCAL_MACHINE, SUBKEY_SYSTEM_HIVE, lpszHiveName)) != ERROR_SUCCESS)
	{
		FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, iError,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
			(LPTSTR)&error, 0, NULL);
		puts(error);
		return iError;
	}

	return ERROR_SUCCESS;
}


void UnloadHive() {
	int errorCode;
	if ((errorCode = RegUnLoadKey(HKEY_LOCAL_MACHINE, SUBKEY_SYSTEM_HIVE)) != ERROR_SUCCESS)
	{
		puts("Could not unload offline SYSTEM hive. Try unloading it manually using Regedit.exe.\n");
	}
}
