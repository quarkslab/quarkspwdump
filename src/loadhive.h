//-----------------------------------------------------------
// Header file for Load Hive
// Copyright (C) 2001, MATCODE Software
// http://www.matcode.com
// Author: Vitaly Evseenko
// E-Mail: ve@matcode.com
// Hack: Nadeem Douba
//-----------------------------------------------------------

#define ID_regf		0x66676572
#define ID_CREG		0x47455243
#define ID_RGKN		0x4E4B4752

#define SZ_APPICON	0x80

#ifdef UNICODE
#define MODIFY_NAME	"W"
#else
#define MODIFY_NAME	"A"
#endif

#define SUBKEY_SYSTEM_HIVE "OFFLINE_SYSTEM"

int LoadHive(LPTSTR lpszHiveName);
void UnloadHive();

#pragma pack(1)

typedef struct _WNTREGHEADER{
	DWORD       id;     // "regf" = 0x66676572  = W95_REG header signature
	DWORD       dwVType1;
	DWORD       dwVType2;
	FILETIME    ModifyTime;
	DWORD       dw1;
	DWORD       dwRegVer;
	DWORD       dw2;
	DWORD       dw3;
	DWORD       dwRootOfs; // Offset of ROOT key
	DWORD       dwFileSize;
	DWORD       dw4;
	WCHAR       HiveName[230];
	DWORD       CheckSum;
} WNTREGHEADER, *PWNTREGHEADER;

typedef struct _W95REGHEADER {
	DWORD       id;     // 'CREG' = W95_REG header signature
	DWORD       dwVer;
	DWORD       FirstBlock;
	DWORD       dwZero;
	WORD        nBlocks;
	WORD        w0;
	DWORD       dwDummy0;
	DWORD       dwDummy1;
	DWORD       dwDummy2;
} W95REGHEADER, *PW95REGHEADER;

typedef struct _W95REGINDEX {
	DWORD       id;     // 'RGKN' = W95_REG index signature
	DWORD       dwSize;
	WORD        AddressOffset;
	WORD        wDummy0;
	DWORD       dwNumRecords;
} W95REGINDEX, *PW95REGINDEX;


typedef struct _W95REGBLOCK {
	DWORD       id;     // 'RGDB' = W95_REG block signature
	DWORD       dwSize;
	DWORD       dwFree;
	WORD        ResList;
	WORD        wNumOfBlock;
	DWORD       dwFreeOffset;
	WORD        nParts;
	WORD        nFree;
	DWORD       dwDummy0;
	DWORD       dwDummy1;
} W95REGBLOCK, *PW95REGBLOCK;

#pragma pack()

