#pragma once

#include "common.h"

/* Dumping tools */
#define SZ_DUMP_BEGIN "\n--------------------------------------------- BEGIN DUMP --------------------------------------------"
#define SZ_DUMP_END   "---------------------------------------------- END DUMP ---------------------------------------------"

#define SAM_EMPTY_LM "AAD3B435B51404EEAAD3B435B51404EE"
static BYTE SAM_EMPTY_LM_BYTES[16] = {0xAA,0xD3,0xB4,0x35,0xB5,0x14,0x04,0xEE,0xAA,0xD3,0xB4,0x35,0xB5,0x14,0x04,0xEE};
#define SAM_EMPTY_NT "31D6CFE0D16AE931B73C59D7E0C089C0"

/* NT/LM hash struct */
#define WIN_NTLM_HASH_SIZE 16
typedef enum{LM_HASH,NT_HASH,NT_NO_HASH}NT_HASH_TYPE;

typedef struct {
	NT_HASH_TYPE hash_type;
	BYTE LM_hash[WIN_NTLM_HASH_SIZE];
	BYTE NT_hash[WIN_NTLM_HASH_SIZE];
}s_NTLM_Hash;

#pragma pack(push)
#pragma pack(1)

	/* NTDS ciphered NT/LM hash struct */
	typedef struct {
		BYTE marker[8];
		BYTE decipher_key[16];
		BYTE ciphered_hash[WIN_NTLM_HASH_SIZE];
	}s_NTLM_hash_ciphered;

	/* NTDS deciphered PEK struct */
	typedef struct{
		BYTE marker2[36];
		BYTE decipher_key2[16];
	}s_NTLM_pek;

	/* NTDS ciphered PEK struct */
	typedef struct{
		BYTE marker[8];
		BYTE decipher_key1[16];
		BYTE marker2[36];
		BYTE decipher_key2_ciphered[16];
	}s_NTLM_pek_ciphered;
#pragma pack(pop)


/* 
 * SAM accounts structures (ldap, local & cached)
 * + Bitlocker account struct
 */
typedef struct {
	WCHAR szSAMAccountName[UNLEN+1];
	DWORD szSAMAccountType;
	PSID sid;
	DWORD rid;
	s_NTLM_hash_ciphered LM_hash_ciphered;
	s_NTLM_hash_ciphered NT_hash_ciphered;
	UINT nbHistoryEntries;

	LPBYTE LM_history_ciphered;
	LPBYTE NT_history_ciphered;
	UINT LM_history_ciphered_size;
	UINT NT_history_ciphered_size;
	LPBYTE LM_history_deciphered;
	LPBYTE NT_history_deciphered;

	s_NTLM_Hash NTLM_hash;
	s_NTLM_Hash *NTLM_hash_history;
}s_ldapAccountInfo;

typedef struct {
	TCHAR szSAMAccountName[UNLEN+1];
	DWORD rid;
	LPBYTE V;							/* Ciphered hash & history */
	DWORD dwVSize;
	UINT nbHistoryEntries;

	s_NTLM_Hash NTLM_hash;
	s_NTLM_Hash *NTLM_hash_history;
}s_localAccountInfo;

typedef struct {
	WCHAR szSAMAccountName[UNLEN+1];
	WCHAR szFullDomain[UNLEN+1];
	WCHAR szDomain[UNLEN+1];
	LPBYTE cachedEntry;					/* Ciphered buffer : hash, username,. domain name, ..*/
	DWORD dwCachedEntrySize;
	BOOL isEmpty;

	s_NTLM_Hash NTLM_hash;
}s_cachedAccountInfo;

typedef struct {
	TCHAR szSAMAccountName[UNLEN+1];
	GUID msFVE_VolumeGUID;
	GUID msFVE_RecoveryGUID;
	WCHAR msFVE_RecoveryPassword[55+1];	/* Recovery password (48 digits + '-') */
	LPBYTE msFVE_KeyPackage;			/* Binary keyfile for recovery */
	DWORD dwSzKeyPackage;
}s_bitlockerAccountInfo;


/* Linked list strcutures for SAM accounts */
typedef struct l_ldapAccountInfo
{
    s_ldapAccountInfo info;
    struct l_ldapAccountInfo *next;
}l_ldapAccountInfo;

typedef l_ldapAccountInfo* ll_ldapAccountInfo;

typedef struct l_localAccountInfo
{
    s_localAccountInfo info;
    struct l_localAccountInfo *next;
}l_localAccountInfo;

typedef l_localAccountInfo* ll_localAccountInfo;

typedef struct l_cachedAccountInfo
{
    s_cachedAccountInfo info;
    struct l_cachedAccountInfo *next;
}l_cachedAccountInfo;

typedef l_cachedAccountInfo* ll_cachedAccountInfo;

typedef struct l_bitlockerAccountInfo
{
    s_bitlockerAccountInfo info;
    struct l_bitlockerAccountInfo *next;
}l_bitlockerAccountInfo;

typedef l_bitlockerAccountInfo* ll_bitlockerAccountInfo;


/* Text dump strcuture */
typedef enum{NTDUMP_JOHN,NTDUMP_LC}NT_DUMP_TYPE;


/* Utils + Numeric */
DWORD BSWAP(DWORD n);
BYTE HexDigitToByte(TCHAR digit);
void BytesToHex(LPVOID data,size_t data_size,LPSTR out_str);


/* Privileges setting */
BOOL SetSeRestorePrivilege();
BOOL SetSeBackupPrivilege();
BOOL SetPrivilege();


/* Windows registry overlay */
BOOL RegGetValueEx(HKEY hKeyReg,LPSTR keyName,LPSTR valueName,LPDWORD type,LPVOID val,DWORD valSize,LPDWORD outValSize);


/* Linked list handling for accounts (username, hash, sid,...) */
ll_ldapAccountInfo ldapAccountInfoNew(ll_ldapAccountInfo *ldapAccountInfo,s_ldapAccountInfo *ldapAccountEntry);
BOOL ldapAccountInfoFreeAll(ll_ldapAccountInfo ldapAccountInfo);

ll_localAccountInfo localAccountInfoNew(ll_localAccountInfo *localAccountInfo,s_localAccountInfo *localAccountEntry);
BOOL localAccountInfoFreeAll(ll_localAccountInfo localAccountInfo);

ll_cachedAccountInfo cachedAccountInfoNew(ll_cachedAccountInfo *cachedAccountInfo,s_cachedAccountInfo *cachedAccountEntry);
BOOL cachedAccountInfoFreeAll(ll_cachedAccountInfo cachedAccountInfo);

ll_bitlockerAccountInfo bitlockerAccountInfoNew(ll_bitlockerAccountInfo *bitlockerAccountInfo,s_bitlockerAccountInfo *bitlockerAccountEntry);
BOOL bitlockerAccountInfoFreeAll(ll_bitlockerAccountInfo bitlockerAccountInfo);


/* Debug / text functions */
void PEK_cipheredDump(s_NTLM_pek_ciphered *pek_ciphered);
void PEK_Dump(s_NTLM_pek *pek);

BOOL NTDS_NTLM_DumpAll(ll_ldapAccountInfo ldapAccountInfo,NT_DUMP_TYPE dump_type,BOOL isStdout,LPSTR outFileName);
BOOL SAM_NTLM_DumpAll(ll_localAccountInfo localAccountInfo,NT_DUMP_TYPE dump_type,BOOL isStdout,LPSTR outFileName);
BOOL SAM_NTLM_Cached_DumpAll(ll_cachedAccountInfo cachedAccountInfo,NT_DUMP_TYPE dump_type,BOOL isStdout,LPSTR outFileName);
BOOL Bitlocker_DumpAll(ll_bitlockerAccountInfo bitlockerAccountInfo,BOOL isStdout,LPSTR outFileName);
