#pragma once

#include "common.h"
#include <openssl\aes.h>
#include <openssl\des.h>
#include <openssl\rc4.h>
#include <openssl\md5.h>
#include <openssl\sha.h>
#include <openssl\hmac.h>

#include "utils.h"

/* Crypt functions error codes */
#define CRYPT_SUCCESS 0
#define CRYPT_MEM_ERROR -1
#define CRYPT_EMPTY_RECORD -2

#define SYSKEY_SUCCESS 0
#define SYSKEY_REGISTRY_ERROR -1
#define SYSKEY_METHOD_NOT_IMPL -2

#define LSAKEY_SUCCESS 0
#define LSAKEY_REGISTRY_ERROR -1


/* Some cipher cste for local NTLM hashes deciphering */
#define SAM_QWERTY "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%"
#define SAM_NUM    "0123456789012345678901234567890123456789"
#define SAM_LMPASS "LMPASSWORD"
#define SAM_NTPASS "NTPASSWORD"
#define SAM_LMPASS_HISTORY "LMPASSWORDHISTORY"
#define SAM_NTPASS_HISTORY "NTPASSWORDHISTORY"


/*
 * Common windows key structure
 * SYSKEY, BOOTKEY, LSAKEY, NL$KM
 */
#pragma pack(push)
#pragma pack(1)
	typedef struct{
		BYTE key[16];
	}s_SYSKEY;

	typedef struct{
		BYTE key[16];
	}s_BOOTKEY;

	typedef struct{
		BYTE F[240];
	}s_BOOTKEY_ciphered;

	typedef struct{
		BYTE key[16];					/* XP, 2003 only */
		BYTE key_v2[32];			 	/* Vista, 7, 2008 only */

		DWORD dwMajorVersion;			/* OS identification */
	}s_LSAKEY;
	typedef struct{
		BYTE PolSecretEncryptionKey[76]; /* XP, 2003 only */
		BYTE PolEKList[172];			 /* Vista, 7, 2008 only */

		DWORD dwMajorVersion;			 /* OS identification */
	}s_LSAKEY_ciphered;

	typedef struct{
		BYTE key[64];					/* XP, 2003 only */
		BYTE key_v2[64];				/* Vista, 7, 2008 only */

		DWORD dwMajorVersion;			/* OS identification */
	}s_NLKM;
	typedef struct{
		BYTE key[84];					 /* XP, 2003 only */
		BYTE key_v2[156];			 	 /* Vista, 7, 2008 only */

		DWORD dwMajorVersion;			 /* OS identification */
	}s_NLKM_ciphered;
#pragma pack(pop)


/* Classical windows keys retrieving (all stored in registry) 
 *  SYSKEY could be dumped directly from registry by any standard users
 *  BOOTKEY, LSAKEY and NLKM must be extracted ciphered from SAM
 *  and SECURITY hives before (need LocalSystem privs) => see samparser.cpp
 *  
 *  LSAKEY & NLKM are used for domain cached passwords only
 *  BOOTKEY is used for local account only
 *  SYSKEY is used a bit everywhere :)
 */
int CRYPT_SyskeyGetOfflineValue(s_SYSKEY *pSyskey, LPTSTR hiveFileName);
int CRYPT_SyskeyGetValue(s_SYSKEY *pSyskey);
int CRYPT_BootkeyGetValue(s_BOOTKEY_ciphered *bootkey_ciphered,s_BOOTKEY *bootkey);
int CRYPT_LsakeyGetValue(s_LSAKEY *lsakey,s_LSAKEY_ciphered *lsakey_ciphered,s_SYSKEY *syskey);
int CRYPT_NlkmGetValue(s_NLKM *nlkm,s_NLKM_ciphered *nlkm_ciphered,s_LSAKEY *lsakey);


/* PEK is used for NTDS (ActiveDirectory) NTLM hashes storage */
BOOL CRYPT_Decipher_PEK(s_NTLM_pek_ciphered *pek_ciphered,s_SYSKEY *syskey,s_NTLM_pek *pek);


/* Classical windows keys dump to text */
void SYSKEY_Dump(s_SYSKEY *syskey);
void BOOTKEY_Dump(s_BOOTKEY *bootkey);
void LSAKEY_Dump(s_LSAKEY *bootkey);
void NLKM_Dump(s_NLKM *nlkm);


/* Account decipering funcs : local, cached and NTDS + history */
BOOL CRYPT_NTDS_DecipherAllAccount(ll_ldapAccountInfo ldapAccountInfo,s_SYSKEY *syskey,s_NTLM_pek *pek);
BOOL CRYPT_SAM_DecipherAllLocalAccount(ll_localAccountInfo localAccountInfo,s_BOOTKEY *bootkey);
int CRYPT_SAM_DecipherAllCachedAccount(ll_cachedAccountInfo cachedAccountInfo,s_NLKM *nlkm);



