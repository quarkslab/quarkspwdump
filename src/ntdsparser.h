#pragma once

#include "common.h"
#include "crypt.h"
#include "globals.h"

/* NTDS obejcts table */
#define NTDS_TBL_OBJ "datatable"


/* NTDS interesting account attributes */
#define ATT_SAM_ACCOUNT_NAME	"ATTm590045"
#define ATT_SAM_ACCOUNT_TYPE	"ATTj590126"
#define ATT_OBJECT_SID			"ATTr589970"
#define ATT_LM_HASH				"ATTk589879"
#define ATT_NT_HASH				"ATTk589914"
#define ATT_PEK					"ATTk590689"
#define ATT_LM_HASH_HISTORY		"ATTk589984"
#define ATT_NT_HASH_HISTORY		"ATTk589918"

#define ATT_BITLOCKER_MSFVE_KEY_PACKAGE			"ATTk591823"
#define ATT_BITLOCKER_MSFVE_RECOVERY_GUID		"ATTk591789"
#define ATT_BITLOCKER_MSFVE_RECOVERY_PASSWORD	"ATTm591788"
#define ATT_BITLOCKER_MSFVE_VOLUME_GUID			"ATTk591822"


/* SAM account types (NTDS) */
#define SAM_GROUP_OBJECT				0x10000000
#define SAM_NON_SECURITY_GROUP_OBJECT	0x10000001
#define SAM_ALIAS_OBJECT				0x20000000
#define SAM_NON_SECURITY_ALIAS_OBJECT	0x20000001
#define SAM_USER_OBJECT					0x30000000
#define SAM_MACHINE_ACCOUNT				0x30000001
#define SAM_TRUST_ACCOUNT				0x30000002


/* NTDS parser structure definitions */
#define ID_SAM_ACCOUNT_NAME		0
#define ID_SAM_ACCOUNT_TYPE		1
#define ID_OBJECT_SID			2
#define ID_LM_HASH				3
#define ID_NT_HASH				4
#define ID_PEK					5
#define ID_LM_HASH_HISTORY		6
#define ID_NT_HASH_HISTORY		7

#define ID_MSFVE_KEY_PACKAGE		0
#define ID_MSFVE_RECOVERY_GUID		1
#define ID_MSFVE_RECOVERY_PASSWORD	2
#define ID_MSFVE_VOLUME_GUID		3

typedef struct {
	JET_INSTANCE instance;
	JET_SESID sesid;
	JET_DBID dbid;
	TCHAR parsed_filename[MAX_PATH+1];
	JET_COLUMNDEF columndef[8];
}s_parser;


/* Error codes for NTDS functions */
#define NTDS_SUCCESS 0
#define NTDS_BAD_RECORD -1
#define NTDS_API_ERROR -2
#define NTDS_MEM_ERROR -3
#define NTDS_EMPTY_ERROR -4


/* NTDS parser handling */
BOOL NTDS_ParserInit(s_parser *parser);
BOOL NTDS_ParserClose(s_parser *parser);

BOOL NTDS_OpenDatabase(s_parser *parser,LPCSTR szNtdsPath);
BOOL NTDS_CloseDatabase(s_parser *parser);

int NTDS_NTLM_ParseDatabase(s_parser *parser,ll_ldapAccountInfo *ldapAccountInfo,s_NTLM_pek_ciphered *pek_ciphered,BOOL with_history);
int NTDS_Bitlocker_ParseDatabase(s_parser *parser,ll_bitlockerAccountInfo *bitlockerAccountInfo);



