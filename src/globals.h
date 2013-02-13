#pragma once

#include "common.h"
#include "crypt.h"

static TCHAR APP_TITLE[] = "Quarks PwDump";

static TCHAR APP_BANNER[10*91] = {
	"________                          __            __________          ________                            \r\n"
	"\\_____  \\   __ __ _____  _______ |  | __  ______\\______   \\__  _  __\\______ \\   __ __   _____  ______   \r\n"
	" /  / \\  \\ |  |  \\\\__  \\ \\_  __ \\|  |/ / /  ___/ |     ___/\\ \\/ \\/ / |    |  \\ |  |  \\ /     \\ \\____ \\  \r\n"
	"/   \\_/.  \\|  |  / / __ \\_|  | \\/|    <  \\___ \\  |    |     \\     /  |    `   \\|  |  /|  Y Y  \\|  |_> > \r\n"
	"\\_____\\ \\_/|____/ (____  /|__|   |__|_ \\/____  > |____|      \\/\\_/  /_______  /|____/ |__|_|  /|   __/  \r\n"
	"       \\__>            \\/             \\/     \\/                             \\/              \\/ |__|     \r\n"
	"                                                                            v0.2b -<(QuarksLab)>-\r\n"
};

static TCHAR APP_USAGE[10*100] = {
	"quarks-pwdump.exe <options>\r\n"
	"Options : \r\n"
	"-dhl  --dump-hash-local\r\n"
	"-dhdc --dump-hash-domain-cached\r\n"
	"-dhd  --dump-hash-domain (NTDS_FILE must be specified)\r\n"
	"-db   --dump-bitlocker (NTDS_FILE must be specified)\r\n"
	"-nt   --ntds-file FILE\r\n"
	"-hist --with-history (optional)\r\n"
	"-t    --output-type JOHN/LC (optional, if no=>JOHN)\r\n"
	"-o    --output FILE (optional, if no=>stdout)\r\n"
	"\r\nExample: quarks-pwdump.exe --dump-hash-domain --with-history\r\n"
};

/* CLI option */
static BOOL OPT_DUMP_HASH_LOCAL = FALSE;
static BOOL OPT_DUMP_HASH_DOMAIN_CACHED = FALSE;
static BOOL OPT_DUMP_HASH_DOMAIN = FALSE;
static BOOL OPT_DUMP_BITLOCKER = FALSE;
static BOOL OPT_WITH_HISTORY = FALSE;
static BOOL OPT_OUT_STDOUT = TRUE;
static TCHAR OPT_OUTPUT_FILENAME[MAX_PATH+1];
static TCHAR OPT_NTDS_FILENAME[MAX_PATH+1];
static NT_DUMP_TYPE OPT_NT_DUMP_TYPE = NTDUMP_JOHN;

/* Account and crypto struct */
static ll_ldapAccountInfo ldapAccountDatabase = NULL;
static ll_localAccountInfo localAccountDatabase = NULL;
static ll_cachedAccountInfo cachedAccountDatabase = NULL;
static ll_bitlockerAccountInfo bitlockerAccountDatabase = NULL;
static s_NTLM_pek_ciphered PEK_ciphered;
static s_NTLM_pek PEK;
static s_SYSKEY SYSKEY;
static s_BOOTKEY_ciphered BOOTKEY_ciphered;
static s_BOOTKEY BOOTKEY;
static s_LSAKEY_ciphered LSAKEY_ciphered;
static s_LSAKEY LSAKEY;
static s_NLKM_ciphered NLKM_ciphered;
static s_NLKM NLKM;

/* Jet instance unique string */
static JET_PCSTR APP_JET_INSTANCE_STR = "QUARKS-K0DE";
