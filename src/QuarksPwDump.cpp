#include "common.h"
#include "ntdsparser.h"
#include "samparser.h"
#include "crypt.h"
#include "globals.h"



/*
 * Show banner
 */
void PrintBanner() {
	puts(APP_BANNER);
}


/*
 * Show usage
 */
void PrintUsage() {
	puts(APP_USAGE);
}


/*
 * Resiez current windows console
 * for nice outputs :)
 */
void ResizeConsole() {
	HANDLE hConOut;
	COORD newSBSize;
	SMALL_RECT conRect;

	system("cls");
	SetConsoleTitle(APP_TITLE);
	MoveWindow(GetConsoleWindow(),0,0,0,0,true);
	hConOut = GetStdHandle(STD_OUTPUT_HANDLE);

	newSBSize.X = 115;
	newSBSize.Y = 5000;
	SetConsoleScreenBufferSize(hConOut,newSBSize);
	conRect.Top = 0;
	conRect.Left = 0;
	conRect.Right = newSBSize.X-1;
    conRect.Bottom = 35;
	SetConsoleWindowInfo(hConOut,TRUE,&conRect);

	system("Color 1F");
}


/*
 * Parse command line for command options
 */
BOOL ParseCommandLine(int argc, TCHAR* argv[]) {
	BOOL has_ntds = FALSE;

	if(argc<2) 
		return FALSE;

	/* Parse */
	for (int i = 1; i < argc; i++) {
		if((!strcmp(argv[i],"--dump-hash-local")) || (!strcmp(argv[i],"-dhl")))
			OPT_DUMP_HASH_LOCAL = TRUE;
		else if((!strcmp(argv[i],"--dump-hash-domain-cached")) || (!strcmp(argv[i],"-dhdc")))
			OPT_DUMP_HASH_DOMAIN_CACHED = TRUE;
		else if((!strcmp(argv[i],"--dump-hash-domain")) || (!strcmp(argv[i],"-dhd")))
			OPT_DUMP_HASH_DOMAIN = TRUE;
		else if((!strcmp(argv[i],"--dump-bitlocker")) || (!strcmp(argv[i],"-db")))
			OPT_DUMP_BITLOCKER = TRUE;
		else if((!strcmp(argv[i],"--with-history")) || (!strcmp(argv[i],"-hist")))
			OPT_WITH_HISTORY = TRUE;
		else if((!strcmp(argv[i],"--output-type")) || (!strcmp(argv[i],"-t"))){
			if((i+1) < argc) {
				if(!lstrcmp(argv[i+1],"LC"))
					OPT_NT_DUMP_TYPE = NTDUMP_LC;
				else if(!lstrcmp(argv[i+1],"JOHN"))
					OPT_NT_DUMP_TYPE = NTDUMP_JOHN;
				i++;
			}
			else
				return FALSE;
		}
		else if((!strcmp(argv[i],"--ntds-file")) || (!strcmp(argv[i],"-nt"))){
			if((i+1) < argc) {
				lstrcpyn(OPT_NTDS_FILENAME,argv[i+1],MAX_PATH);
				i++;
				has_ntds = TRUE;
			}
			else
				return FALSE;
		}
		else if ((!strcmp(argv[i], "--system-file")) || (!strcmp(argv[i], "-sf"))){
			if ((i + 1) < argc) {
				lstrcpyn(OPT_SYSTEM_FILENAME, argv[i + 1], MAX_PATH);
				i++;
				OPT_WITH_SYSTEM_FILE = TRUE;
			}
			else
				return FALSE;
		}
		else if((!strcmp(argv[i],"--output")) || (!strcmp(argv[i],"-o"))){
			if((i+1) < argc) {
				lstrcpyn(OPT_OUTPUT_FILENAME,argv[i+1],MAX_PATH);
				OPT_OUT_STDOUT = FALSE;
				i++;
			}
			else
				return FALSE;
		}
	}

	/* Something choosed ? */
	if(!(OPT_DUMP_HASH_LOCAL || OPT_DUMP_HASH_DOMAIN_CACHED || OPT_DUMP_HASH_DOMAIN || OPT_DUMP_BITLOCKER))
		return FALSE;

	/* Check for conflicts */
	if(OPT_DUMP_HASH_LOCAL && OPT_DUMP_HASH_DOMAIN_CACHED && OPT_DUMP_HASH_DOMAIN && OPT_DUMP_BITLOCKER)
		return FALSE;

	if(OPT_DUMP_HASH_LOCAL && (OPT_DUMP_HASH_DOMAIN_CACHED || OPT_DUMP_HASH_DOMAIN || OPT_DUMP_BITLOCKER))  
		return FALSE;

	if(OPT_DUMP_HASH_DOMAIN_CACHED && (OPT_DUMP_HASH_LOCAL || OPT_DUMP_HASH_DOMAIN || OPT_DUMP_BITLOCKER))  
		return FALSE;

	if(OPT_DUMP_HASH_DOMAIN && (OPT_DUMP_HASH_DOMAIN_CACHED || OPT_DUMP_HASH_LOCAL || OPT_DUMP_BITLOCKER))  
		return FALSE;

	if(OPT_DUMP_BITLOCKER && (OPT_DUMP_HASH_DOMAIN_CACHED || OPT_DUMP_HASH_DOMAIN || OPT_DUMP_HASH_LOCAL))  
		return FALSE;

	if((OPT_DUMP_HASH_DOMAIN || OPT_DUMP_BITLOCKER) && !has_ntds)
		return FALSE;

	return TRUE;
}


/*
 * Actions dispatcher
 * Returns:
 *  TRUE if somethin has been successfully treated
 *  FALSE otherwise
 */
BOOL CommandDispatcher() {
	s_parser parser;
	int ret_code;

	/* Get SYSKEY (for domain hash dump only) */
	if(OPT_DUMP_HASH_DOMAIN || OPT_DUMP_HASH_DOMAIN_CACHED) {
		printf("[+] SYSKEY restrieving...");		
		ret_code = (OPT_WITH_SYSTEM_FILE)?CRYPT_SyskeyGetOfflineValue(&SYSKEY, OPT_SYSTEM_FILENAME) : CRYPT_SyskeyGetValue(&SYSKEY);
		if(ret_code==SYSKEY_SUCCESS) {
			puts("[OK]");
			SYSKEY_Dump(&SYSKEY);
		}
		else {
			if(ret_code==SYSKEY_REGISTRY_ERROR)
				puts("[ERR] Registry error, are you admin?");
			else
				puts("[ERR] SYSKEY is not stored locally, not supported yet");
			return FALSE;
		}
	}

	/* Domain users hashes dump from NTDS.dit */
	if(OPT_DUMP_HASH_DOMAIN) {

		printf("[+] Init JET engine...");
		if(!NTDS_ParserInit(&parser)) {
			puts("[!] NTDS_ParserInit failed!");
			return FALSE;
		}
		else{
			puts("OK");
			printf("[+] Open Database %s...",OPT_NTDS_FILENAME);
			if(!NTDS_OpenDatabase(&parser,OPT_NTDS_FILENAME)) {
				puts("[!] NTDS_OpenDatabase failed!");
				NTDS_ParserClose(&parser);
				return FALSE;
			}
			else {
				puts("OK");
				printf("[+] Parsing datatable...");
				if(NTDS_NTLM_ParseDatabase(&parser,&ldapAccountDatabase,&PEK_ciphered,OPT_WITH_HISTORY)!=NTDS_SUCCESS) {
					puts("Fatal error, wrong file?");
					if(NTDS_CloseDatabase(&parser))
						NTDS_ParserClose(&parser);
					return FALSE;
				}
				puts("OK");
				printf("[+] Processing PEK deciphering...");
				CRYPT_Decipher_PEK(&PEK_ciphered,&SYSKEY,&PEK);
				puts("OK");
				PEK_Dump(&PEK);

				printf("[+] Processing hashes deciphering...");
				if(!CRYPT_NTDS_DecipherAllAccount(ldapAccountDatabase,&SYSKEY,&PEK))
					puts("ERROR: nothing to decipher");
				else {
					puts("OK");
					NTDS_NTLM_DumpAll(ldapAccountDatabase,OPT_NT_DUMP_TYPE,OPT_OUT_STDOUT,OPT_OUTPUT_FILENAME);
				}

				if(ldapAccountDatabase)
					ldapAccountInfoFreeAll(ldapAccountDatabase);

				printf("[+] Close Database...");
				if(NTDS_CloseDatabase(&parser)) {
					NTDS_ParserClose(&parser);
					puts("OK");
				}		
			}
		}	
	}
	/* Local users hashes dump */
	else if(OPT_DUMP_HASH_LOCAL) {
		printf("[+] Setting BACKUP and RESTORE privileges...");
		if(!SetSeRestorePrivilege() || !SetSeBackupPrivilege()) {
			puts("ERROR: are you admin?");
			return FALSE;
		}
		else {
			puts("[OK]");
			printf("[+] Parsing SAM registry hive...");
			ret_code = SAM_ParseLocalDatabase(&localAccountDatabase,&BOOTKEY_ciphered,OPT_WITH_HISTORY);
			if(ret_code==SAM_REG_ERROR) {
				puts("ERROR: Registry error");
				return FALSE;
			}
			else if(ret_code==SAM_MOUNT_ERROR) {
				puts("ERROR: Can't mount previously saved SAM registry hive");
				return FALSE;
			}
			else if(ret_code==SAM_MEM_ERROR) {
				puts("ERROR: Fatal, not enough memory!");
				return FALSE;
			}
			else if(ret_code==SAM_NO_ACCOUNT) {
				puts("\n\nNo account found");
				return FALSE;
			}
			else{
				puts("[OK]");

				printf("[+] BOOTKEY retrieving...");
				ret_code = CRYPT_BootkeyGetValue(&BOOTKEY_ciphered,&BOOTKEY);
				if(ret_code==SYSKEY_SUCCESS) {
					puts("[OK]");
					BOOTKEY_Dump(&BOOTKEY);
					CRYPT_SAM_DecipherAllLocalAccount(localAccountDatabase,&BOOTKEY);
					SAM_NTLM_DumpAll(localAccountDatabase,OPT_NT_DUMP_TYPE,OPT_OUT_STDOUT,OPT_OUTPUT_FILENAME);
				}
				else {
					if(ret_code==SYSKEY_REGISTRY_ERROR)
						puts("[ERR] Registry error, are you admin?");
					else
						puts("[ERR] SYSKEY is not stored locally, not supported yet");
				}
			}
			if(localAccountDatabase)
				localAccountInfoFreeAll(localAccountDatabase);
		}
	}
	/* Cached domain hashes dump */
	else if(OPT_DUMP_HASH_DOMAIN_CACHED) {
		printf("[+] Setting BACKUP and RESTORE privileges...");
		if(!SetSeRestorePrivilege() || !SetSeBackupPrivilege()) {
			puts("ERROR: are you admin?");
			return FALSE; 
		}
		else {
			puts("[OK]");
			printf("[+] Parsing SECURITY registry hive...");
			ret_code = SAM_ParseCachedDatabase(&cachedAccountDatabase,&LSAKEY_ciphered,&NLKM_ciphered);
			if(ret_code==SAM_REG_ERROR) {
				puts("ERROR: Registry error");
				return FALSE;
			}
			else if(ret_code==SAM_MOUNT_ERROR) {
				puts("ERROR: Can't mount previously saved SAM registry hive");
				return FALSE;
			}
			else if(ret_code==SAM_MEM_ERROR) {
				puts("ERROR: Fatal, not enough memory!");
				return FALSE;
			}
			else {
				puts("[OK]");
				printf("[+] LSAKEY(s) retrieving...");
				if(CRYPT_LsakeyGetValue(&LSAKEY,&LSAKEY_ciphered,&SYSKEY)==LSAKEY_SUCCESS) {
					puts("[OK]");
					LSAKEY_Dump(&LSAKEY);
					printf("[+] NLKM retrieving...");
					if(CRYPT_NlkmGetValue(&NLKM,&NLKM_ciphered,&LSAKEY)==LSAKEY_SUCCESS) {
						puts("[OK]");
						NLKM_Dump(&NLKM);
						if(CRYPT_SAM_DecipherAllCachedAccount(cachedAccountDatabase,&NLKM)==CRYPT_EMPTY_RECORD)
							puts("\nNo cached domain password found!");
						else
							SAM_NTLM_Cached_DumpAll(cachedAccountDatabase,OPT_NT_DUMP_TYPE,OPT_OUT_STDOUT,OPT_OUTPUT_FILENAME);
					}
				}
			}
			if(cachedAccountDatabase)
				cachedAccountInfoFreeAll(cachedAccountDatabase);
		}
	}
	/* Bitlocker information extraction from NTDS.dit */
	else if(OPT_DUMP_BITLOCKER) {
		printf("[+] Init JET engine...");
		if(!NTDS_ParserInit(&parser)) {
			puts("[!] NTDS_ParserInit failed!");
			return FALSE;
		}
		else{
			puts("OK");
			printf("[+] Open Database %s...",OPT_NTDS_FILENAME);
			if(!NTDS_OpenDatabase(&parser,OPT_NTDS_FILENAME)) {
				puts("[!] NTDS_OpenDatabase failed!");
				NTDS_ParserClose(&parser);
				return FALSE;
			}
			else {
				puts("OK");
				printf("[+] Parsing datatable...");
				ret_code = NTDS_Bitlocker_ParseDatabase(&parser,&bitlockerAccountDatabase);
				if(ret_code==NTDS_SUCCESS)  {
					puts("OK");
					Bitlocker_DumpAll(bitlockerAccountDatabase,OPT_OUT_STDOUT,OPT_OUTPUT_FILENAME);
				}
				else
					puts("Error: bad file or no Bitlocker account there");
				
				if(bitlockerAccountDatabase)
					bitlockerAccountInfoFreeAll(bitlockerAccountDatabase);

				printf("[+] Close Database...");
				if(NTDS_CloseDatabase(&parser)) {
					NTDS_ParserClose(&parser);
					puts("OK");
				}
			}
		}
	}

	return TRUE;
}


/*
 * Once upon a time...
 */
int main(int argc, TCHAR* argv[]) {
	BOOL status;

	/* Prepare console */
	ResizeConsole();
	setvbuf(stdout,NULL,_IONBF,0);
	PrintBanner();

	/* Parse args/options */
	if(!ParseCommandLine(argc,argv)) {
		PrintUsage();
		return 1;
	}

	/* Execute user's desired actions */
	status = CommandDispatcher();

	puts("\n");

	return status!=TRUE;
}
