#include "ntdsparser.h"


/*
 * Print JET engine errors
 */
void NTDS_ErrorPrint(s_parser *parser,LPSTR function,JET_ERR jet_err) {
	TCHAR szErrString[1024];
	JET_ERR jetErr = jet_err;

	printf("ERROR : %s() failed with JET_ERR = %d\n",function,jet_err);

	RtlZeroMemory(szErrString,sizeof(szErrString));
	JetGetSystemParameter(parser->instance,parser->sesid,JET_paramErrorToString,(JET_API_PTR *)&jetErr,szErrString,sizeof(szErrString));
	printf("Details : %s\n",szErrString);
}


/*
 * Intialize JET engine for NTDS files
 * (page_size=8192, no recovery)
 */
BOOL NTDS_ParserInit(s_parser *parser) {
	RtlZeroMemory(parser,sizeof(s_parser));

	if(JetSetSystemParameter(&parser->instance,JET_sesidNil,JET_paramDatabasePageSize,8192,NULL)!=JET_errSuccess)
		return FALSE;

	if(JetCreateInstance(&parser->instance,APP_JET_INSTANCE_STR)!=JET_errSuccess)
		return FALSE;

	if(JetSetSystemParameter(&parser->instance,JET_sesidNil,JET_paramRecovery,NULL,"Off")!=JET_errSuccess)
		return FALSE;

	if(JetInit(&parser->instance)!=JET_errSuccess)
		return FALSE;

	return TRUE;
}


/*
 * Close JET engine API
 */
BOOL NTDS_ParserClose(s_parser *parser) {
	if(!parser)
		return FALSE;

	return JetTerm(parser->instance)==JET_errSuccess;
}


/*
 * Open database from file
 */
BOOL NTDS_OpenDatabase(s_parser *parser,LPCSTR szNtdsPath) {
	JET_DBID dbID = JET_dbidNil;
	TCHAR szConnect[256];
	JET_ERR jet_err;

	lstrcpyn(parser->parsed_filename,szNtdsPath,sizeof(parser->parsed_filename)-1);

	jet_err = JetBeginSession(parser->instance,&parser->sesid,NULL,NULL);
	if(jet_err!=JET_errSuccess) {
		NTDS_ErrorPrint(parser,"JetBeginSession",jet_err);
		JetEndSession(parser->sesid,0);
		return FALSE;
	}

	jet_err = JetAttachDatabase(parser->sesid,parser->parsed_filename,JET_bitDbReadOnly);
	if(jet_err!=JET_errSuccess) {
		NTDS_ErrorPrint(parser,"JetAttachDatabase",jet_err);
		JetEndSession(parser->sesid,0);
		return FALSE;
	}

	jet_err = JetOpenDatabase(parser->sesid,parser->parsed_filename,szConnect,&parser->dbid,JET_bitDbReadOnly);
	if(jet_err!=JET_errSuccess) {
		NTDS_ErrorPrint(parser,"JetOpenDatabase",jet_err);
		JetEndSession(parser->sesid,0);
		return FALSE;
	}

	return TRUE;
}


/*
 * Close a previously opened database
 */
BOOL NTDS_CloseDatabase(s_parser *parser) {
	JET_ERR jet_err;

	jet_err = JetCloseDatabase(parser->sesid,parser->dbid,0);
	if(jet_err!=JET_errSuccess) {
		NTDS_ErrorPrint(parser,"JetCloseDatabase",jet_err);
		return FALSE;
	}

	jet_err = JetDetachDatabase(parser->sesid,parser->parsed_filename);
	if(jet_err!=JET_errSuccess) {
		NTDS_ErrorPrint(parser,"JetDetachDatabase",jet_err);
		return FALSE;
	}

	jet_err = JetEndSession(parser->sesid,0);
	if(jet_err!=JET_errSuccess) {
		NTDS_ErrorPrint(parser,"JetEndSession",jet_err);
		return FALSE;
	}

	return TRUE;
}


/*
 * Get specific column id content
 * Return value size only if val is NULL
 */
JET_ERR NTDS_GetRecord(s_parser *parser,JET_TABLEID tableid,JET_COLUMNID columnid,LPBYTE val,ULONG *val_size) {
	JET_ERR jet_err;

	if(val)
		RtlZeroMemory(val,*val_size);

	jet_err =  JetRetrieveColumn(parser->sesid,tableid,columnid,NULL,0,val_size,0,NULL);
	if(!val)
		return JET_errSuccess;

	if((*val_size) && jet_err != JET_errSuccess) {
		jet_err =  JetRetrieveColumn(parser->sesid,tableid,columnid,val,*val_size,val_size,0,NULL);
	}

	return jet_err;
}


/*
 * Try to parse object at current cursor position
 * Returns:
 *  NTDS_BAD_RECORD if record is not a user account or computer
 *  NTDS_MEM_ERROR if memory allocation errors
 */
int NTDS_NTLM_ParseSAMRecord(s_parser *parser,JET_TABLEID tableid,s_ldapAccountInfo *ldapAccountEntry,BOOL with_history) {
	unsigned long attributeSize;
	BYTE attributeVal[1024];
	JET_ERR jet_err;

	RtlZeroMemory(ldapAccountEntry,sizeof(s_ldapAccountInfo));

	/* Browse per sam account type */
	attributeSize = sizeof(attributeVal);
	jet_err = NTDS_GetRecord(parser,tableid,parser->columndef[ID_SAM_ACCOUNT_TYPE].columnid,attributeVal,&attributeSize);
	if((jet_err==JET_errSuccess)&&(attributeSize==sizeof(ldapAccountEntry->szSAMAccountType))) {
		ldapAccountEntry->szSAMAccountType = *(LPDWORD)attributeVal;
	} 
	else
		return NTDS_BAD_RECORD;

	if((ldapAccountEntry->szSAMAccountType != SAM_USER_OBJECT) && 
		(ldapAccountEntry->szSAMAccountType != SAM_MACHINE_ACCOUNT) && 
		(ldapAccountEntry->szSAMAccountType != SAM_TRUST_ACCOUNT)){
		return NTDS_BAD_RECORD;
	}

	/* Get SAM account name */
	attributeSize = sizeof(attributeVal);
	jet_err = NTDS_GetRecord(parser,tableid,parser->columndef[ID_SAM_ACCOUNT_NAME].columnid,attributeVal,&attributeSize);
	if((!attributeSize) || (jet_err!=JET_errSuccess))
		return NTDS_BAD_RECORD;

	lstrcpyW(ldapAccountEntry->szSAMAccountName,(LPWSTR)attributeVal);


	/* Get LM hash */
	attributeSize = sizeof(attributeVal);
	jet_err = NTDS_GetRecord(parser,tableid,parser->columndef[ID_LM_HASH].columnid,attributeVal,&attributeSize);
	if((jet_err==JET_errSuccess)&&(attributeSize==sizeof(s_NTLM_hash_ciphered))) {
		RtlMoveMemory(&ldapAccountEntry->LM_hash_ciphered,attributeVal,sizeof(s_NTLM_hash_ciphered));
		ldapAccountEntry->NTLM_hash.hash_type = LM_HASH;
	}
	else {
		ldapAccountEntry->NTLM_hash.hash_type = NT_NO_HASH;
	}

	/* Get NT hash */
	attributeSize = sizeof(attributeVal);
	jet_err = NTDS_GetRecord(parser,tableid,parser->columndef[ID_NT_HASH].columnid,attributeVal,&attributeSize);
	if((jet_err==JET_errSuccess)&&(attributeSize==sizeof(s_NTLM_hash_ciphered))) {
		RtlMoveMemory(&ldapAccountEntry->NT_hash_ciphered,attributeVal,sizeof(s_NTLM_hash_ciphered));
		if(ldapAccountEntry->NTLM_hash.hash_type != LM_HASH)
			ldapAccountEntry->NTLM_hash.hash_type = NT_HASH;
	}

	if(with_history) {
		/* Get LM hash history */
		jet_err = NTDS_GetRecord(parser,tableid,parser->columndef[ID_LM_HASH_HISTORY].columnid,NULL,&attributeSize);
		if(jet_err==JET_errSuccess && attributeSize) {
			ldapAccountEntry->LM_history_ciphered = (LPBYTE)VirtualAlloc(NULL,attributeSize,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
			ldapAccountEntry->LM_history_deciphered = (LPBYTE)VirtualAlloc(NULL,attributeSize,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
			if(!ldapAccountEntry->LM_history_ciphered || !ldapAccountEntry->LM_history_deciphered)
				return NTDS_MEM_ERROR;
			jet_err = NTDS_GetRecord(parser,tableid,parser->columndef[ID_LM_HASH_HISTORY].columnid,ldapAccountEntry->LM_history_ciphered,&attributeSize);
			if(jet_err != JET_errSuccess)
				return NTDS_API_ERROR;
			ldapAccountEntry->LM_history_ciphered_size = attributeSize;
		}
		
		/* Get NT hash history */
		jet_err = NTDS_GetRecord(parser,tableid,parser->columndef[ID_NT_HASH_HISTORY].columnid,NULL,&attributeSize);
		if(jet_err==JET_errSuccess && attributeSize) {
			ldapAccountEntry->NT_history_ciphered = (LPBYTE)VirtualAlloc(NULL,attributeSize,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
			ldapAccountEntry->NT_history_deciphered = (LPBYTE)VirtualAlloc(NULL,attributeSize,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
			if(!ldapAccountEntry->NT_history_ciphered || !ldapAccountEntry->NT_history_deciphered)
				return NTDS_MEM_ERROR;
			jet_err = NTDS_GetRecord(parser,tableid,parser->columndef[ID_NT_HASH_HISTORY].columnid,ldapAccountEntry->NT_history_ciphered,&attributeSize);
			if(jet_err != JET_errSuccess)
				return NTDS_API_ERROR;
		}

		if(ldapAccountEntry->LM_history_ciphered && ldapAccountEntry->NT_history_ciphered) {
			ldapAccountEntry->nbHistoryEntries = (attributeSize - 24) / WIN_NTLM_HASH_SIZE;
			if(!(ldapAccountEntry->NTLM_hash_history = (s_NTLM_Hash *)VirtualAlloc(NULL,ldapAccountEntry->nbHistoryEntries*sizeof(s_NTLM_Hash),MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE)))
				return NTDS_MEM_ERROR;
			ldapAccountEntry->NT_history_ciphered_size = attributeSize;
		}
	}

	/* Get Sid */
	attributeSize = sizeof(attributeVal);
	jet_err = NTDS_GetRecord(parser,tableid,parser->columndef[ID_OBJECT_SID].columnid,attributeVal,&attributeSize);
	if(jet_err==JET_errSuccess) {
		ldapAccountEntry->sid = (PSID)VirtualAlloc(NULL,attributeSize,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
		if(!ldapAccountEntry->sid)
			return NTDS_MEM_ERROR;
		RtlMoveMemory(ldapAccountEntry->sid,attributeVal,attributeSize-sizeof(ldapAccountEntry->rid));
		ldapAccountEntry->rid = BSWAP(*LPDWORD(attributeVal+attributeSize-sizeof(ldapAccountEntry->rid)));
		*LPDWORD((LPBYTE)ldapAccountEntry->sid+attributeSize-sizeof(ldapAccountEntry->rid))= ldapAccountEntry->rid;
	}
	else
		return NTDS_BAD_RECORD;

	return NTDS_SUCCESS;
}


/*
 * Try to parse a PEK object at current cursor position
 * Returns:
 *  NTDS_BAD_RECORD if record is not a PEK
 */
int NTDS_NTLM_ParsePEKRecord(s_parser *parser,JET_TABLEID tableid,s_NTLM_pek_ciphered *pek_ciphered) {
	unsigned long attributeSize;
	BYTE attributeVal[1024];
	JET_ERR jet_err;

	RtlZeroMemory(pek_ciphered,sizeof(s_NTLM_pek_ciphered));
	attributeSize = sizeof(attributeVal);

	jet_err = NTDS_GetRecord(parser,tableid,parser->columndef[ID_PEK].columnid,attributeVal,&attributeSize);
	if((attributeSize!=sizeof(s_NTLM_pek_ciphered)) || (jet_err!=JET_errSuccess))
		return NTDS_BAD_RECORD;

	RtlMoveMemory(pek_ciphered,attributeVal,sizeof(s_NTLM_pek_ciphered));

	return NTDS_SUCCESS;
}


/*
 * Parse NTDS.dit file and its "datatable" table
 * Lokk for PEK, SAM account name & type, hashes, SID and hashes history if asked
 */
BOOL NTDS_NTLM_ParseDatabase(s_parser *parser,ll_ldapAccountInfo *ldapAccountInfo,s_NTLM_pek_ciphered *pek_ciphered,BOOL with_history){
	s_ldapAccountInfo ldapAccountEntry;
	JET_TABLEID tableid;
	JET_ERR jet_err;
	int success = NTDS_SUCCESS;
	int retCode;

	jet_err = JetOpenTable(parser->sesid,parser->dbid,NTDS_TBL_OBJ,NULL,0,JET_bitTableReadOnly | JET_bitTableSequential,&tableid);
	if(jet_err!=JET_errSuccess) {
		NTDS_ErrorPrint(parser,"JetOpenTable",jet_err);
		return NTDS_API_ERROR;
	}

	/* Get attributes identifiers */
	jet_err = JetGetTableColumnInfo(parser->sesid,tableid,ATT_SAM_ACCOUNT_NAME,&parser->columndef[ID_SAM_ACCOUNT_NAME],sizeof(JET_COLUMNDEF),JET_ColInfo);
	jet_err |= JetGetTableColumnInfo(parser->sesid,tableid,ATT_OBJECT_SID,&parser->columndef[ID_OBJECT_SID],sizeof(JET_COLUMNDEF),JET_ColInfo);
	jet_err |= JetGetTableColumnInfo(parser->sesid,tableid,ATT_LM_HASH,&parser->columndef[ID_LM_HASH],sizeof(JET_COLUMNDEF),JET_ColInfo);
	jet_err |= JetGetTableColumnInfo(parser->sesid,tableid,ATT_NT_HASH,&parser->columndef[ID_NT_HASH],sizeof(JET_COLUMNDEF),JET_ColInfo);
	jet_err |= JetGetTableColumnInfo(parser->sesid,tableid,ATT_PEK,&parser->columndef[ID_PEK],sizeof(JET_COLUMNDEF),JET_ColInfo);
	jet_err |= JetGetTableColumnInfo(parser->sesid,tableid,ATT_SAM_ACCOUNT_TYPE,&parser->columndef[ID_SAM_ACCOUNT_TYPE],sizeof(JET_COLUMNDEF),JET_ColInfo);

	if(with_history) {
		jet_err |= JetGetTableColumnInfo(parser->sesid,tableid,ATT_LM_HASH_HISTORY,&parser->columndef[ID_LM_HASH_HISTORY],sizeof(JET_COLUMNDEF),JET_ColInfo);
		jet_err |= JetGetTableColumnInfo(parser->sesid,tableid,ATT_NT_HASH_HISTORY,&parser->columndef[ID_NT_HASH_HISTORY],sizeof(JET_COLUMNDEF),JET_ColInfo);
	}

	if(jet_err!=JET_errSuccess) {
		NTDS_ErrorPrint(parser,"JetGetTableColumnInfo ",jet_err);
		JetCloseTable(parser->sesid,tableid);
		return NTDS_API_ERROR;
	}

	/* Parse datatable for SAM accounts */
	jet_err = JetMove(parser->sesid,tableid,JET_MoveFirst,0);
	do{
		retCode = NTDS_NTLM_ParseSAMRecord(parser,tableid,&ldapAccountEntry,with_history);
		if(retCode==NTDS_SUCCESS) {
			if(!ldapAccountInfoNew(ldapAccountInfo,&ldapAccountEntry)) {
				puts("Fatal error: not enough memory!");
				return NTDS_MEM_ERROR;
			}
		}
		else if(retCode==NTDS_MEM_ERROR) {
			puts("Fatal error: not enough memory!");
			return retCode;
		}

	}while(JetMove(parser->sesid,tableid,JET_MoveNext,0) == JET_errSuccess);
	
	if(!*ldapAccountInfo)
		success = NTDS_EMPTY_ERROR;

	/* Parse datatable for ciphered PEK */
	jet_err = JetMove(parser->sesid,tableid,JET_MoveFirst,0);
	do{
		if(NTDS_NTLM_ParsePEKRecord(parser,tableid,pek_ciphered)==NTDS_SUCCESS) {
			success = NTDS_SUCCESS;
			break;
		}
	}while(JetMove(parser->sesid,tableid,JET_MoveNext,0) == JET_errSuccess);

	jet_err = JetCloseTable(parser->sesid,tableid);
	if(jet_err!=JET_errSuccess) {
		NTDS_ErrorPrint(parser,"JetCloseTable",jet_err);
		return NTDS_API_ERROR;
	}

	return success;
}


/*
 * Try to parse a bitlocker record
 * Parsing is done through Volume GUID (TO DO: per machine name)
 */
int NTDS_Bitlocker_ParseRecord(s_parser *parser,JET_TABLEID tableid,s_bitlockerAccountInfo *bitlockerAccountEntry) {
	unsigned long attributeSize;
	BYTE attributeVal[2048];
	JET_ERR jet_err;

	RtlZeroMemory(bitlockerAccountEntry,sizeof(s_bitlockerAccountInfo));


	/* Parse per Volume GUID */
	attributeSize = sizeof(attributeVal);
	jet_err = NTDS_GetRecord(parser,tableid,parser->columndef[ID_MSFVE_VOLUME_GUID].columnid,attributeVal,&attributeSize);
	if((!attributeSize) || (jet_err!=JET_errSuccess) || (attributeSize!=sizeof(bitlockerAccountEntry->msFVE_VolumeGUID)))
		return NTDS_BAD_RECORD;

	RtlMoveMemory(&bitlockerAccountEntry->msFVE_VolumeGUID,attributeVal,attributeSize);
	
	/* Get recovery GUID */
	attributeSize = sizeof(attributeVal);
	jet_err = NTDS_GetRecord(parser,tableid,parser->columndef[ID_MSFVE_RECOVERY_GUID].columnid,attributeVal,&attributeSize);
	if((jet_err==JET_errSuccess) && (attributeSize==sizeof(bitlockerAccountEntry->msFVE_RecoveryGUID))) {
		RtlMoveMemory(&bitlockerAccountEntry->msFVE_RecoveryGUID,attributeVal,attributeSize);
	}

	/* Get recovery password */
	attributeSize = sizeof(attributeVal);
	jet_err = NTDS_GetRecord(parser,tableid,parser->columndef[ID_MSFVE_RECOVERY_PASSWORD].columnid,attributeVal,&attributeSize);
	if((jet_err==JET_errSuccess)&& (attributeSize==(sizeof(bitlockerAccountEntry->msFVE_RecoveryPassword)-2))) {
		RtlMoveMemory(&bitlockerAccountEntry->msFVE_RecoveryPassword,attributeVal,attributeSize);
	}

	/* Get key package*/
	attributeSize = sizeof(attributeVal);
	jet_err = NTDS_GetRecord(parser,tableid,parser->columndef[ID_MSFVE_KEY_PACKAGE].columnid,attributeVal,&attributeSize);
	if((jet_err==JET_errSuccess) && attributeSize) {
		bitlockerAccountEntry->msFVE_KeyPackage = (LPBYTE)VirtualAlloc(NULL,attributeSize,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
		if(!bitlockerAccountEntry->msFVE_KeyPackage)
			return NTDS_MEM_ERROR;
		RtlMoveMemory(bitlockerAccountEntry->msFVE_KeyPackage,attributeVal,attributeSize);
		bitlockerAccountEntry->dwSzKeyPackage = attributeSize;
	}

	return NTDS_SUCCESS;
}


/*
 * Parse NTDS file database and extract bitlocker related attributes
 * (Key package, recovery password, recovery guid, volume id)
 */
int NTDS_Bitlocker_ParseDatabase(s_parser *parser,ll_bitlockerAccountInfo *bitlockerAccountInfo) {
	s_bitlockerAccountInfo bitlockerAccountEntry;
	JET_TABLEID tableid;
	JET_ERR jet_err;
	int success = NTDS_SUCCESS;
	int retCode;

	jet_err = JetOpenTable(parser->sesid,parser->dbid,NTDS_TBL_OBJ,NULL,0,JET_bitTableReadOnly | JET_bitTableSequential,&tableid);
	if(jet_err!=JET_errSuccess) {
		NTDS_ErrorPrint(parser,"JetOpenTable",jet_err);
		return NTDS_API_ERROR;
	}

	/* Get attributes identifiers */
	jet_err = JetGetTableColumnInfo(parser->sesid,tableid,ATT_BITLOCKER_MSFVE_KEY_PACKAGE,&parser->columndef[ID_MSFVE_KEY_PACKAGE],sizeof(JET_COLUMNDEF),JET_ColInfo);
	jet_err |= JetGetTableColumnInfo(parser->sesid,tableid,ATT_BITLOCKER_MSFVE_RECOVERY_GUID,&parser->columndef[ID_MSFVE_RECOVERY_GUID],sizeof(JET_COLUMNDEF),JET_ColInfo);
	jet_err |= JetGetTableColumnInfo(parser->sesid,tableid,ATT_BITLOCKER_MSFVE_RECOVERY_PASSWORD,&parser->columndef[ID_MSFVE_RECOVERY_PASSWORD],sizeof(JET_COLUMNDEF),JET_ColInfo);
	jet_err |= JetGetTableColumnInfo(parser->sesid,tableid,ATT_BITLOCKER_MSFVE_VOLUME_GUID,&parser->columndef[ID_MSFVE_VOLUME_GUID],sizeof(JET_COLUMNDEF),JET_ColInfo);

	if(jet_err!=JET_errSuccess) {
		NTDS_ErrorPrint(parser,"JetGetTableColumnInfo ",jet_err);
		JetCloseTable(parser->sesid,tableid);
		return NTDS_API_ERROR;
	}

	/* Parse datatable for Bitlocker accounts */
	jet_err = JetMove(parser->sesid,tableid,JET_MoveFirst,0);
	do{
		retCode = NTDS_Bitlocker_ParseRecord(parser,tableid,&bitlockerAccountEntry);
		if(retCode==NTDS_SUCCESS) {
			if(!bitlockerAccountInfoNew(bitlockerAccountInfo,&bitlockerAccountEntry)) {
				puts("Fatal error: not enough memory!");
				return NTDS_MEM_ERROR;
			}
		}
		else if(retCode==NTDS_MEM_ERROR) {
			puts("Fatal error: not enough memory!");
			return retCode;
		}
	}while(JetMove(parser->sesid,tableid,JET_MoveNext,0) == JET_errSuccess);

	if(!*bitlockerAccountInfo)
		success = NTDS_EMPTY_ERROR;

	jet_err = JetCloseTable(parser->sesid,tableid);
	if(jet_err!=JET_errSuccess) {
		NTDS_ErrorPrint(parser,"JetCloseTable",jet_err);
		return NTDS_API_ERROR;
	}

	return success;
}
