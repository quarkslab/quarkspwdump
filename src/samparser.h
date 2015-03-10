#pragma once

#include "common.h"
#include "utils.h"
#include "crypt.h"


/* Temporary mount point in windows registry */
#define TEMP_SAM_KEY "QUARKS-SAM"


/* SAM functions error codes */
#define SAM_SUCCESS 0
#define SAM_REG_ERROR -1 
#define SAM_MOUNT_ERROR -2 
#define SAM_MEM_ERROR -3
#define SAM_NO_ACCOUNT -4


/* Local SAM parsing (local account and domain cached */
int SAM_ParseLocalDatabase(ll_localAccountInfo *localAccountInfo,s_BOOTKEY_ciphered *bootkey_ciphered,BOOL with_history);
int SAM_ParseCachedDatabase(ll_cachedAccountInfo *cachedAccountInfo,s_LSAKEY_ciphered *lsakey_ciphered,s_NLKM_ciphered *nlkm_ciphered);

