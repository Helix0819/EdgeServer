#include "storeEnclave_u.h"
#include <errno.h>

typedef struct ms_Ecall_Init_Upload_t {
	int ms_indexType;
} ms_Ecall_Init_Upload_t;

typedef struct ms_Ecall_ProcRecipeBatch_t {
	uint8_t* ms_recipeBuffer;
	uint8_t* ms_keyRecipeBuffer;
	size_t ms_recipeNum;
	ResOutSGX_t* ms_resOutSGX;
} ms_Ecall_ProcRecipeBatch_t;

typedef struct ms_Ecall_ProcRecipeTailBatch_t {
	ResOutSGX_t* ms_resOutSGX;
} ms_Ecall_ProcRecipeTailBatch_t;

typedef struct ms_Ecall_ProcChunkBatch_t {
	SendMsgBuffer_t* ms_recvChunkBuffer;
	UpOutSGX_t* ms_upOutSGX;
} ms_Ecall_ProcChunkBatch_t;

typedef struct ms_Ecall_ProcTailChunkBatch_t {
	UpOutSGX_t* ms_upOutSGX;
} ms_Ecall_ProcTailChunkBatch_t;

typedef struct ms_Ecall_Init_Client_t {
	uint32_t ms_clientID;
	int ms_type;
	int ms_optType;
	uint8_t* ms_encMasterKey;
	void** ms_sgxClient;
} ms_Ecall_Init_Client_t;

typedef struct ms_Ecall_Destroy_Client_t {
	void* ms_sgxClient;
} ms_Ecall_Destroy_Client_t;

typedef struct ms_Ecall_Enclave_RA_Init_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t ms_key;
	int ms_b_pse;
	sgx_ra_context_t* ms_ctx;
	sgx_status_t* ms_pse_status;
} ms_Ecall_Enclave_RA_Init_t;

typedef struct ms_Ecall_Enclave_RA_Close_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_ctx;
} ms_Ecall_Enclave_RA_Close_t;

typedef struct ms_Ecall_Get_RA_Key_Hash_t {
	sgx_ra_context_t ms_ctx;
	sgx_ra_key_type_t ms_type;
} ms_Ecall_Get_RA_Key_Hash_t;

typedef struct ms_Ecall_Session_Key_Exchange_t {
	uint8_t* ms_publicKeyBuffer;
	uint32_t ms_clientID;
} ms_Ecall_Session_Key_Exchange_t;

typedef struct ms_Ecall_Enclave_Init_t {
	EnclaveConfig_t* ms_enclaveConfig;
} ms_Ecall_Enclave_Init_t;

typedef struct ms_Ecall_GetEnclaveInfo_t {
	EnclaveInfo_t* ms_info;
} ms_Ecall_GetEnclaveInfo_t;

typedef struct ms_Ecall_MigrateOneBatch_t {
	uint8_t* ms_recipeBuffer;
	size_t ms_recipeNum;
	MrOutSGX_t* ms_mrOutSGX;
	uint8_t* ms_isInCloud;
} ms_Ecall_MigrateOneBatch_t;

typedef struct ms_Ecall_MigrateTailBatch_t {
	MrOutSGX_t* ms_mrOutSGX;
} ms_Ecall_MigrateTailBatch_t;

typedef struct ms_Ecall_DownloadOneBatch_t {
	uint8_t* ms_recipeBuffer;
	uint8_t* ms_secRecipeBuffer;
	size_t ms_recipeNum;
	RtOutSGX_t* ms_rtOutSGX;
} ms_Ecall_DownloadOneBatch_t;

typedef struct ms_Ecall_DownloadTailBatch_t {
	RtOutSGX_t* ms_rtOutSGX;
} ms_Ecall_DownloadTailBatch_t;

typedef struct ms_Ecall_ProcessOneBatchChunk_t {
	uint8_t* ms_chunkContentBuffer;
	size_t ms_chunkNum;
	RtOutSGX_t* ms_rtOutSGX;
} ms_Ecall_ProcessOneBatchChunk_t;

typedef struct ms_Ecall_ProcessTailBatchChunk_t {
	RtOutSGX_t* ms_rtOutSGX;
} ms_Ecall_ProcessTailBatchChunk_t;

typedef struct ms_sgx_ra_get_ga_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	sgx_ec256_public_t* ms_g_a;
} ms_sgx_ra_get_ga_t;

typedef struct ms_sgx_ra_proc_msg2_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	const sgx_ra_msg2_t* ms_p_msg2;
	const sgx_target_info_t* ms_p_qe_target;
	sgx_report_t* ms_p_report;
	sgx_quote_nonce_t* ms_p_nonce;
} ms_sgx_ra_proc_msg2_trusted_t;

typedef struct ms_sgx_ra_get_msg3_trusted_t {
	sgx_status_t ms_retval;
	sgx_ra_context_t ms_context;
	uint32_t ms_quote_size;
	sgx_report_t* ms_qe_report;
	sgx_ra_msg3_t* ms_p_msg3;
	uint32_t ms_msg3_size;
} ms_sgx_ra_get_msg3_trusted_t;

typedef struct ms_Ocall_SGX_Exit_Error_t {
	const char* ms_error_msg;
} ms_Ocall_SGX_Exit_Error_t;

typedef struct ms_Ocall_Printf_t {
	const char* ms_str;
} ms_Ocall_Printf_t;

typedef struct ms_Ocall_PrintfBinary_t {
	const uint8_t* ms_buffer;
	size_t ms_len;
} ms_Ocall_PrintfBinary_t;

typedef struct ms_Ocall_WriteContainer_t {
	void* ms_outClient;
} ms_Ocall_WriteContainer_t;

typedef struct ms_Ocall_UpdateIndexStoreBuffer_t {
	bool* ms_ret;
	const char* ms_key;
	size_t ms_keySize;
	const uint8_t* ms_buffer;
	size_t ms_bufferSize;
} ms_Ocall_UpdateIndexStoreBuffer_t;

typedef struct ms_Ocall_ReadIndexStore_t {
	bool* ms_ret;
	const char* ms_key;
	size_t ms_keySize;
	uint8_t** ms_retVal;
	size_t* ms_expectedRetValSize;
	void* ms_outClient;
} ms_Ocall_ReadIndexStore_t;

typedef struct ms_Ocall_ReadIndexStoreBrief_t {
	bool ms_retval;
	const char* ms_key;
	size_t ms_keySize;
	void* ms_outClient;
} ms_Ocall_ReadIndexStoreBrief_t;

typedef struct ms_Ocall_InitWriteSealedFile_t {
	bool* ms_ret;
	const char* ms_sealedFileName;
} ms_Ocall_InitWriteSealedFile_t;

typedef struct ms_Ocall_CloseWriteSealedFile_t {
	const char* ms_sealedFileName;
} ms_Ocall_CloseWriteSealedFile_t;

typedef struct ms_Ocall_WriteSealedData_t {
	const char* ms_sealedFileName;
	uint8_t* ms_sealedDataBuffer;
	size_t ms_sealedDataSize;
} ms_Ocall_WriteSealedData_t;

typedef struct ms_Ocall_InitReadSealedFile_t {
	uint64_t* ms_fileSize;
	const char* ms_sealedFileName;
} ms_Ocall_InitReadSealedFile_t;

typedef struct ms_Ocall_CloseReadSealedFile_t {
	const char* ms_sealedFileName;
} ms_Ocall_CloseReadSealedFile_t;

typedef struct ms_Ocall_ReadSealedData_t {
	const char* ms_sealedFileName;
	uint8_t* ms_dataBuffer;
	uint32_t ms_sealedDataSize;
} ms_Ocall_ReadSealedData_t;

typedef struct ms_Ocall_GetCurrentTime_t {
	uint64_t* ms_retTime;
} ms_Ocall_GetCurrentTime_t;

typedef struct ms_Ocall_GetReqContainers_t {
	void* ms_outClient;
} ms_Ocall_GetReqContainers_t;

typedef struct ms_Ocall_GetReqContainers_MR_t {
	void* ms_outClient;
} ms_Ocall_GetReqContainers_MR_t;

typedef struct ms_Ocall_SendRestoreData_t {
	void* ms_outClient;
} ms_Ocall_SendRestoreData_t;

typedef struct ms_Ocall_SendMigrationData_t {
	void* ms_outClient;
} ms_Ocall_SendMigrationData_t;

typedef struct ms_Ocall_QueryOutIndex_t {
	void* ms_outClient;
} ms_Ocall_QueryOutIndex_t;

typedef struct ms_Ocall_QueryOutIndexRT_t {
	void* ms_outClient;
} ms_Ocall_QueryOutIndexRT_t;

typedef struct ms_Ocall_RestoreGetContainerName_t {
	void* ms_outClient;
} ms_Ocall_RestoreGetContainerName_t;

typedef struct ms_Ocall_UpdateOutIndex_t {
	void* ms_outClient;
} ms_Ocall_UpdateOutIndex_t;

typedef struct ms_Ocall_UpdateFileRecipe_t {
	void* ms_outClient;
} ms_Ocall_UpdateFileRecipe_t;

typedef struct ms_Ocall_CreateUUID_t {
	uint8_t* ms_id;
	size_t ms_len;
} ms_Ocall_CreateUUID_t;

typedef struct ms_Ocall_MigrationGetContainerName_t {
	void* ms_outClient;
} ms_Ocall_MigrationGetContainerName_t;

typedef struct ms_Ocall_SendSecRecipe_t {
	void* ms_outClient;
} ms_Ocall_SendSecRecipe_t;

typedef struct ms_Ocall_WriteContainerRT_t {
	void* ms_outClient;
} ms_Ocall_WriteContainerRT_t;

typedef struct ms_Ocall_UpdateOutIndexRT_t {
	void* ms_outClient;
} ms_Ocall_UpdateOutIndexRT_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

typedef struct ms_u_sgxssl_ftime_t {
	void* ms_timeptr;
	uint32_t ms_timeb_len;
} ms_u_sgxssl_ftime_t;

typedef struct ms_pthread_wait_timeout_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
	unsigned long long ms_timeout;
} ms_pthread_wait_timeout_ocall_t;

typedef struct ms_pthread_create_ocall_t {
	int ms_retval;
	unsigned long long ms_self;
} ms_pthread_create_ocall_t;

typedef struct ms_pthread_wakeup_ocall_t {
	int ms_retval;
	unsigned long long ms_waiter;
} ms_pthread_wakeup_ocall_t;

static sgx_status_t SGX_CDECL storeEnclave_Ocall_SGX_Exit_Error(void* pms)
{
	ms_Ocall_SGX_Exit_Error_t* ms = SGX_CAST(ms_Ocall_SGX_Exit_Error_t*, pms);
	Ocall_SGX_Exit_Error(ms->ms_error_msg);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_Printf(void* pms)
{
	ms_Ocall_Printf_t* ms = SGX_CAST(ms_Ocall_Printf_t*, pms);
	Ocall_Printf(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_PrintfBinary(void* pms)
{
	ms_Ocall_PrintfBinary_t* ms = SGX_CAST(ms_Ocall_PrintfBinary_t*, pms);
	Ocall_PrintfBinary(ms->ms_buffer, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_WriteContainer(void* pms)
{
	ms_Ocall_WriteContainer_t* ms = SGX_CAST(ms_Ocall_WriteContainer_t*, pms);
	Ocall_WriteContainer(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_UpdateIndexStoreBuffer(void* pms)
{
	ms_Ocall_UpdateIndexStoreBuffer_t* ms = SGX_CAST(ms_Ocall_UpdateIndexStoreBuffer_t*, pms);
	Ocall_UpdateIndexStoreBuffer(ms->ms_ret, ms->ms_key, ms->ms_keySize, ms->ms_buffer, ms->ms_bufferSize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_ReadIndexStore(void* pms)
{
	ms_Ocall_ReadIndexStore_t* ms = SGX_CAST(ms_Ocall_ReadIndexStore_t*, pms);
	Ocall_ReadIndexStore(ms->ms_ret, ms->ms_key, ms->ms_keySize, ms->ms_retVal, ms->ms_expectedRetValSize, ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_ReadIndexStoreBrief(void* pms)
{
	ms_Ocall_ReadIndexStoreBrief_t* ms = SGX_CAST(ms_Ocall_ReadIndexStoreBrief_t*, pms);
	ms->ms_retval = Ocall_ReadIndexStoreBrief(ms->ms_key, ms->ms_keySize, ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_InitWriteSealedFile(void* pms)
{
	ms_Ocall_InitWriteSealedFile_t* ms = SGX_CAST(ms_Ocall_InitWriteSealedFile_t*, pms);
	Ocall_InitWriteSealedFile(ms->ms_ret, ms->ms_sealedFileName);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_CloseWriteSealedFile(void* pms)
{
	ms_Ocall_CloseWriteSealedFile_t* ms = SGX_CAST(ms_Ocall_CloseWriteSealedFile_t*, pms);
	Ocall_CloseWriteSealedFile(ms->ms_sealedFileName);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_WriteSealedData(void* pms)
{
	ms_Ocall_WriteSealedData_t* ms = SGX_CAST(ms_Ocall_WriteSealedData_t*, pms);
	Ocall_WriteSealedData(ms->ms_sealedFileName, ms->ms_sealedDataBuffer, ms->ms_sealedDataSize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_InitReadSealedFile(void* pms)
{
	ms_Ocall_InitReadSealedFile_t* ms = SGX_CAST(ms_Ocall_InitReadSealedFile_t*, pms);
	Ocall_InitReadSealedFile(ms->ms_fileSize, ms->ms_sealedFileName);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_CloseReadSealedFile(void* pms)
{
	ms_Ocall_CloseReadSealedFile_t* ms = SGX_CAST(ms_Ocall_CloseReadSealedFile_t*, pms);
	Ocall_CloseReadSealedFile(ms->ms_sealedFileName);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_ReadSealedData(void* pms)
{
	ms_Ocall_ReadSealedData_t* ms = SGX_CAST(ms_Ocall_ReadSealedData_t*, pms);
	Ocall_ReadSealedData(ms->ms_sealedFileName, ms->ms_dataBuffer, ms->ms_sealedDataSize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_GetCurrentTime(void* pms)
{
	ms_Ocall_GetCurrentTime_t* ms = SGX_CAST(ms_Ocall_GetCurrentTime_t*, pms);
	Ocall_GetCurrentTime(ms->ms_retTime);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_GetReqContainers(void* pms)
{
	ms_Ocall_GetReqContainers_t* ms = SGX_CAST(ms_Ocall_GetReqContainers_t*, pms);
	Ocall_GetReqContainers(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_GetReqContainers_MR(void* pms)
{
	ms_Ocall_GetReqContainers_MR_t* ms = SGX_CAST(ms_Ocall_GetReqContainers_MR_t*, pms);
	Ocall_GetReqContainers_MR(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_SendRestoreData(void* pms)
{
	ms_Ocall_SendRestoreData_t* ms = SGX_CAST(ms_Ocall_SendRestoreData_t*, pms);
	Ocall_SendRestoreData(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_SendMigrationData(void* pms)
{
	ms_Ocall_SendMigrationData_t* ms = SGX_CAST(ms_Ocall_SendMigrationData_t*, pms);
	Ocall_SendMigrationData(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_QueryOutIndex(void* pms)
{
	ms_Ocall_QueryOutIndex_t* ms = SGX_CAST(ms_Ocall_QueryOutIndex_t*, pms);
	Ocall_QueryOutIndex(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_QueryOutIndexRT(void* pms)
{
	ms_Ocall_QueryOutIndexRT_t* ms = SGX_CAST(ms_Ocall_QueryOutIndexRT_t*, pms);
	Ocall_QueryOutIndexRT(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_RestoreGetContainerName(void* pms)
{
	ms_Ocall_RestoreGetContainerName_t* ms = SGX_CAST(ms_Ocall_RestoreGetContainerName_t*, pms);
	Ocall_RestoreGetContainerName(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_UpdateOutIndex(void* pms)
{
	ms_Ocall_UpdateOutIndex_t* ms = SGX_CAST(ms_Ocall_UpdateOutIndex_t*, pms);
	Ocall_UpdateOutIndex(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_UpdateFileRecipe(void* pms)
{
	ms_Ocall_UpdateFileRecipe_t* ms = SGX_CAST(ms_Ocall_UpdateFileRecipe_t*, pms);
	Ocall_UpdateFileRecipe(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_CreateUUID(void* pms)
{
	ms_Ocall_CreateUUID_t* ms = SGX_CAST(ms_Ocall_CreateUUID_t*, pms);
	Ocall_CreateUUID(ms->ms_id, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_MigrationGetContainerName(void* pms)
{
	ms_Ocall_MigrationGetContainerName_t* ms = SGX_CAST(ms_Ocall_MigrationGetContainerName_t*, pms);
	Ocall_MigrationGetContainerName(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_SendSecRecipe(void* pms)
{
	ms_Ocall_SendSecRecipe_t* ms = SGX_CAST(ms_Ocall_SendSecRecipe_t*, pms);
	Ocall_SendSecRecipe(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_WriteContainerRT(void* pms)
{
	ms_Ocall_WriteContainerRT_t* ms = SGX_CAST(ms_Ocall_WriteContainerRT_t*, pms);
	Ocall_WriteContainerRT(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_UpdateOutIndexRT(void* pms)
{
	ms_Ocall_UpdateOutIndexRT_t* ms = SGX_CAST(ms_Ocall_UpdateOutIndexRT_t*, pms);
	Ocall_UpdateOutIndexRT(ms->ms_outClient);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_Ocall_ClearFpIndex(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	Ocall_ClearFpIndex();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_u_sgxssl_ftime(void* pms)
{
	ms_u_sgxssl_ftime_t* ms = SGX_CAST(ms_u_sgxssl_ftime_t*, pms);
	u_sgxssl_ftime(ms->ms_timeptr, ms->ms_timeb_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_pthread_wait_timeout_ocall(void* pms)
{
	ms_pthread_wait_timeout_ocall_t* ms = SGX_CAST(ms_pthread_wait_timeout_ocall_t*, pms);
	ms->ms_retval = pthread_wait_timeout_ocall(ms->ms_waiter, ms->ms_timeout);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_pthread_create_ocall(void* pms)
{
	ms_pthread_create_ocall_t* ms = SGX_CAST(ms_pthread_create_ocall_t*, pms);
	ms->ms_retval = pthread_create_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL storeEnclave_pthread_wakeup_ocall(void* pms)
{
	ms_pthread_wakeup_ocall_t* ms = SGX_CAST(ms_pthread_wakeup_ocall_t*, pms);
	ms->ms_retval = pthread_wakeup_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[38];
} ocall_table_storeEnclave = {
	38,
	{
		(void*)storeEnclave_Ocall_SGX_Exit_Error,
		(void*)storeEnclave_Ocall_Printf,
		(void*)storeEnclave_Ocall_PrintfBinary,
		(void*)storeEnclave_Ocall_WriteContainer,
		(void*)storeEnclave_Ocall_UpdateIndexStoreBuffer,
		(void*)storeEnclave_Ocall_ReadIndexStore,
		(void*)storeEnclave_Ocall_ReadIndexStoreBrief,
		(void*)storeEnclave_Ocall_InitWriteSealedFile,
		(void*)storeEnclave_Ocall_CloseWriteSealedFile,
		(void*)storeEnclave_Ocall_WriteSealedData,
		(void*)storeEnclave_Ocall_InitReadSealedFile,
		(void*)storeEnclave_Ocall_CloseReadSealedFile,
		(void*)storeEnclave_Ocall_ReadSealedData,
		(void*)storeEnclave_Ocall_GetCurrentTime,
		(void*)storeEnclave_Ocall_GetReqContainers,
		(void*)storeEnclave_Ocall_GetReqContainers_MR,
		(void*)storeEnclave_Ocall_SendRestoreData,
		(void*)storeEnclave_Ocall_SendMigrationData,
		(void*)storeEnclave_Ocall_QueryOutIndex,
		(void*)storeEnclave_Ocall_QueryOutIndexRT,
		(void*)storeEnclave_Ocall_RestoreGetContainerName,
		(void*)storeEnclave_Ocall_UpdateOutIndex,
		(void*)storeEnclave_Ocall_UpdateFileRecipe,
		(void*)storeEnclave_Ocall_CreateUUID,
		(void*)storeEnclave_Ocall_MigrationGetContainerName,
		(void*)storeEnclave_Ocall_SendSecRecipe,
		(void*)storeEnclave_Ocall_WriteContainerRT,
		(void*)storeEnclave_Ocall_UpdateOutIndexRT,
		(void*)storeEnclave_Ocall_ClearFpIndex,
		(void*)storeEnclave_sgx_oc_cpuidex,
		(void*)storeEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)storeEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)storeEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)storeEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
		(void*)storeEnclave_u_sgxssl_ftime,
		(void*)storeEnclave_pthread_wait_timeout_ocall,
		(void*)storeEnclave_pthread_create_ocall,
		(void*)storeEnclave_pthread_wakeup_ocall,
	}
};
sgx_status_t Ecall_Init_Upload(sgx_enclave_id_t eid, int indexType)
{
	sgx_status_t status;
	ms_Ecall_Init_Upload_t ms;
	ms.ms_indexType = indexType;
	status = sgx_ecall(eid, 0, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_Destroy_Upload(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_storeEnclave, NULL);
	return status;
}

sgx_status_t Ecall_Init_Restore(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_storeEnclave, NULL);
	return status;
}

sgx_status_t Ecall_Destroy_Restore(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_storeEnclave, NULL);
	return status;
}

sgx_status_t Ecall_Init_Migrate(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 4, &ocall_table_storeEnclave, NULL);
	return status;
}

sgx_status_t Ecall_Destory_Migrate(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 5, &ocall_table_storeEnclave, NULL);
	return status;
}

sgx_status_t Ecall_ProcRecipeBatch(sgx_enclave_id_t eid, uint8_t* recipeBuffer, uint8_t* keyRecipeBuffer, size_t recipeNum, ResOutSGX_t* resOutSGX)
{
	sgx_status_t status;
	ms_Ecall_ProcRecipeBatch_t ms;
	ms.ms_recipeBuffer = recipeBuffer;
	ms.ms_keyRecipeBuffer = keyRecipeBuffer;
	ms.ms_recipeNum = recipeNum;
	ms.ms_resOutSGX = resOutSGX;
	status = sgx_ecall(eid, 6, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_ProcRecipeTailBatch(sgx_enclave_id_t eid, ResOutSGX_t* resOutSGX)
{
	sgx_status_t status;
	ms_Ecall_ProcRecipeTailBatch_t ms;
	ms.ms_resOutSGX = resOutSGX;
	status = sgx_ecall(eid, 7, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_ProcChunkBatch(sgx_enclave_id_t eid, SendMsgBuffer_t* recvChunkBuffer, UpOutSGX_t* upOutSGX)
{
	sgx_status_t status;
	ms_Ecall_ProcChunkBatch_t ms;
	ms.ms_recvChunkBuffer = recvChunkBuffer;
	ms.ms_upOutSGX = upOutSGX;
	status = sgx_ecall(eid, 8, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_ProcTailChunkBatch(sgx_enclave_id_t eid, UpOutSGX_t* upOutSGX)
{
	sgx_status_t status;
	ms_Ecall_ProcTailChunkBatch_t ms;
	ms.ms_upOutSGX = upOutSGX;
	status = sgx_ecall(eid, 9, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_Init_Client(sgx_enclave_id_t eid, uint32_t clientID, int type, int optType, uint8_t* encMasterKey, void** sgxClient)
{
	sgx_status_t status;
	ms_Ecall_Init_Client_t ms;
	ms.ms_clientID = clientID;
	ms.ms_type = type;
	ms.ms_optType = optType;
	ms.ms_encMasterKey = encMasterKey;
	ms.ms_sgxClient = sgxClient;
	status = sgx_ecall(eid, 10, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_Destroy_Client(sgx_enclave_id_t eid, void* sgxClient)
{
	sgx_status_t status;
	ms_Ecall_Destroy_Client_t ms;
	ms.ms_sgxClient = sgxClient;
	status = sgx_ecall(eid, 11, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_Enclave_RA_Init(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t key, int b_pse, sgx_ra_context_t* ctx, sgx_status_t* pse_status)
{
	sgx_status_t status;
	ms_Ecall_Enclave_RA_Init_t ms;
	ms.ms_key = key;
	ms.ms_b_pse = b_pse;
	ms.ms_ctx = ctx;
	ms.ms_pse_status = pse_status;
	status = sgx_ecall(eid, 12, &ocall_table_storeEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Ecall_Enclave_RA_Close(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t ctx)
{
	sgx_status_t status;
	ms_Ecall_Enclave_RA_Close_t ms;
	ms.ms_ctx = ctx;
	status = sgx_ecall(eid, 13, &ocall_table_storeEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t Ecall_Get_RA_Key_Hash(sgx_enclave_id_t eid, sgx_ra_context_t ctx, sgx_ra_key_type_t type)
{
	sgx_status_t status;
	ms_Ecall_Get_RA_Key_Hash_t ms;
	ms.ms_ctx = ctx;
	ms.ms_type = type;
	status = sgx_ecall(eid, 14, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_Session_Key_Exchange(sgx_enclave_id_t eid, uint8_t* publicKeyBuffer, uint32_t clientID)
{
	sgx_status_t status;
	ms_Ecall_Session_Key_Exchange_t ms;
	ms.ms_publicKeyBuffer = publicKeyBuffer;
	ms.ms_clientID = clientID;
	status = sgx_ecall(eid, 15, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_Enclave_Init(sgx_enclave_id_t eid, EnclaveConfig_t* enclaveConfig)
{
	sgx_status_t status;
	ms_Ecall_Enclave_Init_t ms;
	ms.ms_enclaveConfig = enclaveConfig;
	status = sgx_ecall(eid, 16, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_Enclave_Destroy(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 17, &ocall_table_storeEnclave, NULL);
	return status;
}

sgx_status_t Ecall_GetEnclaveInfo(sgx_enclave_id_t eid, EnclaveInfo_t* info)
{
	sgx_status_t status;
	ms_Ecall_GetEnclaveInfo_t ms;
	ms.ms_info = info;
	status = sgx_ecall(eid, 18, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_MigrateOneBatch(sgx_enclave_id_t eid, uint8_t* recipeBuffer, size_t recipeNum, MrOutSGX_t* mrOutSGX, uint8_t* isInCloud)
{
	sgx_status_t status;
	ms_Ecall_MigrateOneBatch_t ms;
	ms.ms_recipeBuffer = recipeBuffer;
	ms.ms_recipeNum = recipeNum;
	ms.ms_mrOutSGX = mrOutSGX;
	ms.ms_isInCloud = isInCloud;
	status = sgx_ecall(eid, 19, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_MigrateTailBatch(sgx_enclave_id_t eid, MrOutSGX_t* mrOutSGX)
{
	sgx_status_t status;
	ms_Ecall_MigrateTailBatch_t ms;
	ms.ms_mrOutSGX = mrOutSGX;
	status = sgx_ecall(eid, 20, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_DownloadOneBatch(sgx_enclave_id_t eid, uint8_t* recipeBuffer, uint8_t* secRecipeBuffer, size_t recipeNum, RtOutSGX_t* rtOutSGX)
{
	sgx_status_t status;
	ms_Ecall_DownloadOneBatch_t ms;
	ms.ms_recipeBuffer = recipeBuffer;
	ms.ms_secRecipeBuffer = secRecipeBuffer;
	ms.ms_recipeNum = recipeNum;
	ms.ms_rtOutSGX = rtOutSGX;
	status = sgx_ecall(eid, 21, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_DownloadTailBatch(sgx_enclave_id_t eid, RtOutSGX_t* rtOutSGX)
{
	sgx_status_t status;
	ms_Ecall_DownloadTailBatch_t ms;
	ms.ms_rtOutSGX = rtOutSGX;
	status = sgx_ecall(eid, 22, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_ProcessOneBatchChunk(sgx_enclave_id_t eid, uint8_t* chunkContentBuffer, size_t chunkNum, RtOutSGX_t* rtOutSGX)
{
	sgx_status_t status;
	ms_Ecall_ProcessOneBatchChunk_t ms;
	ms.ms_chunkContentBuffer = chunkContentBuffer;
	ms.ms_chunkNum = chunkNum;
	ms.ms_rtOutSGX = rtOutSGX;
	status = sgx_ecall(eid, 23, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t Ecall_ProcessTailBatchChunk(sgx_enclave_id_t eid, RtOutSGX_t* rtOutSGX)
{
	sgx_status_t status;
	ms_Ecall_ProcessTailBatchChunk_t ms;
	ms.ms_rtOutSGX = rtOutSGX;
	status = sgx_ecall(eid, 24, &ocall_table_storeEnclave, &ms);
	return status;
}

sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a)
{
	sgx_status_t status;
	ms_sgx_ra_get_ga_t ms;
	ms.ms_context = context;
	ms.ms_g_a = g_a;
	status = sgx_ecall(eid, 25, &ocall_table_storeEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce)
{
	sgx_status_t status;
	ms_sgx_ra_proc_msg2_trusted_t ms;
	ms.ms_context = context;
	ms.ms_p_msg2 = p_msg2;
	ms.ms_p_qe_target = p_qe_target;
	ms.ms_p_report = p_report;
	ms.ms_p_nonce = p_nonce;
	status = sgx_ecall(eid, 26, &ocall_table_storeEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size)
{
	sgx_status_t status;
	ms_sgx_ra_get_msg3_trusted_t ms;
	ms.ms_context = context;
	ms.ms_quote_size = quote_size;
	ms.ms_qe_report = qe_report;
	ms.ms_p_msg3 = p_msg3;
	ms.ms_msg3_size = msg3_size;
	status = sgx_ecall(eid, 27, &ocall_table_storeEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

