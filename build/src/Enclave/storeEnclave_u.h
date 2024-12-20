#ifndef STOREENCLAVE_U_H__
#define STOREENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "sgx_tseal.h"
#include "sgx_trts.h"
#include "constVar.h"
#include "chunkStructure.h"
#include "stdbool.h"
#include "sgx_key_exchange.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_SGX_EXIT_ERROR_DEFINED__
#define OCALL_SGX_EXIT_ERROR_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_SGX_Exit_Error, (const char* error_msg));
#endif
#ifndef OCALL_PRINTF_DEFINED__
#define OCALL_PRINTF_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_Printf, (const char* str));
#endif
#ifndef OCALL_PRINTFBINARY_DEFINED__
#define OCALL_PRINTFBINARY_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_PrintfBinary, (const uint8_t* buffer, size_t len));
#endif
#ifndef OCALL_WRITECONTAINER_DEFINED__
#define OCALL_WRITECONTAINER_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_WriteContainer, (void* outClient));
#endif
#ifndef OCALL_UPDATEINDEXSTOREBUFFER_DEFINED__
#define OCALL_UPDATEINDEXSTOREBUFFER_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_UpdateIndexStoreBuffer, (bool* ret, const char* key, size_t keySize, const uint8_t* buffer, size_t bufferSize));
#endif
#ifndef OCALL_READINDEXSTORE_DEFINED__
#define OCALL_READINDEXSTORE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_ReadIndexStore, (bool* ret, const char* key, size_t keySize, uint8_t** retVal, size_t* expectedRetValSize, void* outClient));
#endif
#ifndef OCALL_READINDEXSTOREBRIEF_DEFINED__
#define OCALL_READINDEXSTOREBRIEF_DEFINED__
bool SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_ReadIndexStoreBrief, (const char* key, size_t keySize, void* outClient));
#endif
#ifndef OCALL_INITWRITESEALEDFILE_DEFINED__
#define OCALL_INITWRITESEALEDFILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_InitWriteSealedFile, (bool* ret, const char* sealedFileName));
#endif
#ifndef OCALL_CLOSEWRITESEALEDFILE_DEFINED__
#define OCALL_CLOSEWRITESEALEDFILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_CloseWriteSealedFile, (const char* sealedFileName));
#endif
#ifndef OCALL_WRITESEALEDDATA_DEFINED__
#define OCALL_WRITESEALEDDATA_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_WriteSealedData, (const char* sealedFileName, uint8_t* sealedDataBuffer, size_t sealedDataSize));
#endif
#ifndef OCALL_INITREADSEALEDFILE_DEFINED__
#define OCALL_INITREADSEALEDFILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_InitReadSealedFile, (uint64_t* fileSize, const char* sealedFileName));
#endif
#ifndef OCALL_CLOSEREADSEALEDFILE_DEFINED__
#define OCALL_CLOSEREADSEALEDFILE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_CloseReadSealedFile, (const char* sealedFileName));
#endif
#ifndef OCALL_READSEALEDDATA_DEFINED__
#define OCALL_READSEALEDDATA_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_ReadSealedData, (const char* sealedFileName, uint8_t* dataBuffer, uint32_t sealedDataSize));
#endif
#ifndef OCALL_GETCURRENTTIME_DEFINED__
#define OCALL_GETCURRENTTIME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_GetCurrentTime, (uint64_t* retTime));
#endif
#ifndef OCALL_GETREQCONTAINERS_DEFINED__
#define OCALL_GETREQCONTAINERS_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_GetReqContainers, (void* outClient));
#endif
#ifndef OCALL_GETREQCONTAINERS_MR_DEFINED__
#define OCALL_GETREQCONTAINERS_MR_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_GetReqContainers_MR, (void* outClient));
#endif
#ifndef OCALL_SENDRESTOREDATA_DEFINED__
#define OCALL_SENDRESTOREDATA_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_SendRestoreData, (void* outClient));
#endif
#ifndef OCALL_SENDMIGRATIONDATA_DEFINED__
#define OCALL_SENDMIGRATIONDATA_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_SendMigrationData, (void* outClient));
#endif
#ifndef OCALL_QUERYOUTINDEX_DEFINED__
#define OCALL_QUERYOUTINDEX_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_QueryOutIndex, (void* outClient));
#endif
#ifndef OCALL_QUERYOUTINDEXRT_DEFINED__
#define OCALL_QUERYOUTINDEXRT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_QueryOutIndexRT, (void* outClient));
#endif
#ifndef OCALL_RESTOREGETCONTAINERNAME_DEFINED__
#define OCALL_RESTOREGETCONTAINERNAME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_RestoreGetContainerName, (void* outClient));
#endif
#ifndef OCALL_UPDATEOUTINDEX_DEFINED__
#define OCALL_UPDATEOUTINDEX_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_UpdateOutIndex, (void* outClient));
#endif
#ifndef OCALL_UPDATEFILERECIPE_DEFINED__
#define OCALL_UPDATEFILERECIPE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_UpdateFileRecipe, (void* outClient));
#endif
#ifndef OCALL_CREATEUUID_DEFINED__
#define OCALL_CREATEUUID_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_CreateUUID, (uint8_t* id, size_t len));
#endif
#ifndef OCALL_MIGRATIONGETCONTAINERNAME_DEFINED__
#define OCALL_MIGRATIONGETCONTAINERNAME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_MigrationGetContainerName, (void* outClient));
#endif
#ifndef OCALL_SENDSECRECIPE_DEFINED__
#define OCALL_SENDSECRECIPE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_SendSecRecipe, (void* outClient));
#endif
#ifndef OCALL_WRITECONTAINERRT_DEFINED__
#define OCALL_WRITECONTAINERRT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_WriteContainerRT, (void* outClient));
#endif
#ifndef OCALL_UPDATEOUTINDEXRT_DEFINED__
#define OCALL_UPDATEOUTINDEXRT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_UpdateOutIndexRT, (void* outClient));
#endif
#ifndef OCALL_CLEARFPINDEX_DEFINED__
#define OCALL_CLEARFPINDEX_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, Ocall_ClearFpIndex, (void));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif
#ifndef U_SGXSSL_FTIME_DEFINED__
#define U_SGXSSL_FTIME_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, u_sgxssl_ftime, (void* timeptr, uint32_t timeb_len));
#endif
#ifndef PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
#define PTHREAD_WAIT_TIMEOUT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wait_timeout_ocall, (unsigned long long waiter, unsigned long long timeout));
#endif
#ifndef PTHREAD_CREATE_OCALL_DEFINED__
#define PTHREAD_CREATE_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_create_ocall, (unsigned long long self));
#endif
#ifndef PTHREAD_WAKEUP_OCALL_DEFINED__
#define PTHREAD_WAKEUP_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, pthread_wakeup_ocall, (unsigned long long waiter));
#endif

sgx_status_t Ecall_Init_Upload(sgx_enclave_id_t eid, int indexType);
sgx_status_t Ecall_Destroy_Upload(sgx_enclave_id_t eid);
sgx_status_t Ecall_Init_Restore(sgx_enclave_id_t eid);
sgx_status_t Ecall_Destroy_Restore(sgx_enclave_id_t eid);
sgx_status_t Ecall_Init_Migrate(sgx_enclave_id_t eid);
sgx_status_t Ecall_Destory_Migrate(sgx_enclave_id_t eid);
sgx_status_t Ecall_ProcRecipeBatch(sgx_enclave_id_t eid, uint8_t* recipeBuffer, uint8_t* keyRecipeBuffer, size_t recipeNum, ResOutSGX_t* resOutSGX);
sgx_status_t Ecall_ProcRecipeTailBatch(sgx_enclave_id_t eid, ResOutSGX_t* resOutSGX);
sgx_status_t Ecall_ProcChunkBatch(sgx_enclave_id_t eid, SendMsgBuffer_t* recvChunkBuffer, UpOutSGX_t* upOutSGX);
sgx_status_t Ecall_ProcTailChunkBatch(sgx_enclave_id_t eid, UpOutSGX_t* upOutSGX);
sgx_status_t Ecall_Init_Client(sgx_enclave_id_t eid, uint32_t clientID, int type, int optType, uint8_t* encMasterKey, void** sgxClient);
sgx_status_t Ecall_Destroy_Client(sgx_enclave_id_t eid, void* sgxClient);
sgx_status_t Ecall_Enclave_RA_Init(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t key, int b_pse, sgx_ra_context_t* ctx, sgx_status_t* pse_status);
sgx_status_t Ecall_Enclave_RA_Close(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t ctx);
sgx_status_t Ecall_Get_RA_Key_Hash(sgx_enclave_id_t eid, sgx_ra_context_t ctx, sgx_ra_key_type_t type);
sgx_status_t Ecall_Session_Key_Exchange(sgx_enclave_id_t eid, uint8_t* publicKeyBuffer, uint32_t clientID);
sgx_status_t Ecall_Enclave_Init(sgx_enclave_id_t eid, EnclaveConfig_t* enclaveConfig);
sgx_status_t Ecall_Enclave_Destroy(sgx_enclave_id_t eid);
sgx_status_t Ecall_GetEnclaveInfo(sgx_enclave_id_t eid, EnclaveInfo_t* info);
sgx_status_t Ecall_MigrateOneBatch(sgx_enclave_id_t eid, uint8_t* recipeBuffer, size_t recipeNum, MrOutSGX_t* mrOutSGX, uint8_t* isInCloud);
sgx_status_t Ecall_MigrateTailBatch(sgx_enclave_id_t eid, MrOutSGX_t* mrOutSGX);
sgx_status_t Ecall_DownloadOneBatch(sgx_enclave_id_t eid, uint8_t* recipeBuffer, uint8_t* secRecipeBuffer, size_t recipeNum, RtOutSGX_t* rtOutSGX);
sgx_status_t Ecall_DownloadTailBatch(sgx_enclave_id_t eid, RtOutSGX_t* rtOutSGX);
sgx_status_t Ecall_ProcessOneBatchChunk(sgx_enclave_id_t eid, uint8_t* chunkContentBuffer, size_t chunkNum, RtOutSGX_t* rtOutSGX);
sgx_status_t Ecall_ProcessTailBatchChunk(sgx_enclave_id_t eid, RtOutSGX_t* rtOutSGX);
sgx_status_t sgx_ra_get_ga(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, sgx_ec256_public_t* g_a);
sgx_status_t sgx_ra_proc_msg2_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, const sgx_ra_msg2_t* p_msg2, const sgx_target_info_t* p_qe_target, sgx_report_t* p_report, sgx_quote_nonce_t* p_nonce);
sgx_status_t sgx_ra_get_msg3_trusted(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ra_context_t context, uint32_t quote_size, sgx_report_t* qe_report, sgx_ra_msg3_t* p_msg3, uint32_t msg3_size);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
