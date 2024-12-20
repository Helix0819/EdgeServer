/**
 * @file ecallClient.cc
 * @author Zuoru YANG (zryang@cse.cuhk.edu.hk)
 * @brief implement enclave client class
 * @version 0.1
 * @date 2021-07-07
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include "../../include/ecallClient.h"

/**
 * @brief Construct a new Enclave Client object
 * 
 * @param clientID client ID
 * @param indexType index type
 * @param optType the operation type (upload / download)
 */
EnclaveClient::EnclaveClient(uint32_t clientID, int indexType, int optType) {
    // store the parameters
    _clientID = clientID;
    indexType_ = indexType;
    optType_ = optType;

    // init the ctx
    _cipherCtx = EVP_CIPHER_CTX_new();
    _mdCtx = EVP_MD_CTX_new();

    // get a random iv
    sgx_read_rand(_iv, CRYPTO_BLOCK_SIZE); 

    // init the buffer according to the 
    switch (optType_) {
        case UPLOAD_OPT: {
            this->InitUploadBuffer();
            break;
        }
        case DOWNLOAD_OPT: {
            this->InitRestoreBuffer();
            break;
        }
        case MIGRATE_TO_CLOUD: {
            this->InitMigrationBuffer();
            break;
        }
        case DOWNLOAD_FROM_CLOUD: {
            this->InitDownloadBuffer();
            break;
        }
        default: {
            Ocall_SGX_Exit_Error("wrong init operation type");
        }
    }
}

/**
 * @brief Destroy the Enclave Client object
 * 
 */
EnclaveClient::~EnclaveClient() {

    switch (optType_) {
        case UPLOAD_OPT: {
            this->DestroyUploadBuffer();
            break;
        }
        case DOWNLOAD_OPT: {
            this->DestroyRestoreBuffer();
            break;
        }
        case MIGRATE_TO_CLOUD: {
            this->DestroyMigrationBuffer();
            break;
        }
        case DOWNLOAD_FROM_CLOUD: {
            this->DestroyDownloadBuffer();
            break;
        }
        default: {
            Ocall_SGX_Exit_Error("EnclaveClient: wrong destroy operation type");
        }
    }
    EVP_CIPHER_CTX_free(_cipherCtx);
    EVP_MD_CTX_free(_mdCtx);
}

/**
 * @brief init the buffer used in the upload
 * 
 */
void EnclaveClient::InitUploadBuffer() {
    _recvBuffer = (uint8_t*) malloc(Enclave::sendChunkBatchSize_ * sizeof(Chunk_t));
    _inRecipe.entryList = (uint8_t*) malloc(Enclave::sendRecipeBatchSize_ *
        CHUNK_HASH_SIZE);
    _inRecipe.recipeNum = 0;

    if (indexType_ == EXTREME_BIN || indexType_ == SPARSE_INDEX) {
        _segment.buffer = (uint8_t*) malloc(MAX_SEGMENT_SIZE * sizeof(uint8_t));
        _segment.metadata = (SegmentMeta_t*) malloc((MAX_SEGMENT_SIZE / MIN_CHUNK_SIZE) * 
            sizeof(SegmentMeta_t));
        _segment.minHashVal = UINT32_MAX;
        _segment.chunkNum = 0;
        _segment.segmentSize = 0;
    }

    _inQueryBase = (InQueryEntry_t*) malloc(Enclave::sendChunkBatchSize_ * 
        sizeof(InQueryEntry_t));
    _localIndex.reserve(Enclave::sendChunkBatchSize_);
    _inContainer.headerBuf = (uint8_t*) malloc(MAX_CONTAINER_SIZE * sizeof(uint8_t));
    _inContainer.contentBuf = (uint8_t*) malloc(MAX_CONTAINER_SIZE * sizeof(uint8_t));
    _inContainer.curHeaderSize = 0;
    _inContainer.curContentSize = 0;
    _inContainer.curNum = 0;

    _inSecureRecipe.entryList = (uint8_t*) malloc(Enclave::sendRecipeBatchSize_ *
        CHUNK_HASH_SIZE);
    _inSecureRecipe.recipeNum = 0;

    _inKeyRecipe.entryList = (uint8_t*) malloc(Enclave::sendRecipeBatchSize_ *
        MLE_KEY_SIZE);
    _inKeyRecipe.recipeNum = 0;

    return ;
}

/**
 * @brief destroy the buffer used in the upload
 * 
 */
void EnclaveClient::DestroyUploadBuffer() {
    free(_recvBuffer);
    free(_inRecipe.entryList);
    free(_inSecureRecipe.entryList);
    free(_inKeyRecipe.entryList);
    if (indexType_ == EXTREME_BIN || indexType_ == SPARSE_INDEX) {
        free(_segment.buffer);
        free(_segment.metadata);
    }
    free(_inQueryBase);
    free(_inContainer.headerBuf);
    free(_inContainer.contentBuf);
    return ;
}

/**
 * @brief init the buffer used in the restore
 * 
 */
void EnclaveClient::InitRestoreBuffer() {
    // to store restore chunk
    _restoreChunkBuffer.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) +
        Enclave::sendChunkBatchSize_ * sizeof(Chunk_t));
    _restoreChunkBuffer.header = (NetworkHead_t*) _restoreChunkBuffer.sendBuffer;
    _restoreChunkBuffer.header->clientID = _clientID;
    _restoreChunkBuffer.header->currentItemNum = 0;
    _restoreChunkBuffer.header->dataSize = 0;
    _restoreChunkBuffer.dataBuffer = _restoreChunkBuffer.sendBuffer + sizeof(NetworkHead_t);

    // for recipe
    _plainRecipeBuffer = (uint8_t*) malloc(Enclave::sendRecipeBatchSize_ *
        sizeof(RecipeEntry_t));
    _plainKeyRecipeBuffer = (uint8_t*) malloc(Enclave::sendRecipeBatchSize_ *
        sizeof(keyRecipeEntry_t));

    _inRestoreBase = (InRestoreEntry_t*) malloc(Enclave::sendRecipeBatchSize_ * sizeof(InRestoreEntry_t));
    return ;
}

/**
 * @brief destroy the buffer used in the restore
 * 
 */
void EnclaveClient::DestroyRestoreBuffer() {
    free(_plainRecipeBuffer);
    free(_plainKeyRecipeBuffer);
    free(_restoreChunkBuffer.sendBuffer);
    free(_inRestoreBase);
    return ;
}

/**
 * @brief Set the Master Key object
 * 
 * @param encryptedSecret input encrypted secret
 * @param secretSize the input secret size
 */
void EnclaveClient::SetMasterKey(uint8_t* encryptedSecret, size_t secretSize) {
    EcallCrypto* crypto = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
    crypto->SessionKeyDec(_cipherCtx, encryptedSecret, secretSize,
        _sessionKey, _masterKey);
    delete crypto;
    return ;
}


void EnclaveClient::InitMigrationBuffer()
{
    //Enclave::Logging("Enclave Client", "migration buffer init\n");
    _plainRecipeBuffer_MR = (uint8_t*) malloc(Enclave::sendRecipeBatchSize_ * sizeof(RecipeEntry_t));
    // in chunk buffer
    _migrationChunkBuffer.sendBuffer = (uint8_t*) malloc(sizeof(NetworkHead_t) + 
        Enclave::sendChunkBatchSize_ * sizeof(Chunk_t));
    _migrationChunkBuffer.header = (NetworkHead_t*) _migrationChunkBuffer.sendBuffer;
    _migrationChunkBuffer.header->clientID = _clientID;
    _migrationChunkBuffer.header->currentItemNum = 0;
    _migrationChunkBuffer.header->dataSize = 0;
    _migrationChunkBuffer.dataBuffer = _migrationChunkBuffer.sendBuffer + sizeof(NetworkHead_t);

    _inMigrationBase = (InMigrationEntry_t*) malloc(Enclave::sendRecipeBatchSize_ * sizeof(InMigrationEntry_t));
    return ;
}

void EnclaveClient::DestroyMigrationBuffer()
{
    free(_plainRecipeBuffer_MR);
    free(_migrationChunkBuffer.sendBuffer);
    free(_inMigrationBase);
    return ;
}

void EnclaveClient::InitDownloadBuffer()
{
    Enclave::Logging("Enclave Client", "download from cloud buffer init\n");
    _plainRecipeBuffer_RT = (uint8_t*) malloc(Enclave::sendRecipeBatchSize_ * sizeof(RecipeEntry_t));
    _secureRecipeBuffer_RT = (uint8_t*) malloc(Enclave::sendRecipeBatchSize_ * sizeof(RecipeEntry_t));
    _inQueryBase_RT = (InQueryEntry_t*) malloc(Enclave::sendRecipeBatchSize_ * sizeof(InQueryEntry_t));
    // inContainer init 
    _inContainer_RT.headerBuf = (uint8_t*) malloc(MAX_CONTAINER_SIZE * sizeof(uint8_t));
    _inContainer_RT.contentBuf = (uint8_t*) malloc(MAX_CONTAINER_SIZE * sizeof(uint8_t));
    _inContainer_RT.curHeaderSize = 0;
    _inContainer_RT.curContentSize = 0;
    _inContainer_RT.curNum = 0;
    Enclave::Logging("Enclave Client", "download from cloud buffer done\n");
    return ;
}

void EnclaveClient::DestroyDownloadBuffer()
{
    free(_plainRecipeBuffer_RT);
    free(_secureRecipeBuffer_RT);
    free(_inQueryBase_RT);
    free(_inContainer_RT.headerBuf);
    free(_inContainer_RT.contentBuf);
    return ;
}