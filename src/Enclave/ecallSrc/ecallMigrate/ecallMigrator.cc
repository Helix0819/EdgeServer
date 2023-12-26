#include "../../include/ecallMigrator.h"


void EcallMigrator::MigrateOneBatch(uint8_t* recipeBuffer, size_t recipeNum, 
    MrOutSGX_t* mrOutSGX, uint8_t* isInCloud)
{
    //TODO1: 逐个recipe看是否需要
    //Enclave::Logging(myName.c_str(), "Init Out Enclave Buffer ...\n");
    ReqContainer_t* reqContainer = (ReqContainer_t*)mrOutSGX->reqContainer;
    uint8_t* idBuffer = reqContainer->idBuffer;
    uint8_t** containerArray = reqContainer->containerArray;
    SendMsgBuffer_t* sendChunkBuffer = mrOutSGX->sendChunkBuf;

    // in buffer
    //Enclave::Logging(myName.c_str(), "Init In Enclave Buffer ...\n");
    EnclaveClient* sgxClient = (EnclaveClient*)mrOutSGX->sgxClient;

    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;

    uint8_t* plainRecipeBuffer = sgxClient->_plainRecipeBuffer_MR;

    // in-enclave info
    InMigrationEntry_t* InMigrationEntry = sgxClient->_inMigrationBase;

    outMigration_t* outMigration = mrOutSGX->outMigration;

    outMigrationEntry_t* outMigrationBase = outMigration->outMigrationBase;

    outMigrationEntry_t* outMigrationEntry = outMigrationBase;

    //Enclave::Logging(myName.c_str(), "Init In Enclave Buffer done...\n");
    // contaienr map
    string tmpContainerNameStr;
    unordered_map<string, uint32_t> tmpContainerMap;
    tmpContainerMap.reserve(CONTAINER_CAPPING_VALUE);
    // decrypt recipe once 
    cryptoObj_->DecryptWithKey(cipherCtx, recipeBuffer, recipeNum * CHUNK_HASH_SIZE,  
        Enclave::indexQueryKey_, plainRecipeBuffer);


    size_t queryNum = 0;
    for(int i = 0; i < recipeNum; i++)
    {
        if(isInCloud[i] == 1) // chunk not on cloud server
        {
            memcpy(InMigrationEntry->chunkHash, plainRecipeBuffer + i*CHUNK_HASH_SIZE, CHUNK_HASH_SIZE);
            cryptoObj_->IndexAESCMCEnc(cipherCtx, InMigrationEntry->chunkHash, CHUNK_HASH_SIZE,
                Enclave::indexQueryKey_, outMigrationEntry->chunkHash);
            InMigrationEntry++;
            outMigrationEntry++;
            queryNum++;
        }
    }

    // query FP Index
    outMigration->queryNum = queryNum;
    Ocall_MigrationGetContainerName(mrOutSGX->outClient);

    InMigrationEntry = sgxClient->_inMigrationBase;
    InMigrationEntry_t* startEntry = InMigrationEntry;
    outMigrationEntry = outMigrationBase;
    size_t processNum = 0;
    for(size_t i =0; i < queryNum; i++)
    {
        cryptoObj_->DecryptWithKey(cipherCtx, outMigrationEntry->containerName, CONTAINER_ID_LENGTH,
            Enclave::indexQueryKey_, InMigrationEntry->containerName);
      
        tmpContainerNameStr.assign((char*)InMigrationEntry->containerName, CONTAINER_ID_LENGTH);
        auto result = tmpContainerMap.find(tmpContainerNameStr);
        if(result == tmpContainerMap.end())
        {
            tmpContainerMap[tmpContainerNameStr] = reqContainer->idNum;
            InMigrationEntry->containerID = reqContainer->idNum;
            memcpy(idBuffer + reqContainer->idNum * CONTAINER_ID_LENGTH,
                tmpContainerNameStr.c_str(), CONTAINER_ID_LENGTH);
            reqContainer->idNum++;
        } else {
            InMigrationEntry->containerID = result->second;
        }

        processNum++;
        InMigrationEntry++;
        outMigrationEntry++;


        if(reqContainer->idNum == CONTAINER_CAPPING_VALUE || i == (queryNum - 1))
        {
            Ocall_GetReqContainers_MR(mrOutSGX->outClient);
            
            GetMigrationContent(mrOutSGX, containerArray, reqContainer->idNum, startEntry,
                                    processNum, sendChunkBuffer);

            reqContainer->idNum = 0;
            tmpContainerMap.clear();
            processNum = 0;
            startEntry = InMigrationEntry;
        }    
    }
    return ;
}

EcallMigrator::EcallMigrator()
{
    cryptoObj_ = new EcallCrypto(CIPHER_TYPE, HASH_TYPE);
    storageObj_ = new EcallStorageCore();
    return ;
}

EcallMigrator::~EcallMigrator()
{
    delete cryptoObj_;
    delete storageObj_;
    return ;
}

void EcallMigrator::MigrateTailBatch(MrOutSGX_t* mrOutSGX)
{
    //Enclave::Logging(myName.c_str(), "migrate tail batch\n");
    SendMsgBuffer_t* sendChunkBuffer = mrOutSGX->sendChunkBuf;
    sendChunkBuffer->header->messageType = EDGE_MIGRATION_CHUNK_FINAL;
    Ocall_SendMigrationData(mrOutSGX->outClient);
    return ;
}

void EcallMigrator::GetMigrationContent(MrOutSGX_t* mrOutSGX, uint8_t** containerArray, uint32_t idNum,
        InMigrationEntry_t* startEntry,size_t entryNum, SendMsgBuffer_t* sendChunkBuffer)
{
    EnclaveClient* sgxClient = (EnclaveClient*)mrOutSGX->sgxClient;
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;

    uint8_t headerBuf[MAX_CONTAINER_SIZE / 20];



    InMigrationEntry_t* entry = startEntry;
    unordered_map<uint32_t, unordered_map<string, InMigrationEntry_t*>> tmpMap;
    // build tmp map
    //Enclave::Logging(myName.c_str(), "build tmp map\n");
    for(size_t i = 0; i < entryNum; i++)
    {
        string tmpHashStr;
        tmpHashStr.assign((char*)entry->chunkHash, CHUNK_HASH_SIZE);
        uint32_t containerId = entry->containerID;
        tmpMap[containerId][tmpHashStr] = entry;
        entry++;
    }

    for(size_t i = 0; i < idNum; i++)
    {
        //Enclave::Logging(myName.c_str(), "get chunk num\n");
        size_t chunkNum = (containerArray[i][3]) + (containerArray[i][2] << 8) + 
            (containerArray[i][1] << 16) + (containerArray[i][0] << 24);
        // Enclave::Logging(myName_.c_str(), "ok for get chunk num: %lu\n", chunkNum);
        //Enclave::Logging(myName.c_str(), "decrypt container header\n");
        cryptoObj_->DecryptWithKey(cipherCtx, containerArray[i]+4, 
            chunkNum * (CHUNK_HASH_SIZE+8), Enclave::indexQueryKey_, headerBuf);
        uint8_t* containerContent = containerArray[i];
        for (size_t j = 0; j < chunkNum; j++)
        {
            string tmpChunkHash;
            tmpChunkHash.assign((char*)headerBuf + (j * (CHUNK_HASH_SIZE + 8)), CHUNK_HASH_SIZE);
            
            auto result = tmpMap[i].find(tmpChunkHash);
            if(result != tmpMap[i].end())
            {
                uint32_t offset = (
                    (headerBuf[j * (CHUNK_HASH_SIZE + 8) + CHUNK_HASH_SIZE + 3]) + 
                    (headerBuf[j * (CHUNK_HASH_SIZE + 8) + CHUNK_HASH_SIZE + 2] << 8) + 
                    (headerBuf[j * (CHUNK_HASH_SIZE + 8) + CHUNK_HASH_SIZE + 1] << 16) + 
                    (headerBuf[j * (CHUNK_HASH_SIZE + 8) + CHUNK_HASH_SIZE + 0] << 24) +
                    chunkNum * (CHUNK_HASH_SIZE + 8) + 4);
                uint32_t length = (
                    (headerBuf[j * (CHUNK_HASH_SIZE + 8) + CHUNK_HASH_SIZE + 7]) + 
                    (headerBuf[j * (CHUNK_HASH_SIZE + 8) + CHUNK_HASH_SIZE + 6] << 8) + 
                    (headerBuf[j * (CHUNK_HASH_SIZE + 8) + CHUNK_HASH_SIZE + 5] << 16) + 
                    (headerBuf[j * (CHUNK_HASH_SIZE + 8) + CHUNK_HASH_SIZE + 4] << 24));
       
                // put into sendbuffer
                uint8_t* sendBuffer = sendChunkBuffer->dataBuffer + sendChunkBuffer->header->dataSize;   
                memcpy(sendBuffer, &length, sizeof(uint32_t));
                sendChunkBuffer->header->dataSize += sizeof(uint32_t);
                memcpy(sendBuffer + sizeof(uint32_t), containerArray[i] + offset, length);
                sendChunkBuffer->header->dataSize += length;
                sendChunkBuffer->header->currentItemNum++;
            }

            if(sendChunkBuffer->header->currentItemNum != 0 && sendChunkBuffer->header->currentItemNum %
                Enclave::sendChunkBatchSize_ == 0)
            {
                
                sendChunkBuffer->header->messageType = EDGE_MIGRATION_CHUNK;
                Ocall_SendMigrationData(mrOutSGX->outClient);

                sendChunkBuffer->header->dataSize = 0;
                sendChunkBuffer->header->currentItemNum = 0;
            }
        }
        if(sendChunkBuffer->header->currentItemNum %
            Enclave::sendChunkBatchSize_ != 0 && i == idNum - 1)
        {
            sendChunkBuffer->header->messageType = EDGE_MIGRATION_CHUNK;
            Ocall_SendMigrationData(mrOutSGX->outClient);

            sendChunkBuffer->header->dataSize = 0;
            sendChunkBuffer->header->currentItemNum = 0;
        }
    }
    
    return ;
}

void EcallMigrator::DownloadOneBatch(uint8_t* recipeBuffer, uint8_t* secRecipeBuffer, size_t recipeNum, RtOutSGX_t* rtOutSGX)
{
    // init client
    EnclaveClient* sgxClient = (EnclaveClient*)rtOutSGX->sgxClient;
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;
    // init recipe buffer 
    uint8_t* plainRecipeBuffer = sgxClient->_plainRecipeBuffer_RT;
    SendMsgBuffer_t* sendSecFpBuf = rtOutSGX->sendSecFpBuf;
    OutQuery_t* outQuery = rtOutSGX->outQuery;
    OutQueryEntry_t* outQueryEntry = outQuery->outQueryBase;
    outQuery->queryNum = 0;
    InQueryEntry_t* inQueryEntryBase = sgxClient->_inQueryBase_RT;
    uint32_t* needChunkNum = rtOutSGX->needChunkNum;
    // decrtpt recipe once 
    //Enclave::Logging(myName.c_str(), "Decrypt recipe buffer\n");
    cryptoObj_->DecryptWithKey(cipherCtx, recipeBuffer, recipeNum * sizeof(RecipeEntry_t),
        Enclave::indexQueryKey_, plainRecipeBuffer);
    
    uint8_t* plainFp = plainRecipeBuffer;
    // plain chunk hash
    string tmpHashStr;
    tmpHashStr.resize(CHUNK_HASH_SIZE, 0);
    // secure chunk has
    string tmpSecHashStr;
    tmpSecHashStr.resize(CHUNK_HASH_SIZE, 0);

    string tmpEncHashStr;
    tmpEncHashStr.resize(CHUNK_HASH_SIZE, 0);
    // encrypt
    //Enclave::Logging(myName.c_str(), "Encrypt chunk fp and recipe num is %d\n", recipeNum);
    for(size_t i = 0; i < recipeNum; i++)
    {
        tmpHashStr.assign((char*)plainFp, CHUNK_HASH_SIZE);
        // update in query entry
        //  crypte & update out query entry
        //Enclave::Logging(myName.c_str(), "i is %d\n", i);
        cryptoObj_->IndexAESCMCEnc(cipherCtx, (uint8_t*)tmpHashStr.c_str(), CHUNK_HASH_SIZE,
            Enclave::indexQueryKey_,  outQueryEntry->chunkHash);
        plainFp += CHUNK_HASH_SIZE;
        outQuery->queryNum++;
        outQueryEntry++;
    }
    //Ocall_SendSecRecipe(rtOutSGX->outClient);
    //Enclave::Logging(myName.c_str(), "ocall out query index.\n");
    Ocall_QueryOutIndexRT(rtOutSGX->outClient);

    
    // write chunk & update index    
    outQueryEntry = outQuery->outQueryBase;
    uint8_t* secFp = secRecipeBuffer;
    plainFp = plainRecipeBuffer;
    //Enclave::Logging(myName.c_str(), "fill out inentries \n");
    for(size_t i = 0; i < recipeNum; i++)
    {
        tmpHashStr.assign((char*)plainFp, CHUNK_HASH_SIZE);
        tmpSecHashStr.assign((char*)secFp, CHUNK_HASH_SIZE);

        if(outQueryEntry->dedupFlag == NONEXIST)
        {
            memcpy(sendSecFpBuf->dataBuffer + sendSecFpBuf->header->dataSize, secFp, CHUNK_HASH_SIZE);
            memcpy(inQueryEntryBase->secureChunkHash, tmpSecHashStr.c_str(), CHUNK_HASH_SIZE);
            memcpy(inQueryEntryBase->chunkHash, tmpHashStr.c_str(), CHUNK_HASH_SIZE);

            inQueryEntryBase++;
            sendSecFpBuf->header->dataSize += CHUNK_HASH_SIZE;
            sendSecFpBuf->header->currentItemNum++;
            (*needChunkNum)++;
        }
        secFp += CHUNK_HASH_SIZE;
        plainFp += CHUNK_HASH_SIZE;
        outQueryEntry++;
    }    
    //Ocall send 
    Ocall_SendSecRecipe(rtOutSGX->outClient);
    return ;
}

void EcallMigrator::DownloadTailBatch(RtOutSGX_t* rtOutSGX)
{

    return ;
}

void EcallMigrator::ProcessOneBatchChunk(uint8_t* chunkContentBuffer, size_t chunkNum, RtOutSGX_t* rtOutSGX)
{
    // set up client 
    EnclaveClient* sgxClient = (EnclaveClient*)rtOutSGX->sgxClient;
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;
    // set up buffer
    InQueryEntry_t* inQueryEntryBase = sgxClient->_inQueryBase_RT;
    inQueryEntryBase += *(rtOutSGX->processNum);
    //uint32_t startIdx = *(rtOutSGX->processNum);
    uint8_t* chunkBuffer = chunkContentBuffer;
    uint32_t tmpChunkSize = 0; 
    uint32_t currentOffset = 0;
    Container_t* curContainer = rtOutSGX->curContainer;
    OutQuery_t* outQuery = rtOutSGX->outQuery;
    OutQueryEntry_t* outQueryEntry = outQuery->outQueryBase;
    outQuery->queryNum = 0;
    // process chunk
    string tmpHashStr;
    string tmpSecHasStr;
    string tmpEncHashStr;
    string containerName;
    tmpHashStr.resize(CHUNK_HASH_SIZE, 0);
    tmpSecHasStr.resize(CHUNK_HASH_SIZE, 0);
    tmpEncHashStr.resize(CHUNK_HASH_SIZE, 0);
    for(size_t i = 0; i < chunkNum; i++)
    {
        memcpy(&tmpChunkSize, chunkBuffer + currentOffset, sizeof(uint32_t));
        //Enclave::Logging(myName.c_str(), "tmp chunk size is %d\n", tmpChunkSize);
        currentOffset += sizeof(uint32_t);
        // save chunk 
        //Enclave::Logging(myName.c_str(), "save a chunk \n");
        storageObj_->SaveChunk_RT((char*)(chunkBuffer + currentOffset), tmpChunkSize, (uint8_t*)(curContainer->containerID), rtOutSGX, inQueryEntryBase->chunkHash);
        currentOffset += tmpChunkSize;
        //Enclave::Logging(myName.c_str(), "save a chunk done\n");
        // update container id 
        //Enclave::Logging(myName.c_str(), "update container id  \n");
        containerName.assign((char*)inQueryEntryBase->containerName, CONTAINER_ID_LENGTH);
        //Enclave::Logging(myName.c_str(), " container id is %s\n", containerName.c_str());
        memcpy(inQueryEntryBase->containerName, curContainer->containerID, CONTAINER_ID_LENGTH);

        cryptoObj_->IndexAESCMCEnc(cipherCtx, inQueryEntryBase->chunkHash, CHUNK_HASH_SIZE,
            Enclave::indexQueryKey_, outQueryEntry->chunkHash);
        
        cryptoObj_->EncryptWithKey(cipherCtx, inQueryEntryBase->containerName, CONTAINER_ID_LENGTH, 
            Enclave::indexQueryKey_, outQueryEntry->containerName);

        memcpy(outQueryEntry->secureChunkHash, inQueryEntryBase->secureChunkHash, CHUNK_HASH_SIZE);
        //Enclave::Logging(myName.c_str(), "update container id done\n");
        outQuery->queryNum++;

        inQueryEntryBase++;
        outQueryEntry++;
    }
    //Enclave::Logging(myName.c_str(), "process a batch done!\n");
    return ;
}

void EcallMigrator::ProcessTailBatchChunk(RtOutSGX_t* rtOutSGX)
{
    EnclaveClient* sgxClient = (EnclaveClient*)rtOutSGX->sgxClient;
    InContainer* inContainer = &sgxClient->_inContainer_RT;
    Container_t* outContainer = rtOutSGX->curContainer;
    EVP_CIPHER_CTX* cipherCtx = sgxClient->_cipherCtx;

    uint32_t curSize = inContainer->curContentSize + inContainer->curHeaderSize + 4;

    if(curSize != 0)
    {
        // curNum转换为4*char
        uint8_t curNumChar[4];
        curNumChar[0] = inContainer->curNum >> 24;
        curNumChar[1] = inContainer->curNum >> 16;
        curNumChar[2] = inContainer->curNum >> 8;
        curNumChar[3] = inContainer->curNum;

        // 依次复制curNum, header, content
        memcpy(outContainer->body, curNumChar, 4);

        cryptoObj_->EncryptWithKey(cipherCtx, inContainer->headerBuf,
            inContainer->curHeaderSize, Enclave::indexQueryKey_, outContainer->body + 4);
        
        memcpy(outContainer->body + 4 + inContainer->curHeaderSize, inContainer->contentBuf, inContainer->curContentSize);
        outContainer->currentSize = 4 + inContainer->curHeaderSize + inContainer->curContentSize;
        Ocall_WriteContainerRT(rtOutSGX->outClient);

        // 重置container
        inContainer->curHeaderSize = 0;
        inContainer->curContentSize = 0;
        inContainer->curNum = 0;
    }

    return ;
}