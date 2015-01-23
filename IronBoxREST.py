#------------------------------------------------------------------------
#   IronBox REST API Python wrapper
#   Version: 1.9 (01/06/2014)
#   Author: KevinLam@goironbox.com
#   Website: www.goironbox.com
#   Dependencies:
#    pip install -r requirements.txt
#
#   Change History:
#   ---------------
#    01/06/2014  -    v1.9 Added verifySSLCert flag, which allows callers
#                     to control if they want to validate SSL certificates
#                     or not when connecting to API servers or not, default
#                     on.
#
#    01/02/2014  -    v1.8 Corrected issue with Encrypt_File method
#                     in ContainerKeyData class. Final padding check
#                     should be based on the read block size, not 
#                     AES block size, was only an issue for files < 1024
#                     and multiple of 16.
# 
#    12/16/2013  -    v1.7 Added CreateEntitySFTContainer and 
#                     RemoveEntityContainer
#
#    12/06/2013  -    v1.6 Added GetContextSetting and 
#                     GetContainerInfoListByContext methods 
#
#    12/04/2013  -    v1.5 Added RemoveEntityContainerBlob, 
#                     DownloadBlobFromContainer (helper method),
#                     ReadEntityContainerBlob
#            
#    12/04/2013  -    v1.4 Added GetContainerBlobInfoListByState
#
#    11/15/2013  -    v1.3 Added x-ms-version in BlockBlob upload for 
#                     stricter adherence to protocol
#
#    11/12/2013  -    v1.2 Removed dependency on M2Crypto, Urllib, 
#                     Urllib2, openssl and Json.  Added pycrypto.
#                     Using BlockBlob and re-assembling on the server
#                     as it's more efficient than PageBlobs
#
#    11/10/2013  -    v1.1 Initial release (beta)
#
#------------------------------------------------------------------------
import os
import datetime
import sys

import requests
from Crypto.Cipher import AES
import json

class IronBoxRESTClient():

    def __init__(self, entity, entity_password, entity_type=0, version='latest', content_format='application/json', verbose=False, verifySSLCert=True):
        # Actual entity identifier, this can be email address,
        # name identifier (mostly internal use only) or an entity
        # ID which is a 64-bit integer that identifies the specific 
        # user
        self.Entity = entity 

        # Entity password
        self.EntityPassword = entity_password 

        # Entity type, 0 = email address, 1 = name identifier, 2 = entity ID
        self.EntityType = entity_type   

        # API server URL, default however can be changed
        # to test servers
        self.APIServerURL = "https://api.goironcloud.com/%s/" % version

        # Accept format
        self.ContentFormat = content_format 

        # Flag that indicates whether or not to be verbose or not
        self.Verbose = verbose 

        # Verify SSL certificate flag
        self.VerifySSLCert = verifySSLCert

        return

    #*************************************************************
    #    IronBox REST Client helper functions
    #*************************************************************

    #-------------------------------------------------------------
    #    Uploads a given file to an IronBox container
    #    
    #    In:
    #        ContainerID = IronBox container ID, 64-bit integer
    #        FilePath = local file path of file to upload
    #        BlobName = name of the file to use on cloud storage
    #    Returns:
    #        Returns True on success, False otherwise
    #-------------------------------------------------------------
    def UploadFileToContainer(self,ContainerID, FilePath, BlobName):
        #----------------------------
        #   Step 1:
        #   Test to make sure that the API server is accessible
        #----------------------------
        if not self.Ping():
            raise Exception("IronBox API server is not accessible from this network location")
        self.console_log("IronBox API is up, starting transfer")

        #----------------------------
        #   Step 2:
        #   Get the container key data
        #----------------------------
        IronBoxKeyData = self.ContainerKeyData(ContainerID)
        if not IronBoxKeyData:
            raise Exception("Unable to retrieve container key data")
        self.console_log("Retrieved container symmetric key data")

        #----------------------------
        #   Step 3:
        #   Create a container blob and check it out.
        #   This doesn't actually upload the contents, just
        #   creates the entry, and does a "check out" which
        #   lets IronBox know you're going to upload contents
        #   soon.  As part of the checkout process you'll get a
        #   check in token that is your way to check the
        #   blob back in.
        #----------------------------
        BlobIDName = self.CreateEntityContainerBlob(ContainerID, BlobName)
        if not BlobIDName:
            raise Exception("Unable to create blob in container")

        CheckOutData = self.CheckOutEntityContainerBlob(ContainerID, BlobIDName)
        if not CheckOutData:
            raise Exception("Unable to checkout container blob")

        #----------------------------
        #   Step 4:
        #   Make a copy of the file and encrypt it
        #----------------------------
        self.console_log("Encrypting a copy of " + FilePath)
        OriginalFileSize = os.path.getsize(FilePath)
        EncryptedFilePath = FilePath + ".ironbox"

        if IronBoxKeyData.Encrypt_File(FilePath, EncryptedFilePath) is False:
            raise Exception("Unable to encrypt local copy of file")

        #----------------------------
        #   Step 5:
        #   Upload the encrypted file using the shared
        #   acccess signature we got at checkout
        #   Use python-requests, since it's file upload is
        #   more advanced.
        #----------------------------
        self.console_log("Uploading encrypted copy of " + FilePath)
        if not self.UploadBlobWithSharedAccessSignatureUri(EncryptedFilePath,CheckOutData.SharedAccessSignatureUri):
            raise Exception("Unable to upload encrypted file")

        #----------------------------
        #   Step 6:
        #   Mark the file as ready to download by
        #   checking it back in
        #----------------------------
        if not self.CheckInEntityContainerBlob(ContainerID, BlobIDName, OriginalFileSize, CheckOutData.CheckInToken):
            raise Exception("Unable to finalize upload")

        self.console_log("Upload completed, cleaning up")

        #done
        os.remove(EncryptedFilePath)
        return True

    #-------------------------------------------------------------
    #    Downloads a blob from an IronBox container
    #    
    #    In:
    #        ContainerID = IronBox container ID, 64-bit integer
    #        BlobID = ID of blob to download 
    #        DestFilePath = Path of the file to save the decrypted 
    #        blob to. 
    #
    #    Returns:
    #        Returns True on success, False otherwise
    #-------------------------------------------------------------
    def DownloadBlobFromContainer(self,ContainerID, BlobID, DestFilePath):

        #---------------------------------------------------------
        #   Step 1:
        #   Test to make sure that the API server is accessible
        #---------------------------------------------------------
        if not self.Ping():
            raise Exception("IronBox API server is not accessible from this network location")
        self.console_log("IronBox API is up, starting download of target file %s" % DestFilePath)

        #---------------------------------------------------------
        #   Step 2:
        #   Get the container key data
        #---------------------------------------------------------
        IronBoxKeyData = self.ContainerKeyData(ContainerID)
        if not IronBoxKeyData:
            raise Exception("Unable to retrieve container key data")
        self.console_log("Retrieved container symmetric key data")

        #---------------------------------------------------------
        #   Step 3:
        #   Download the blob read data, specifically we need 
        #   a shared access signature URI to the encrypted
        #   blob 
        #---------------------------------------------------------
        ReadBlobData = self.ReadEntityContainerBlob(ContainerID,BlobID)
        if not ReadBlobData:
            raise Exception("Unable to read container blob download data")
        self.console_log("Retrieved blob download Shared Access Signature URI")
        EncryptedFilePath = DestFilePath + ".encrypted"     
        r = requests.get(ReadBlobData.SharedAccessSignatureUri, stream=True, verify=self.VerifySSLCert)
        numBytesDownloaded = 0
        with open(EncryptedFilePath, 'wb') as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
                    numBytesDownloaded = numBytesDownloaded + len(chunk)
                    # Show progress if needed
                    if self.Verbose is True:
                        sys.stdout.write("\rDownloaded %d encrypted byte(s) to %s" % (numBytesDownloaded,EncryptedFilePath))
                        sys.stdout.flush()
                    f.flush()
        
            # If verbose, we need to print out a new line
            if self.Verbose:
                print
        
        #---------------------------------------------------------
        #   Step 4:
        #   Decrypt the downloaded blob
        #---------------------------------------------------------
        self.console_log("Decrypting encrypted blob")
        IronBoxKeyData.Decrypt_File(EncryptedFilePath,DestFilePath)

        #---------------------------------------------------------
        #   Step 5:
        #   Done, clean up 
        #---------------------------------------------------------
        self.console_log("Done, cleaning up %s" % EncryptedFilePath)
        os.remove(EncryptedFilePath)
        return True

    #-------------------------------------------------------------
    #    Uploads an encrypted file to cloud storage using the 
    #    shared access signature provided.  This function uploads
    #    blocks in 4 MB blocks with max 50k blocks, meaning that 
    #    there is a 200 GB max for any file uploaded.
    #    
    #    Returns:
    #        Returns true on success, false otherwise
    #-------------------------------------------------------------
    def UploadBlobWithSharedAccessSignatureUri(self, in_filename, sasUri):

        # Validate file
        if not os.path.exists(in_filename):
            return False

        # Cloud storage only allows blocks of max 4MB, and max 50k blocks 
        # so 200 GB max    per file
        blockSizeMB = 4    
        blockSizeBytes = blockSizeMB * 1024 * 1024  
        fileSize = os.path.getsize(in_filename)
        self.console_log("Starting send in %dMB increments" % blockSizeMB)

        # Send headers 
        headers = {
            'content-type': 'application/octet-stream',
            'x-ms-blob-type' : 'BlockBlob',
            'x-ms-version' : '2012-02-12'   
        }

        # Open handle to encrypted file and send it in blocks
        sasUriBlockPrefix = sasUri + "&comp=block&blockid=" 
        blockIDs = []
        numBytesSent = 0    
        i = 0
        with open(in_filename,'rb') as infile:
            while True:
        
                buf = infile.read(blockSizeBytes)
                if not buf:
                    break;

                # block IDs all have to be the same length, which was NOT
                # documented by MSFT
                blockID = "block"+"{0:08}".format(i)
                blockSASUri = sasUriBlockPrefix + blockID.encode('base64','strict')

                # Create a blob block
                r = requests.put(blockSASUri, data=buf, headers=headers, verify=self.VerifySSLCert)        
                if r.status_code != requests.codes.created:
                    return False    

                # Block was successfuly sent, record its ID
                blockIDs.append(blockID)
                numBytesSent += len(buf)
                i += 1        

                # Show progress if needed
                if self.Verbose is True:
                    done = int(50 * numBytesSent / fileSize)
                    sys.stdout.write("\r[%s%s] %d byte(s) sent" % ('=' * done, ' ' * (50-done), numBytesSent) )    
                    sys.stdout.flush()
    
        # We're done, so if verbose go to new line            
        if self.Verbose:
            print

        # Done sending blocks, so commit the blocks into a single one 
        # do the final re-assembly on the storage server side
        commitBlockSASUrl = sasUri + "&comp=blockList" 
        commitheaders = {
            'content-type': 'text/xml',
            'x-ms-version' : '2012-02-12'   
        }
        # build list of block ids as xml elements
        blockListBody = ''
        for x in blockIDs:
            encodedBlockID = x.encode('base64','strict').strip()
            # Indicate blocks to commit per 2012-02-12 version PUT block list specifications 
            blockListBody += "<Latest>%s</Latest>" % encodedBlockID 
        commitBody = '<?xml version="1.0" encoding="utf-8"?><BlockList>%s</BlockList>' % blockListBody
        commitResponse = requests.put(commitBlockSASUrl, data=commitBody, headers=commitheaders, verify=self.VerifySSLCert)        
        return commitResponse.status_code == requests.codes.created
         
    
    #-------------------------------------------------------------
    #    Console logger
    #-------------------------------------------------------------
    def console_log(self, m):
        if self.Verbose is True:
            now = datetime.datetime.now()
            print (str(now) + ": " + m)

    #*************************************************************
    #    CORE REST API FUNCTIONS 
    #*************************************************************

    #-------------------------------------------------------------
    #   Checks if the IronBox API server is responding
    #   In:
    #    A URL string to the API server to check
    #   Returns:
    #    A boolean value if 
    #-------------------------------------------------------------
    def Ping(self):
        r = requests.get(self.APIServerURL + 'Ping', verify=self.VerifySSLCert)
        if r.status_code == requests.codes.ok:
            return r.json()
        return False

    #-------------------------------------------------------------
    #   Fetches an IronBox container key data
    #    
    #    Returns:
    #        Returns an IronBoxKeyData object, otherwise None
    #        on error
    #-------------------------------------------------------------
    def ContainerKeyData(self,ContainerID):
        url = self.APIServerURL + "ContainerKeyData"

        post_data = {
            'Entity': self.Entity,
            'EntityType': self.EntityType,
            'EntityPassword':self.EntityPassword,
            'ContainerID': ContainerID
        }

        r = requests.post(url, data=post_data, headers={'Accept': self.ContentFormat}, verify=self.VerifySSLCert)

        if r.status_code != requests.codes.ok:
            return None

        # Parse the response, get container key, IV and strength
        response = r.json()
        if not response:
            return None

        ContainerKeyData = IronBoxKeyData()

        session_key_base_64 = response.get('SessionKeyBase64', None)
        if not session_key_base_64:
            return None
        ContainerKeyData.SymmetricKey = session_key_base_64.decode('base64', 'strict')
        ContainerKeyData.IV = response.get('SessionIVBase64').decode('base64', 'strict')
        ContainerKeyData.KeyStrength =  response.get('SymmetricKeyStrength')

        return ContainerKeyData

  
    #-------------------------------------------------------------
    #    Creates an IronBox blob in an existing container
    #    
    #    Returns:
    #        Returns the blob ID of the blob created, otherwise
    #        None on error  
    #-------------------------------------------------------------
    def CreateEntityContainerBlob(self,ContainerID, BlobName):
        post_data = {
            'Entity': self.Entity,
            'EntityType': self.EntityType,
            'EntityPassword':self.EntityPassword,
            'ContainerID': ContainerID,
            'BlobName': BlobName
        }
        url = self.APIServerURL + "CreateEntityContainerBlob"

        r = requests.post(url, data=post_data, headers={'Accept': self.ContentFormat}, verify=self.VerifySSLCert)

        if r.status_code != requests.codes.ok:
            return None

        return r.json()

    #-------------------------------------------------------------
    #    Checks outs an entity container blob, so that the caller
    #    can begin uploading the contents of the blob.
    #    
    #    Inputs:
    #        ContainerID = 64-bit integer container ID
    #        BlobIDName = ID of the blob being checked out
    #
    #    Returns:
    #        An IronBoxREST.IronBoxBlobCheckOutData object, 
    #        otherwise None on error
    #-------------------------------------------------------------
    def CheckOutEntityContainerBlob(self,ContainerID, BlobIDName):
        post_data = {
            'Entity': self.Entity,
            'EntityType': self.EntityType,
            'EntityPassword':self.EntityPassword,
            'ContainerID': ContainerID,
            'BlobIDName': BlobIDName
        }
        url = self.APIServerURL + "CheckOutEntityContainerBlob"

        r = requests.post(url, data=post_data, headers={'Accept': self.ContentFormat}, verify=self.VerifySSLCert)

        if r.status_code != requests.codes.ok:
            return None

        response = r.json()
        if not response:
            return None

        CheckOutData = IronBoxBlobCheckOutData()

        shared_access_signature = response.get('SharedAccessSignature', None)
        if not shared_access_signature:
            return None

        CheckOutData.SharedAccessSignature = shared_access_signature
        CheckOutData.SharedAccessSignatureUri = response.get('SharedAccessSignatureUri')
        CheckOutData.CheckInToken = response.get('CheckInToken')
        CheckOutData.StorageUri = response.get('StorageUri')
        CheckOutData.StorageType = response.get('StorageType')
        CheckOutData.ContainerStorageName = response.get('ContainerStorageName')

        #CheckOutData.DebugPrintProps()

        return CheckOutData

    #-------------------------------------------------------------
    #    Checks in a checked out entity container blob
    #
    #    Inputs:    
    #        ContainerID = 64-bit integer container ID
    #        BlobIDName = ID of the blob being checked in
    #        BlobSizeBytes = Reports the size of the blob in bytes
    #        CheckInToken = Check in token
    # 
    #-------------------------------------------------------------
    def CheckInEntityContainerBlob(self,ContainerID, BlobIDName, BlobSizeBytes, CheckInToken):
        post_data = {
            'Entity': self.Entity,
            'EntityType': self.EntityType,
            'EntityPassword':self.EntityPassword,
            'ContainerID': ContainerID,
            'BlobIDName': BlobIDName,
            'BlobSizeBytes': BlobSizeBytes,
            'BlobCheckInToken': CheckInToken
        }
        url = self.APIServerURL + "CheckInEntityContainerBlob"

        r = requests.post(url, data=post_data, headers={'Accept': self.ContentFormat}, verify=self.VerifySSLCert)

        if r.status_code != requests.codes.ok:
            return None

        return r.json()    


    #-------------------------------------------------------------
    #    Returns information about the blobs in the given container 
    #    that are in a given state.  For example, if 
    #    a Ready state is provided, then returns the container blobs
    #    that are in a ready state. The return object is a list of 
    #    double-tuples where 0=BlobID and 1=BlobName.
    #
    #    Inputs:
    #        ContainerID = 64-bit integer container ID
    #        BlobState = 32-bit integer 
    #        0 = Blob created 
    #        1 = Entity is uploading
    #        2 = Ready
    #        3 = Checked out
    #        4 = Entity is modifying 
    #        5 = None 
    #
    #-------------------------------------------------------------
    def GetContainerBlobInfoListByState(self,ContainerID, BlobState):
    
        post_data = {
            'Entity': self.Entity,
            'EntityType': self.EntityType,
            'EntityPassword':self.EntityPassword,
            'ContainerID': ContainerID,
            'BlobState': BlobState
        }
        url = self.APIServerURL + "GetContainerBlobInfoListByState"

        r = requests.post(url, data=post_data, headers={'Accept': self.ContentFormat}, verify=self.VerifySSLCert)

        if r.status_code != requests.codes.ok:
            return None

        # Get the Json response
        response = r.json()
        if not response:
            return None

        # Start parsing the Json response into a list of double-tuples
        # where 0 = BlobID and 1 = BlobName
        result = list()
        jsonData = response["BlobInfoArray"]
        for item in jsonData: 
            # Create a tuple [BlobID,BlobName] and add to our 
            # result list
            t = item.get("BlobID"), item.get("BlobName")
            result.append(t)
    
        # Done, return result list of double-tuples
        return result

    #-------------------------------------------------------------
    #    Retrieves the storage information required to read 
    #    encrypted entity container blobs directly from storage. 
    #    Returned information will include storage endpoint URL, 
    #    container name and a shared access signature that grants 
    #    limited temporary access to back-end storage.
    #    
    #    Callers can then use the URL specified in the 
    #    SharedAccessSignatureUri response to directly read the 
    #    encrypted blob from storage.
    #
    #    Once downloaded, callers must then decrypt the encrypted 
    #    blob using the information provided from the call to 
    #    ContainerKeyData. 
    #
    #-------------------------------------------------------------
    def ReadEntityContainerBlob(self,ContainerID, BlobID):
    
        post_data = {
            'Entity': self.Entity,
            'EntityType': self.EntityType,
            'EntityPassword':self.EntityPassword,
            'ContainerID': ContainerID,
            'BlobIDName': BlobID
        }
        url = self.APIServerURL + "ReadEntityContainerBlob"

        r = requests.post(url, data=post_data, headers={'Accept': self.ContentFormat}, verify=self.VerifySSLCert)

        if r.status_code != requests.codes.ok:
            return None

        # Parse the response, get container key, IV and strength
        response = r.json()
        if not response:
            return None

        # Parse response into an IronBoxBlobReadData object
        BlobReadData = IronBoxBlobReadData() 
        BlobReadData.ContainerStorageName = response.get('ContainerStorageName')
        BlobReadData.SharedAccessSignature = response.get('SharedAccessSignature')
        BlobReadData.SharedAccessSignatureUri = response.get('SharedAccessSignatureUri')
        BlobReadData.StorageType = response.get('StorageType')
        BlobReadData.StorageUri = response.get('StorageUri')

        #Done, return the blob read data
        return BlobReadData

    #-------------------------------------------------------------
    #    Removes a blob from an entity container, returns true on 
    #    success false otherwise.    
    #
    #    Inputs:    
    #        ContainerID = 64-bit integer container ID
    #        BlobID = ID of the blob being checked in
    # 
    #-------------------------------------------------------------
    def RemoveEntityContainerBlob(self,ContainerID, BlobID):
        post_data = {
            'Entity': self.Entity,
            'EntityType': self.EntityType,
            'EntityPassword':self.EntityPassword,
            'ContainerID': ContainerID,
            'BlobIDName': BlobID
        }
        url = self.APIServerURL + "RemoveEntityContainerBlob"

        r = requests.post(url, data=post_data, headers={'Accept': self.ContentFormat}, verify=self.VerifySSLCert)

        if r.status_code != requests.codes.ok:
            return None

        return r.json()    


    #-------------------------------------------------------------
    #    Gets a setting for a given context. For example, using this
    #    call you can retrieve certain properties of the context
    #    secure.goironcloud.com, such as company name, company logo
    #    URL, etc. The entity making this request must already be
    #    a member of the context.
    #-------------------------------------------------------------
    def GetContextSetting(self, Context, ContextSetting):

        post_data = {
            'Entity': self.Entity,
            'EntityType': self.EntityType,
            'EntityPassword':self.EntityPassword,
            'Context': Context,
            'ContextSetting': ContextSetting 
        }
        url = self.APIServerURL + "GetContextSetting"

        r = requests.post(url, data=post_data, headers={'Accept': self.ContentFormat}, verify=self.VerifySSLCert)    

        if r.status_code != requests.codes.ok:
            return None

        return r.json()    
    

    #-------------------------------------------------------------
    #    Returns the IDs and names of a container for an entity
    #    in a given context (e.g. secure.goironcloud.com or 
    #    demo.goironcloud.com) and by given container type (always
    #    use 5 for now).
    #-------------------------------------------------------------
    def GetContainerInfoListByContext(self,Context,ContainerType):
    
        post_data = {
            'Entity': self.Entity,
            'EntityType': self.EntityType,
            'EntityPassword':self.EntityPassword,
            'Context': Context,
            'ContainerType': ContainerType 
        }
        url = self.APIServerURL + "GetContainerInfoListByContext"

        r = requests.post(url, data=post_data, headers={'Accept': self.ContentFormat}, verify=self.VerifySSLCert)

        if r.status_code != requests.codes.ok:
            return None

        # Get the Json response
        response = r.json()
        if not response:
            return None

        # Start parsing the Json response into a list of double-tuples
        # where 0 = ContainerID and 1 = ContainerName
        result = list()
        jsonData = response["ContainerInfoArray"]
        for item in jsonData: 
            # Create a tuple [ContainerID,ContainerName] and add to our 
            # result list
            t = item.get("ContainerID"), item.get("ContainerName")
            result.append(t)
    
        # Done, return result list of double-tuples
        return result


    #-------------------------------------------------------------
    #    Creates an IronBox entity secure file transfer (SFT)
    #    container with the given container configuration information
    #    and for the given context.  The caller must already be a 
    #    member of the given context and must have permissions to 
    #    create SFT containers.
    #-------------------------------------------------------------
    def CreateEntitySFTContainer(self, Context, ContainerConfig):

        post_data = {
            'Entity': self.Entity,
            'EntityType': self.EntityType,
            'EntityPassword':self.EntityPassword,
            'Context': Context,
            'Name': ContainerConfig.Name,
            'Description': ContainerConfig.Description
        }

        url = self.APIServerURL + "CreateEntitySFTContainer"

        r = requests.post(url, data=post_data, headers={'Accept': self.ContentFormat}, verify=self.VerifySSLCert)

        if r.status_code != requests.codes.ok:
            return None
    
        # Parse the response, get container key, IV and strength
        response = r.json()
        if not response:
            return None

        # Parse response into an IronBoxSFTContainerData object
        ResultContainerData = IronBoxSFTContainerConfig() 
        ResultContainerData.Name = response.get('Name');    
        ResultContainerData.Description = response.get('Description');    
        ResultContainerData.ContainerID = response.get('ContainerID');    
        ResultContainerData.FriendlyID = response.get('FriendlyID');    

        # Done, return our parsed container data object
        return ResultContainerData

    #-------------------------------------------------------------
    #    Removes an entity container, the caller must be the owner
    #    of the entity container. Returns true on success, false 
    #    otherwise.
    #-------------------------------------------------------------
    def RemoveEntityContainer(self, ContainerID):
        post_data = {
            'Entity': self.Entity,
            'EntityType': self.EntityType,
            'EntityPassword':self.EntityPassword,
            'ContainerID': ContainerID
        }
        url = self.APIServerURL + "RemoveEntityContainer"

        r = requests.post(url, data=post_data, headers={'Accept': self.ContentFormat}, verify=self.VerifySSLCert)

        if r.status_code != requests.codes.ok:
            return None

        return r.json()

    #-------------------------------------------------------------
    #    Enable Easy Access on an existing container. Returns a list
    #    of the Easy Access URL(s) with which external users (i.e. 
    #    users that do not have an IronBox account) can access the 
    #    container.
    #-------------------------------------------------------------
    def SetEntityContainerEasyAccess(self,ContainerID, EasyAccessMode, EasyAccessPassword):
        post_data = {
            'Entity': self.Entity,
            'EntityType': self.EntityType,
            'EntityPassword':self.EntityPassword,
            'ContainerID': ContainerID,
            'EasyAccessMode': EasyAccessMode,
            'EasyAccessPassword': EasyAccessPassword
        }
        url = self.APIServerURL + "SetEntityContainerEasyAccess"

        r = requests.post(url, data=post_data, headers={'Accept': self.ContentFormat}, verify=self.VerifySSLCert)

        if r.status_code != requests.codes.ok:
            return None

        return r.json()

# Regardless of key size, AES always uses a block size of 16
#BS = 16
BS = AES.block_size
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s: s[0:-ord(s[-1])]



#------------------------------------------------------------------
#   IronBox key data class
#------------------------------------------------------------------
class IronBoxKeyData():

    # Symmetric key
    SymmetricKey = []

    # IV
    IV = []

    # Symmetric key strength 0 = none, 1 = 128 and 2 = 256
    KeyStrength = 2
   
            
    #-------------------------------------------------------------
    #    Encrypts a file using the symmetric key data contained in
    #    in this object
    #    
    #    Returns:
    #        True on success, false otherwise
    #-------------------------------------------------------------
    def Encrypt_File(self, in_filename, out_filename):
    
        readBlockSize = 1024
    
        try:
            e = AES.new(self.SymmetricKey, AES.MODE_CBC, self.IV)
            if not os.path.exists(in_filename):
                return False
            with open(in_filename, 'rb') as infile:
                with open(out_filename, "wb") as outfile:
                    while True:
                        buf = infile.read(readBlockSize)
                        if not buf:
                            break
                        if len(buf) < readBlockSize:
                            buf = pad(buf)
                        outfile.write(e.encrypt(buf))
            
                    # if the in_file length is a multiple of the read block size,
                    # then there will be no padding, so we need to add a padded 
                    # block otherwise the cipher has no way of knowing where the 
                    # end of the cipher text is 
                    if (os.path.getsize(in_filename) % readBlockSize) == 0:
                        buf = pad(buf)
                        outfile.write(e.encrypt(buf))
            return True

        except Exception, e:
            return False

    #-------------------------------------------------------------
    #    Decrypts a file using the symmetric key data contained in
    #    this object
    #-------------------------------------------------------------
    def Decrypt_File(self, in_filename, out_filename):
        try:
            d = AES.new(self.SymmetricKey, AES.MODE_CBC, self.IV)
            if not os.path.exists(in_filename):
                return False
            with open(in_filename, 'rb') as infile:
                with open(out_filename, 'wb') as outfile:
                    while True:
                        buf = infile.read(1024)
                        if not buf:
                            break
                        decrypted = d.decrypt(buf)
                        if len(buf) < 1024:
                            decrypted = unpad(decrypted)
                        outfile.write(decrypted) 
            return True
        except Exception, e:
            return False

#------------------------------------------------------------------
#   Class to hold IronBox blob check out data
#------------------------------------------------------------------
class IronBoxBlobCheckOutData():

    SharedAccessSignature = ""
    SharedAccessSignatureUri = ""
    CheckInToken = ""
    StorageUri = ""
    StorageType = 1        # always set to 1
    ContainerStorageName = ""

    def DebugPrintProps(self):
        print("SharedAccessSignature: %s" % self.SharedAccessSignature)
        print("SharedAccessSignatureUri: %s" % self.SharedAccessSignatureUri)
        print("CheckInToken: %s" % self.CheckInToken)
        print("StorageUri: %s" % self.StorageUri)
        print("StorageType: %d" % self.StorageType)
        print("ContainerStorageName: %s" % self.ContainerStorageName)


#------------------------------------------------------------------
#   Class to hold IronBox blob read data
#------------------------------------------------------------------
class IronBoxBlobReadData():

    ContainerStorageName = ""
    SharedAccessSignature = ""
    SharedAccessSignatureUri = ""    
    StorageType = ""
    StorageUri = ""

    def DebugPrintProps(self):
        print("ContainerStorageName: %s" % self.ContainerStorageName)
        print("SharedAccessSignature: %s" % self.SharedAccessSignature)
        print("SharedAccessSignatureUri: %s" % self.SharedAccessSignatureUri)
        print("StorageType: %s" % self.StorageType)
        print("StorageUri: %s" % self.StorageUri)

#------------------------------------------------------------------
#   Class to hold IronBox entity SFT container information
#------------------------------------------------------------------
class IronBoxSFTContainerConfig():

    Name = ""
    Description = ""
    ContainerID = -1 
    FriendlyID = ""

    def DebugPrintProps(self):
        print("Name: %s" % self.Name)
        print("Description: %s" % self.Description)
        print("ContainerID: %d" % self.ContainerID)
        print("FriendlyID: %s" % self.FriendlyID)
