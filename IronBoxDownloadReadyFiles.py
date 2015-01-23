#!/usr/bin/python
#---------------------------------------------------
#   
#   Demonstrates how to download blobs in an IronBox
#   container that are in a ready state.
#
#   Written by KevinLam@goironbox.com 
#   Website: www.goironbox.com
#
#   Usage:
#    python IronBoxDownloadReadyFiles.py
#
#---------------------------------------------------
import sys
from IronBoxREST import IronBoxRESTClient 
from os.path import join 

#---------------------------------------------------
# Your IronBox authentication parameters, you could
# also pass these in as command arguments
#---------------------------------------------------
ContainerID = 100777
IronBoxEmail = "email@email.com"
IronBoxPassword = "password123"
IronBoxAPIServerURL = "https://api.goironcloud.com/latest/"
IronBoxAPIVersion = "latest"

# Gets all the blobs in the Ready state (2). Other states:
#   0 = Blob created
#   1 = Entity is uploading
#   2 = Ready
#   3 = Checked out
#   4 = Entity is modifying
#   5 = None
BlobState = 2 

OutputDir = "./"

#---------------------------------------------------
# Main
#---------------------------------------------------
def main():
    
    # Create an instance of the IronBox REST class
    IronBoxRESTObj = IronBoxRESTClient(IronBoxEmail, IronBoxPassword, version=IronBoxAPIVersion, verbose=True)

    # Get all the blobs in a ready state, result is a tuple list
    # where 0 = blob ID and 1 = blob name 
    result = IronBoxRESTObj.GetContainerBlobInfoListByState(ContainerID, BlobState)
    for item in result:
        # Download and save the file locally
        DestFilePath = join(OutputDir,item[1])
        if IronBoxRESTObj.DownloadBlobFromContainer(ContainerID,item[0],DestFilePath) is True:
            # Optionally you can delete the blob after download
            #IronBoxRESTObj.RemoveEntityContainerBlob(ContainerID,item[0])  
            pass

#---------------------------------------------------
if __name__ == "__main__":
    main()
