#!/usr/bin/python
#---------------------------------------------------
#   
#   Demonstrates how to upload a directory to 
#   an IronBox secure package or container. Note 
#   this script does not recurse into subdirectories
#
#   Written by KevinLam@goironbox.com 
#   Website: www.goironbox.com
#
#   Usage:
#    python IronBoxUploadDir.py dir_to_upload
#
#---------------------------------------------------
import sys
from os import listdir
from os.path import isfile, join
from IronBoxREST import IronBoxRESTClient 

#---------------------------------------------------
# Your IronBox authentication parameters, you could
# also pass these in as command arguments
#---------------------------------------------------
ContainerID = 100777
IronBoxEmail = "email@email.com"
IronBoxPassword = "password123"
IronBoxAPIServerURL = "https://api.goironcloud.com/latest/"
IronBoxAPIVersion = "latest"

# The directory to upload is the 1st command line 
# argument, or hardcode the directory you want to upload
#InDir = "source_dir"
InDir = sys.argv[1]

#---------------------------------------------------
# Main
#---------------------------------------------------
def main():
    
    #----------------------------
    #    Create an instance of the IronBox REST class
    #----------------------------
    IronBoxRESTObj = IronBoxRESTClient(IronBoxEmail, IronBoxPassword, version=IronBoxAPIVersion, verbose=True)

    #----------------------------
    # Get all the files in the target directory
    #----------------------------
    dirFiles = [f for f in listdir(InDir) if isfile(join(InDir,f)) ]
    
    #----------------------------
    # Iterate the dirFiles array and upload each file
    #----------------------------
    for fileName in dirFiles:  
        currentFilePath = join(InDir,fileName)
        IronBoxRESTObj.UploadFileToContainer(ContainerID, currentFilePath, fileName)

#---------------------------------------------------
if __name__ == "__main__":
    main()
