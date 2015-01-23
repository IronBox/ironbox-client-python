#!/usr/bin/python
#---------------------------------------------------
#   
#   Demonstrates how to upload a file to 
#   an IronBox secure package or container
#   using command line parameters:
#
#   Usage:
#   IronBoxUploadFileCmdLine.py containerid email password file_to_upload
#
#   Written by KevinLam@goironbox.com 
#   Website: www.goironbox.com
#
#---------------------------------------------------
from IronBoxREST import IronBoxRESTClient 
import sys, os
from os import path

#---------------------------------------------------
# Your IronBox authentication parameters, these will
# be set by command line arguments
#---------------------------------------------------
ContainerID = 0  
IronBoxEmail = ""
IronBoxPassword = ""
IronBoxAPIServerURL = "https://api.goironcloud.com/latest/"
IronBoxAPIVersion = "latest"
InFile = ""
IronBoxFileName = ""

#---------------------------------------------------
# Main
#---------------------------------------------------
def main():
    
    #-----------------------------------------------   
    #  Parse command line arguments
    #-----------------------------------------------   
    ContainerID = sys.argv[1]
    IronBoxEmail = sys.argv[2]
    IronBoxPassword = sys.argv[3]
    InFile = sys.argv[4]
    IronBoxFileName = path.basename(InFile) 
 
    #-----------------------------------------------   
    #    Create an instance of the IronBox REST class
    #-----------------------------------------------   
    IronBoxRESTObj = IronBoxRESTClient(IronBoxEmail, IronBoxPassword, version=IronBoxAPIVersion, verbose=True)

    #-----------------------------------------------   
    #    Upload the file to IronBox
    #    Duplicate file names will automatically
    #    get renamed
    #-----------------------------------------------   
    IronBoxRESTObj.UploadFileToContainer(ContainerID, InFile, IronBoxFileName)

#---------------------------------------------------
import string, datetime
if __name__ == "__main__":
    main()
