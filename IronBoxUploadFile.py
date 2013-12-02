#!/usr/bin/python
#---------------------------------------------------
#   
#   Demonstrates how to upload a file to 
#   an IronBox secure package or container
#
#   Written by KevinLam@goironbox.com 
#   Website: www.goironbox.com
#
#---------------------------------------------------
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
InFile = "test.txt"
IronBoxFileName = "testFileOnIronBox.txt"

#---------------------------------------------------
# Main
#---------------------------------------------------
def main():
    
    #----------------------------
    #	Create an instance of the IronBox REST class
    #----------------------------
    IronBoxRESTObj = IronBoxRESTClient(IronBoxEmail, IronBoxPassword, version=IronBoxAPIVersion, verbose=True)

    #----------------------------
    #	Upload the file to IronBox
    #	Duplicate file names will automatically
    #	get renamed
    #----------------------------
    IronBoxRESTObj.UploadFileToContainer(ContainerID, InFile, IronBoxFileName)

#---------------------------------------------------
import string, datetime
if __name__ == "__main__":
    main()
