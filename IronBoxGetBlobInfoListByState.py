#!/usr/bin/python
#---------------------------------------------------
#   
#   Demonstrates how to retrieve the ID and names of
#   each blob in an IronBox container by the given 
#   state. 
#
#   Written by KevinLam@goironbox.com 
#   Website: www.goironbox.com
#
#   Usage:
#	python IronBoxGetBlobInfoListByState.py
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
IronBoxPassword = "password"
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
	print("%s -> %s" % (item[0],item[1]))

#---------------------------------------------------
if __name__ == "__main__":
    main()
