#!/usr/bin/python
#---------------------------------------------------
#   
#   Demonstrates how to get the containers that 
#   an entity has access to in a context. 
#
#   A context simply refers to an IronBox instance  
#   or server that an entity logs into.  For example,
#   an entity might log into the following:
#
#	Context1: secure.goironcloud.com
#	Context2: test.goironcloud.com
#
#   This demo shows you how to the retrieve the
#   IronBox containers that the entity has access to
#   in each of the individual contexts 
#
#   Written by KevinLam@goironbox.com 
#   Website: www.goironbox.com
#
#   Usage:
#	python IronBoxGetContextContainers.py
#
#---------------------------------------------------
from IronBoxREST import IronBoxRESTClient 

#---------------------------------------------------
# Your IronBox authentication parameters, you could
# also pass these in as command arguments
#---------------------------------------------------
IronBoxEmail = "email@email.com"
IronBoxPassword = "password123"
IronBoxAPIServerURL = "https://api.goironcloud.com/latest/"
IronBoxAPIVersion = "latest"

# This is the server you log into, minus the "https://"
Context = "secure.goironcloud.com"  

# Always use '5' which refers to AES-256 secure file
# transfer containers 
ContainerType = 5

#---------------------------------------------------
# Main
#---------------------------------------------------
def main():
    
    #----------------------------
    #	Create an instance of the IronBox REST class
    #----------------------------
    IronBoxRESTObj = IronBoxRESTClient(IronBoxEmail, IronBoxPassword, version=IronBoxAPIVersion, verbose=True)

    # Get all the blobs in a ready state, result is a tuple list
    # where 0 = blob ID and 1 = blob name
    result = IronBoxRESTObj.GetContainerInfoListByContext(Context, ContainerType)
    for item in result:
        print("%s -> %s" % (item[0],item[1]))

#---------------------------------------------------
if __name__ == "__main__":
    main()
