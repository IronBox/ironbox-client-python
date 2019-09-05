#!/usr/bin/python
#---------------------------------------------------
#   
#   Demonstrates how to create and remove an IronBox 
#   secure file transfer container 
#
#   Written by KevinLam@goironbox.com 
#   Website: www.goironbox.com
#
#---------------------------------------------------
from IronBoxREST import IronBoxRESTClient 
from IronBoxREST import IronBoxSFTContainerConfig

#---------------------------------------------------
# Your IronBox authentication parameters, you could
# also pass these in as command arguments
#---------------------------------------------------
IronBoxEmail = "email@email.com"
IronBoxPassword = "password123"
IronBoxAPIVersion = "latest"

# Default context, otherwise use your IronBox context 
# instance, i.e., your_company.goironcloud.com
Context = "secure.goironcloud.com"

#---------------------------------------------------
# Main
#---------------------------------------------------
def main():
    
    #--------------------------------------------------
    #	Create an instance of the IronBox REST class
    #--------------------------------------------------
    IronBoxRESTObj = IronBoxRESTClient(IronBoxEmail, IronBoxPassword, version=IronBoxAPIVersion, verbose=True)

    #--------------------------------------------------
    #	Create the container, duplicate container names
    #	are supported
    #--------------------------------------------------
    ContainerConfig = IronBoxSFTContainerConfig() 
    ContainerConfig.Name = "New container name"
    ContainerConfig.Description = "Description of the new container (optional)"
    ResultContainerConfig = IronBoxRESTObj.CreateEntitySFTContainer(Context, ContainerConfig)
    if ResultContainerConfig is None:
	print("Unable to create container")
	return

    print("New container created with ID=%s" % ResultContainerConfig.ContainerID)

    #--------------------------------------------------
    #	Remove the container
    #--------------------------------------------------
    if IronBoxRESTObj.RemoveEntityContainer(ResultContainerConfig.ContainerID) is False:
	print("Unable to remove container")
	return

    print("New container was successfully removed")

#---------------------------------------------------
import string, datetime
if __name__ == "__main__":
    main()
