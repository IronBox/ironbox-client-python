"""
   Demonstrates how to upload a file to 
   an IronBox secure package or container

   Written by KevinLam@goironbox.com 
   Modified by motorific@gmail.com
   Website: www.goironbox.com
"""


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


def main():
    
    # Create an instance of the IronBox REST class
    IronBoxRESTObj = IronBoxRESTClient(IronBoxEmail, IronBoxPassword, version=IronBoxAPIVersion, verbose=True)

    IronBoxRESTObj.upload_file_to_container(ContainerID, InFile, IronBoxFileName)


import string, datetime
if __name__ == "__main__":
    main()
