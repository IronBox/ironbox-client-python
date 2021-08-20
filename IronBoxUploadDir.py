"""
   Demonstrates how to upload a directory to 
   an IronBox secure package or container. Note 
   this script does not recurse into subdirectories

   Written by KevinLam@goironbox.com 
   Modified by motorific@gmail.com
   Website: www.goironbox.com

   Usage:
    python IronBoxUploadDir.py dir_to_upload
"""

import sys

from os import listdir
from os.path import isfile, join
from IronBoxREST import IronBoxRESTClient 

#---------------------------------------------------
# Your IronBox authentication parameters, you could
# also pass these in as command arguments
#---------------------------------------------------
container_id = 100777	
ironbox_email = "email@email.com"
ironbox_pwd = "password"
ironbox_api_url = "https://api.goironcloud.com/latest/"
ironbox_api_version = "latest"

# The directory to upload is the 1st command line 
# argument, or hardcode the directory you want to upload
#InDir = "source_dir"
in_dir = sys.argv[1]


def main():
    
    IronBoxRESTObj = IronBoxRESTClient(ironbox_email, ironbox_pwd, version=ironbox_api_version, verbose=True)

    # Get all the files in the target directory
    file_dir = [f for f in listdir(in_dir) if isfile(join(in_dir, f))]
    
    # Iterate the dirFiles array and upload each file
    for file_name in file_dir:  
        current_path = join(in_dir,file_name)	
	IronBoxRESTObj.upload_file_to_container(container_id, current_path, file_name)


if __name__ == "__main__":
    main()
