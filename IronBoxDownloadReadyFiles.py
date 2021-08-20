"""
   Demonstrates how to download blobs in an IronBox
   container that are in a ready state.

   Written by KevinLam@goironbox.com 
   Modified by motorific@gmail.com
   Website: www.goironbox.com


   Usage:
	python IronBoxDownloadReadyFiles.py
"""


from IronBoxREST import IronBoxRESTClient
from os.path import join

# ---------------------------------------------------
# Your IronBox authentication parameters, you could
# also pass these in as command arguments
# ---------------------------------------------------
container_id = 100777
ironbox_email = "email@email.com"
ironbox_pwd = "password"
ironbox_api_url = "https://api.goironcloud.com/latest/"
ironbox_api_version = "latest"

# Gets all the blobs in the Ready state (2). Other states:
#   0 = Blob created
#   1 = Entity is uploading
#   2 = Ready
#   3 = Checked out
#   4 = Entity is modifying
#   5 = None
blob_state = 2
output_dir = "./"


def main():

    # Create an instance of the IronBox REST class
    IronBoxRESTObj = IronBoxRESTClient(
        ironbox_email, ironbox_pwd, version=ironbox_api_version, verbose=True
    )

    # Get all the blobs in a ready state, result is a tuple list
    # where 0 = blob ID and 1 = blob name
    result = IronBoxRESTObj.get_cont_blob_info_by_state(container_id, blob_state)
    for item in result:

        # Download and save the file locally
        dest_file_path = join(output_dir, item[1])
        if IronBoxRESTObj.download_blob_from_container(
            container_id, item[0], dest_file_path
        ):
            # Optionally you can delete the blob after download
            # IronBoxRESTObj.RemoveEntityContainerBlob(ContainerID,item[0])
            pass


if __name__ == "__main__":
    main()
