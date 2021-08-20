"""   
   Demonstrates how to retrieve the ID and names of
   each blob in an IronBox container by the given 
   state. 

   Written by KevinLam@goironbox.com 
   Modified by motorific@gmail.com
   Website: www.goironbox.com

   Usage:
	python IronBoxGetBlobInfoListByState.py
"""


from IronBoxREST import IronBoxRESTClient

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


def main():

    # Create an instance of the IronBox REST class
    IronBoxRESTObj = IronBoxRESTClient(
        ironbox_email, ironbox_pwd, version=ironbox_api_version, verbose=True
    )

    # Get all the blobs in a ready state, result is a tuple list
    # where 0 = blob ID and 1 = blob name
    result = IronBoxRESTObj.get_cont_blob_info_by_state(container_id, blob_state)
    for item in result:
        print(f"{item[0]} -> {item[1]}")


if __name__ == "__main__":
    main()
