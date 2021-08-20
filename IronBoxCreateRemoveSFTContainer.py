"""
Demonstrates how to create and remove an IronBox 
secure file transfer container 

Written by KevinLam@goironbox.com 
Modified by motorific@gmail.com
Website: www.goironbox.com
"""

from IronBoxREST import IronBoxRESTClient
from IronBoxREST import IronBoxSFTContainerConfig

# ---------------------------------------------------
# Your IronBox authentication parameters, you could
# also pass these in as command arguments
# ---------------------------------------------------
ironbox_email = "email@email.com"
ironbox_pwd = "password123"
ironbox_api_version = "latest"

# Default context, otherwise use your IronBox context
# instance, i.e., your_company.goironcloud.com
context = "secure.goironcloud.com"


def main():

    # --------------------------------------------------
    # 	Create an instance of the IronBox REST class
    # --------------------------------------------------
    IronBoxRESTObj = IronBoxRESTClient(
        ironbox_email, ironbox_pwd, version=ironbox_api_version, verbose=True
    )

    # --------------------------------------------------
    # 	Create the container, duplicate container names
    # 	are supported
    # --------------------------------------------------
    container_config = IronBoxSFTContainerConfig()
    container_config.Name = "New container name"
    container_config.Description = "Description of the new container (optional)"
    result_cont_conf = IronBoxRESTObj.create_entity_sft_cont(context, container_config)
    if result_cont_conf is None:
        print("Unable to create container")
        return

    print(f"New container created with ID={result_cont_conf.container_id}")

    # Remove the container
    if IronBoxRESTObj.remove_entity_container(result_cont_conf.container_id) is False:
        print("Unable to remove container")
        return

    print("New container was successfully removed")


if __name__ == "__main__":
    main()
