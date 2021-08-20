"""
   IronBox REST API Python wrapper
   Version: 2.0 (08/19/2021)
   Author: KevinLam@goironbox.com
   Modified by: motorific@gmail.com
   Website: www.goironbox.com
   Change History:

   08/19/2021   -   v2.0 Refactored file for Python 3.8
                    Included type hints
                    Used dataclasses
                    Updated AES Cipher call to new library pycryptodome
                    fixed base64 encoding errors
                    fixed bytes + str concat errors

    01/06/2014  -	v1.9 Added verifySSLCert flag, which allows callers
                    to control if they want to validate SSL certificates
                    or not when connecting to API servers or not, default
                    on.

    01/02/2014  -	v1.8 Corrected issue with Encrypt_File method
                    in ContainerKeyData class. Final padding check
                    should be based on the read block size, not
                    AES block size, was only an issue for files < 1024
                    and multiple of 16.

    12/16/2013  -	v1.7 Added CreateEntitySFTContainer and
                    RemoveEntityContainer

    12/06/2013  -	v1.6 Added GetContextSetting and
                    GetContainerInfoListByContext methods

    12/04/2013  -	v1.5 Added RemoveEntityContainerBlob,
                    DownloadBlobFromContainer (helper method),
                    ReadEntityContainerBlob

    12/04/2013  -	v1.4 Added GetContainerBlobInfoListByState

    11/15/2013  -	v1.3 Added x-ms-version in BlockBlob upload for
                         stricter adherence to protocol

    11/12/2013  -	v1.2 Removed dependency on M2Crypto, Urllib,
                    Urllib2, openssl and Json.  Added pycrypto.
                    Using BlockBlob and re-assembling on the server
                    as it's more efficient than PageBlobs

    11/10/2013  -	v1.1 Initial release (beta)

"""
import base64
import datetime
import os
import sys
from dataclasses import dataclass
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import requests
from Crypto.Cipher import AES


def pad(s) -> bytes:
    block_size = AES.block_size
    return s + (
        (block_size - len(s) % block_size) * chr(block_size - len(s) % block_size)
    ).encode("utf-8")


def unpad(s) -> bytes:
    return s[0 : -ord(s[-1])]


@dataclass
class IronBoxSFTContainerConfig:
    name = ""
    description = ""
    container_id = -1
    friendly_id = ""

    def debug_print_props(self):
        print(f"Name: {self.name}")
        print(f"Description: {self.description}")
        print(f"ContainerID: {self.container_id}")
        print(f"FriendlyID: {self.friendly_id}")


@dataclass
class IronBoxBlobCheckOutData:
    shared_access_signature: str = ""
    sas_uri: str = ""
    checkin_token: str = ""
    storage_uri: str = ""
    storage_type: int = 1  # always set to 1
    cont_storage_name: str = ""

    def debug_print_props(self):
        print(f"SharedAccessSignature: {self.shared_access_signature}")
        print(f"SharedAccessSignatureUri: {self.sas_uri}")
        print(f"CheckInToken: {self.checkin_token}")
        print(f"StorageUri: {self.storage_uri}")
        print(f"StorageType: {self.storage_type}")
        print(f"ContainerStorageName: {self.cont_storage_name}")


@dataclass
class IronBoxBlobReadData:
    container_storage_name: str = ""
    shared_access_signature: str = ""
    sas_uri: str = ""
    storage_type: str = ""
    storage_uri: str = ""

    def debug_print_props(self):
        print(f"ContainerStorageName: {self.container_storage_name}")
        print(f"SharedAccessSignature: {self.shared_access_signature}")
        print(f"SharedAccessSignatureUri: {self.sas_uri}")
        print(f"StorageType: {self.storage_type}")
        print(f"StorageUri: {self.storage_uri}")


@dataclass
class IronBoxKeyData:
    # Symmetric key
    symmetric_key: bytes = None

    # IV
    IV: bytes = None

    # Symmetric key strength 0 = none, 1 = 128 and 2 = 256
    key_factor: int = 2

    def encrypt_file(self, in_filename, out_filename) -> bool:
        """
        Encrypts a file using the symmetric key data
        :param in_filename:
        :param out_filename:
        :return: True if success, else False
        """

        read_block_size = 1024

        try:
            e = AES.new(self.symmetric_key, AES.MODE_CBC, self.IV)
            if not os.path.exists(in_filename):
                return False
            with open(in_filename, "rb") as infile:
                with open(out_filename, "wb") as outfile:
                    while True:
                        buf = infile.read(read_block_size)
                        if not buf:
                            break
                        if len(buf) < read_block_size:
                            buf = pad(buf)

                        outfile.write(e.encrypt(buf))

                    """if the in_file length is a multiple of the read block size,
                     then there will be no padding, so we need to add a padded
                     block otherwise the cipher has no way of knowing where the
                     end of the cipher text is"""
                    if os.path.getsize(in_filename) % read_block_size == 0:
                        buf = pad(buf)
                        outfile.write(e.encrypt(buf))
            return True
        # TODO: Find the right exception
        except:
            # return False
            raise

    def decrypt_file(self, in_filename: str, out_filename: str) -> bool:
        """
        Decrypts a file using the symmetric key
        :param in_filename:
        :param out_filename:
        :return: True if success, False otherwise
        """
        try:
            d = AES.new(self.symmetric_key, AES.MODE_CBC, self.IV)
            if not os.path.exists(in_filename):
                return False
            with open(in_filename, "rb") as infile:
                with open(out_filename, "wb") as outfile:
                    while True:
                        buf = infile.read(1024)
                        if not buf:
                            break
                        decrypted = d.decrypt(buf)
                        if len(buf) < 1024:
                            decrypted = unpad(decrypted)
                        outfile.write(decrypted)
            return True
        except:
            return False


class IronBoxRESTClient:
    def __init__(
        self,
        entity,
        entity_password,
        entity_type=0,
        version="latest",
        content_format="application/json",
        verbose=False,
        verify_ssl_cert=True,
    ) -> None:

        # Actual entity identifier, this can be email address,
        # name identifier (mostly internal use only) or an entity
        # ID which is a 64-bit integer that identifies the specific
        # user
        self.entity = entity

        # Entity password
        self.entity_password = entity_password

        # Entity type, 0 = email address, 1 = name identifier, 2 = entity ID
        self.entity_type = entity_type

        # API server URL, default however can be changed
        # to test servers
        self.api_server_url = f"https://api.goironcloud.com/{version}/"

        # Accept format
        self.content_format = content_format

        # Flag that indicates whether or not to be verbose or not
        self.verbose = verbose

        # Verify SSL certificate flag
        self.verify_ssl_cert = verify_ssl_cert

        return

    def upload_file_to_container(
        self, container_id: int, file_path: str, blob_name: str
    ) -> bool:
        """

        :param container_id:
        :param file_path:
        :param blob_name:
        :return:
        """

        # Step 1: Test to make sure that the API server is accessible
        if not self.ping_server():
            raise Exception(
                "IronBox API server is not accessible from this network location"
            )
        self.console_log("IronBox API is up, starting transfer")

        # Step 2: Get the container key data
        iron_box_key_data = self.container_key_data(container_id)
        if not iron_box_key_data:
            raise Exception("Unable to retrieve container key data")
        self.console_log("Retrieved container symmetric key data")

        """
        #   Step 3:
        #   Create a container blob and check it out.
        #   This doesn't actually upload the contents, just
        #   creates the entry, and does a "check out" which
        #   lets IronBox know you're going to upload contents
        #   soon.  As part of the checkout process you'll get a
        #   check in token that is your way to check the
        #   blob back in.
        """
        blob_id_name = self.create_entity_container_blob(container_id, blob_name)
        if not blob_id_name:
            raise Exception("Unable to create blob in container")

        check_out_data = self.checkout_entity_container_blob(container_id, blob_id_name)
        if not check_out_data:
            raise Exception("Unable to checkout container blob")

        # Step 4: Make a copy of the file and encrypt it
        self.console_log("Encrypting a copy of " + file_path)
        original_file_size = os.path.getsize(file_path)
        encrypted_file_path = file_path + ".ironbox"

        if iron_box_key_data.encrypt_file(file_path, encrypted_file_path) is False:
            raise Exception("Unable to encrypt local copy of file")

        """
        #   Step 5:
        #   Upload the encrypted file using the shared
        #   access signature we got at checkout
        #   Use python-requests, since it's file upload is
        #   more advanced.
        """
        self.console_log("Uploading encrypted copy of " + file_path)
        if not self.upload_blob_with_sas(encrypted_file_path, check_out_data.sas_uri):
            raise Exception("Unable to upload encrypted file")

        # Step 6: Mark the file as ready to download by checking it back in
        if not self.checkin_entity_container_blob(
            container_id, blob_id_name, original_file_size, check_out_data.checkin_token
        ):
            raise Exception("Unable to finalize upload")

        self.console_log("Upload completed, cleaning up")

        # done
        os.remove(encrypted_file_path)
        return True

    def download_blob_from_container(
        self, container_id: int, blob_id: str, dest_file_path: str
    ) -> bool:
        """
        Downloads a blob from an IronBox container
        :param container_id: IronBox container ID, 64-bit integer
        :param blob_id: ID of blob to download
        :param dest_file_path: Path of the file to save the decrypted
        :return: True if success, False otherwise.
        """

        # Step 1: Test to make sure that the API server is accessible
        if not self.ping_server():
            raise Exception(
                "IronBox API server is not accessible from this network location"
            )
        self.console_log(
            f"IronBox API is up, starting download of target file {dest_file_path}"
        )

        # Step 2: Get the container key data
        iron_box_key_data = self.container_key_data(container_id)
        if not iron_box_key_data:
            raise Exception("Unable to retrieve container key data")
        self.console_log("Retrieved container symmetric key data")

        # Step 3: Download the SAS URI encrypted blob read data
        read_blob_data = self.read_entity_cont_blob(container_id, blob_id)
        if not read_blob_data:
            raise Exception("Unable to read container blob download data")
        self.console_log("Retrieved blob download Shared Access Signature URI")

        encrypted_file_path = dest_file_path + ".encrypted"
        r = requests.get(
            read_blob_data.sas_uri, stream=True, verify=self.verify_ssl_cert
        )
        num_bytes_downloaded = 0

        with open(encrypted_file_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
                    num_bytes_downloaded = num_bytes_downloaded + len(chunk)
                    # Show progress if needed
                    if self.verbose is True:
                        sys.stdout.write(
                            f"\rDownloaded {num_bytes_downloaded} encrypted byte(s) to {encrypted_file_path}"
                        )
                        sys.stdout.flush()
                    f.flush()

            # If verbose, we need to print out a new line
            if self.verbose:
                print("\n")

        #   Step 4: Decrypt the downloaded blob
        self.console_log("Decrypting encrypted blob")
        iron_box_key_data.decrypt_file(encrypted_file_path, dest_file_path)

        #  Step 5: Done, clean up
        self.console_log("Done, cleaning up %s" % encrypted_file_path)
        os.remove(encrypted_file_path)
        return True

    def upload_blob_with_sas(self, in_filename: str, sas_uri: str) -> bool:
        """
        Uploads an encrypted file to cloud storage using the
        shared access signature provided. This function uploads
        blocks in 4 MB blocks with max 50k blocks, meaning that
        there is a 200 GB max for any file uploaded

        Update 2021: Current MSFT Azure upload allows for larger blobs with new x-ms-version.
        See: https://docs.microsoft.com/en-us/rest/api/storageservices/put-block#remarks

        Service version	Maximum block size (via Put Block)	Maximum blob size (via Put Block List)	Maximum blob size via single write operation (via Put Blob)
        Version 2019-12-12 and later	 4000 MiB	Approximately 190.7 TiB (4000 MiB X 50,000 blocks)	5000 MiB (preview)
        Version 2016-05-31 - 2019-07-07	 100 MiB	Approximately 4.75 TiB (100 MiB X 50,000 blocks)	256 MiB
        Versions prior to 2016-05-31	 4 MiB	Approximately 195 GiB (4 MiB X 50,000 blocks)	64 MiB

        :param in_filename:
        :param sas_uri:
        :return: True if success, False otherwise.
        """

        # Validate file
        if not os.path.exists(in_filename):
            return False

        # Cloud storage only allows blocks of max 4MB, and max 50k blocks
        # so 200 GB max	per file
        block_size_mb = 4
        block_size_bytes = block_size_mb * 1024 * 1024
        file_size = os.path.getsize(in_filename)
        self.console_log(f"Starting send in {block_size_mb}MB increments")

        # Send headers
        headers = {
            "content-type": "application/octet-stream",
            "x-ms-blob-type": "BlockBlob",
            "x-ms-version": "2012-02-12",
        }

        # Open handle to encrypted file and send it in blocks
        sas_uri_block_prefix = sas_uri + "&comp=block&blockid="
        block_ids = []
        num_bytes_sent = 0
        i = 0
        with open(in_filename, "rb") as infile:
            while True:

                buf = infile.read(block_size_bytes)
                if not buf:
                    break

                # block IDs all have to be the same length, which was NOT
                # documented by MSFT
                block_id = f"block{i:08}".encode("utf-8")

                # String representation of b64 encoded the blockID cus that's what MSFT says.
                block_id = base64.b64encode(block_id).decode()
                block_sas_uri = sas_uri_block_prefix + block_id

                # Create a blob block
                r = requests.put(
                    block_sas_uri,
                    data=buf,
                    headers=headers,
                    verify=self.verify_ssl_cert,
                )
                if r.status_code != requests.codes.created:
                    return False

                # Block was successfully sent, record its ID
                block_ids.append(block_id)
                num_bytes_sent += len(buf)
                i += 1

                # Show progress if needed
                if self.verbose is True:
                    done = int(50 * num_bytes_sent / file_size)
                    sys.stdout.write(
                        "\r[%s%s] %d byte(s) sent"
                        % ("=" * done, " " * (50 - done), num_bytes_sent)
                    )
                    sys.stdout.flush()

        # We're done, so if verbose go to new line
        if self.verbose:
            print("\n")

        # Done sending blocks, so commit the blocks into a single one
        # do the final re-assembly on the storage server side
        commit_block_sas_url = sas_uri + "&comp=blockList"
        commit_headers = {"content-type": "text/xml", "x-ms-version": "2012-02-12"}
        # build list of block ids as xml elements
        block_list_body = ""
        for x in block_ids:
            # Indicate blocks to commit per 2012-02-12 version PUT block list specifications
            block_list_body += f"<Latest>{x}</Latest>"

        commit_body = f'<?xml version="1.0" encoding="utf-8"?><BlockList>{block_list_body}</BlockList>'
        commit_response = requests.put(
            commit_block_sas_url,
            data=commit_body,
            headers=commit_headers,
            verify=self.verify_ssl_cert,
        )

        return commit_response.status_code == requests.codes.created

    def console_log(self, m) -> None:
        """
        Console logger
        :param m:
        :return:
        """
        if self.verbose is True:
            now = datetime.datetime.now()
            str(now) + ": " + m

    def ping_server(self):
        """
        Checks if the IronBox API server is responding
        :return: json response if True, False otherwise
        """
        r = requests.get(self.api_server_url + "Ping", verify=self.verify_ssl_cert)
        if r.status_code == requests.codes.ok:
            return r.json()
        return False

    def container_key_data(self, container_id: int) -> Optional[IronBoxKeyData]:
        """
        Fetches an ironbox container key data
        :param container_id: 64-bit integer container identifier
        :return:
        """
        url = self.api_server_url + "ContainerKeyData"

        post_data = {
            "Entity": self.entity,
            "EntityType": self.entity_type,
            "EntityPassword": self.entity_password,
            "ContainerID": container_id,
        }

        r = requests.post(
            url,
            data=post_data,
            headers={"Accept": self.content_format},
            verify=self.verify_ssl_cert,
        )

        if r.status_code != requests.codes.ok:
            return None

        # Parse the response, get container key, IV and strength
        response = r.json()
        if not response:
            return None

        container_key_data = IronBoxKeyData()

        session_key_base_64 = response.get("SessionKeyBase64", None)
        if not session_key_base_64:
            return None
        container_key_data.symmetric_key = base64.b64decode(session_key_base_64)
        container_key_data.IV = base64.b64decode(response.get("SessionIVBase64"))
        container_key_data.key_factor = response.get("SymmetricKeyStrength")

        return container_key_data

    def create_entity_container_blob(
        self, container_id: int, blob_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        Creates an Ironbox blob in an existing container
        :param container_id:
        :param blob_name:
        :return: json response or None
        """
        post_data = {
            "Entity": self.entity,
            "EntityType": self.entity_type,
            "EntityPassword": self.entity_password,
            "ContainerID": container_id,
            "BlobName": blob_name,
        }
        url = self.api_server_url + "CreateEntityContainerBlob"

        r = requests.post(
            url,
            data=post_data,
            headers={"Accept": self.content_format},
            verify=self.verify_ssl_cert,
        )

        if r.status_code != requests.codes.ok:
            return None

        return r.json()

    def checkout_entity_container_blob(
        self, container_id: int, blob_id_name: Dict[str, Any]
    ) -> Optional[IronBoxBlobCheckOutData]:
        """
        Checks out an entity container blob so that the caller can begin uploading
        the contents of the blob.
        :param container_id: 64-bit integer container id
        :param blob_id_name: Id of the blob to be checked out.
        :return:
        """
        post_data = {
            "Entity": self.entity,
            "EntityType": self.entity_type,
            "EntityPassword": self.entity_password,
            "ContainerID": container_id,
            "BlobIDName": blob_id_name,
        }
        url = self.api_server_url + "CheckOutEntityContainerBlob"

        r = requests.post(
            url,
            data=post_data,
            headers={"Accept": self.content_format},
            verify=self.verify_ssl_cert,
        )

        if r.status_code != requests.codes.ok:
            return None

        response = r.json()
        if not response:
            return None

        check_out_data = IronBoxBlobCheckOutData()

        shared_access_signature = response.get("SharedAccessSignature", None)
        if not shared_access_signature:
            return None

        check_out_data.shared_access_signature = shared_access_signature
        check_out_data.sas_uri = response.get("SharedAccessSignatureUri")
        check_out_data.checkin_token = response.get("CheckInToken")
        check_out_data.storage_uri = response.get("StorageUri")
        check_out_data.storage_type = response.get("StorageType")
        check_out_data.cont_storage_name = response.get("ContainerStorageName")

        # check_out_data.DebugPrintProps()

        return check_out_data

    def checkin_entity_container_blob(
        self,
        container_id: int,
        blob_id_name: Dict[str, Any],
        blob_size_bytes: int,
        checkin_token: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Checks in a checked out entity container blob
        :param container_id: 64-bit integer container id
        :param blob_id_name: ID of the blob to be checked in
        :param blob_size_bytes: size of the blob in bytes
        :param checkin_token: token
        :return:
        """
        post_data = {
            "Entity": self.entity,
            "EntityType": self.entity_type,
            "EntityPassword": self.entity_password,
            "ContainerID": container_id,
            "BlobIDName": blob_id_name,
            "BlobSizeBytes": blob_size_bytes,
            "BlobCheckInToken": checkin_token,
        }
        url = self.api_server_url + "CheckInEntityContainerBlob"

        r = requests.post(
            url,
            data=post_data,
            headers={"Accept": self.content_format},
            verify=self.verify_ssl_cert,
        )

        if r.status_code != requests.codes.ok:
            return None

        return r.json()

    def get_cont_blob_info_by_state(
        self, container_id: int, blob_state: int
    ) -> Optional[List[Tuple[Any, Any]]]:
        """
        Returns information about hte blobs in the given container that
        are in a given state. For example, if a 'ready' state is provided, then
        this function returns the container blobs that are in a ready state.
        :param container_id: 64-bit container id
        :param blob_state: 32-bit integer
                    0 = Blob created
                    1 = Entity is uploading
                    2 = Ready
                    3 = Checked out
                    4 = Entity is modifying
                    5 = None
        :return: 2-Tuple where 0 = blob_id and 1 = blob_name
        """

        post_data = {
            "Entity": self.entity,
            "EntityType": self.entity_type,
            "EntityPassword": self.entity_password,
            "ContainerID": container_id,
            "BlobState": blob_state,
        }
        url = self.api_server_url + "GetContainerBlobInfoListByState"

        r = requests.post(
            url,
            data=post_data,
            headers={"Accept": self.content_format},
            verify=self.verify_ssl_cert,
        )

        if r.status_code != requests.codes.ok:
            return None

        # Get the Json response
        response = r.json()
        if not response:
            return None

        # Start parsing the Json response into a list of double-tuples
        # where 0 = BlobID and 1 = BlobName
        # TODO: Make sure this actually returns a tuple.
        result = list()
        json_data = response["BlobInfoArray"]
        for item in json_data:
            # Create a tuple [BlobID,BlobName] and add to our
            # result list
            t = item.get("BlobID"), item.get("BlobName")
            result.append(t)

        # Done, return result list of double-tuples
        return result

    def read_entity_cont_blob(
        self, container_id: int, blob_id: str
    ) -> Optional[IronBoxBlobReadData]:
        """
        Retrieves the storage information required to read
        encrypted entity container blobs directly from storage.
        Returned information will include storage endpoint URL,
        container name and a shared access signature that grants
        limited temporary access to back-end storage.

        Callers can then use the URL specified in the
        SharedAccessSignatureUri response to directly read the
        encrypted blob from storage.

        Once downloaded, callers must then decrypt the encrypted
        blob using the information provided from the call to
        ContainerKeyData.
        :param container_id:
        :param blob_id:
        :return:
        """

        post_data = {
            "Entity": self.entity,
            "EntityType": self.entity_type,
            "EntityPassword": self.entity_password,
            "ContainerID": container_id,
            "BlobIDName": blob_id,
        }
        url = self.api_server_url + "ReadEntityContainerBlob"

        r = requests.post(
            url,
            data=post_data,
            headers={"Accept": self.content_format},
            verify=self.verify_ssl_cert,
        )

        if r.status_code != requests.codes.ok:
            return None

        # Parse the response, get container key, IV and strength
        response = r.json()
        if not response:
            return None

        # Parse response into an IronBoxBlobReadData object
        blob_read_data = IronBoxBlobReadData()
        blob_read_data.container_storage_name = response.get("ContainerStorageName")
        blob_read_data.shared_access_signature = response.get("SharedAccessSignature")
        blob_read_data.sas_uri = response.get("SharedAccessSignatureUri")
        blob_read_data.storage_type = response.get("StorageType")
        blob_read_data.storage_uri = response.get("StorageUri")

        # Done, return the blob read data
        return blob_read_data

    def remove_entity_cont_blob(
        self, container_id: int, blob_id: str
    ) -> Optional[Dict[str, Any]]:
        """
        Removes a blob from an entity container
        :param container_id: 64-bit integer
        :param blob_id: ID of the blob being checked in
        :return: True if success, else False
        """
        post_data = {
            "Entity": self.entity,
            "EntityType": self.entity_type,
            "EntityPassword": self.entity_password,
            "ContainerID": container_id,
            "BlobIDName": blob_id,
        }
        url = self.api_server_url + "RemoveEntityContainerBlob"

        r = requests.post(
            url,
            data=post_data,
            headers={"Accept": self.content_format},
            verify=self.verify_ssl_cert,
        )

        if r.status_code != requests.codes.ok:
            return None

        return r.json()

    def get_context_setting(
        self, context: str, context_setting: str
    ) -> Optional[Dict[str, Any]]:
        """
        Gets a setting for a given context. For example, using this call you can
        retrieve certain properties of the context secure.goironcloud.com such as company name, company
        logo, URL, etc. The entity making this request must already be a member o the context.
        :param context:
        :param context_setting:
        :return:
        """

        post_data = {
            "Entity": self.entity,
            "EntityType": self.entity_type,
            "EntityPassword": self.entity_password,
            "Context": context,
            "ContextSetting": context_setting,
        }
        url = self.api_server_url + "GetContextSetting"

        r = requests.post(
            url,
            data=post_data,
            headers={"Accept": self.content_format},
            verify=self.verify_ssl_cert,
        )

        if r.status_code != requests.codes.ok:
            return None

        return r.json()

    def get_cont_info_by_context(
        self, context: str, container_type: int = 5
    ) -> Optional[List[Tuple[Any, Any]]]:
        """
        Returns the Ids and names of a container for an entity in a given context and
        given container type (always 5).
        :param context:
        :param container_type: 5
        :return:
        """

        post_data = {
            "Entity": self.entity,
            "EntityType": self.entity_type,
            "EntityPassword": self.entity_password,
            "Context": context,
            "ContainerType": container_type,
        }
        url = self.api_server_url + "GetContainerInfoListByContext"

        r = requests.post(
            url,
            data=post_data,
            headers={"Accept": self.content_format},
            verify=self.verify_ssl_cert,
        )

        if r.status_code != requests.codes.ok:
            return None

        # Get the Json response
        response = r.json()
        if not response:
            return None

        # Start parsing the Json response into a list of double-tuples
        # where 0 = ContainerID and 1 = ContainerName
        result = list()
        json_data = response["ContainerInfoArray"]
        for item in json_data:
            # Create a tuple [ContainerID,ContainerName] and add to our
            # result list
            t = item.get("ContainerID"), item.get("ContainerName")
            result.append(t)

        # Done, return result list of double-tuples
        return result

    def create_entity_sft_cont(
        self, context: str, container_config: IronBoxSFTContainerConfig
    ) -> Optional[IronBoxSFTContainerConfig]:
        """
        Creates an IronBox entity secure file transfer (SFT) container with the given container
        configuration information and for the given context. The caller must already be a member
        of the given context and must have permissions to create SFT containers.
        :param context:
        :param container_config:
        :return: IronBoxSFTContainerConfig or None
        """

        post_data = {
            "Entity": self.entity,
            "EntityType": self.entity_type,
            "EntityPassword": self.entity_password,
            "Context": context,
            "Name": container_config.name,
            "Description": container_config.description,
        }

        url = self.api_server_url + "CreateEntitySFTContainer"

        r = requests.post(
            url,
            data=post_data,
            headers={"Accept": self.content_format},
            verify=self.verify_ssl_cert,
        )

        if r.status_code != requests.codes.ok:
            return None

        # Parse the response, get container key, IV and strength
        response = r.json()
        if not response:
            return None

        # Parse response into an IronBoxSFTContainerData object
        result_container_data = IronBoxSFTContainerConfig()
        result_container_data.name = response.get("Name")
        result_container_data.description = response.get("Description")
        result_container_data.container_id = response.get("ContainerID")
        result_container_data.friendly_id = response.get("FriendlyID")

        # Done, return our parsed container data object
        return result_container_data

    def remove_entity_container(self, container_id: int) -> Optional[Dict[str, Any]]:
        """
        Removes an entity container. The caller must be the owner of the container.
        :param container_id: 64-bit integer
        :return: True if success, False otherwise
        """
        post_data = {
            "Entity": self.entity,
            "EntityType": self.entity_type,
            "EntityPassword": self.entity_password,
            "ContainerID": container_id,
        }
        url = self.api_server_url + "RemoveEntityContainer"

        r = requests.post(
            url,
            data=post_data,
            headers={"Accept": self.content_format},
            verify=self.verify_ssl_cert,
        )

        if r.status_code != requests.codes.ok:
            return None

        return r.json()
