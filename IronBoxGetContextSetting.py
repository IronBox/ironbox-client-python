"""
   Demonstrates how to retrieve a setting for an
   IronBox context or instance. This will be useful
   when you want get information about a context
   like secure.goironcloud.com such as company name,
   the URL to the logo, etc.

   Important, the entity making this call must 
   already be a member of the context.

   Written by KevinLam@goironbox.com 
   Modified by motorific@gmail.com
   Website: www.goironbox.com
"""


from IronBoxREST import IronBoxRESTClient 

#---------------------------------------------------
# Your IronBox authentication parameters, you could
# also pass these in as command arguments
#---------------------------------------------------
ironbox_email = "email@email.com"
ironbox_pwd = "password123"
ironbox_api_url = "https://api.goironcloud.com/latest/"
ironbox_api_version = "latest"

Context = "secure.goironcloud.com"


def main():
    
    IronBoxRESTObj = IronBoxRESTClient(ironbox_email, ironbox_pwd, version=ironbox_api_version, verbose=True)

    # Get some public information about the context
    print(f"Company Name: {IronBoxRESTObj.get_context_setting(Context, 'CompanyName')}")
    print(f"Company Logo URL: {IronBoxRESTObj.get_context_setting(Context, 'CompanyLogoUrl')}")


if __name__ == "__main__":
    main()
