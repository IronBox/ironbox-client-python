#!/usr/bin/python
#---------------------------------------------------
#   
#   Demonstrates how to retrieve a setting for an
#   IronBox context or instance. This will be useful
#   when you want get information about a context
#   like secure.goironcloud.com such as company name,
#   the URL to the logo, etc.
#
#   Important, the entity making this call must 
#   already be a member of the context.
#
#   Written by KevinLam@goironbox.com 
#   Website: www.goironbox.com
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

Context = "secure.goironcloud.com"

#---------------------------------------------------
# Main
#---------------------------------------------------
def main():
    
    #----------------------------
    #	Create an instance of the IronBox REST class
    #----------------------------
    IronBoxRESTObj = IronBoxRESTClient(IronBoxEmail, IronBoxPassword, version=IronBoxAPIVersion, verbose=True)

    #---------------------------- 
    #	Get some public information about the context
    #---------------------------- 
    print("Company Name: %s" % IronBoxRESTObj.GetContextSetting(Context, "CompanyName"))
    print("Company Logo URL: %s" % IronBoxRESTObj.GetContextSetting(Context, "CompanyLogoUrl"))

#---------------------------------------------------
import string, datetime
if __name__ == "__main__":
    main()
