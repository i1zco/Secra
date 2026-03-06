import nvdlib
import time

def search_cpe(os_name, version=None):

    if version is None:
        search_query = f"{os_name}"
        try:
            cpes = nvdlib.searchCPE(keywordSearch=search_query)
            return cpes
        except Exception:
             raise "Error in NVD API"

    search_query = f"{os_name} {version}"
    try:

        cpes = nvdlib.searchCPE(keywordSearch=search_query)
        time.sleep(2)
        return cpes
         
    except Exception as e:
        print(f"Error in Searching CPEs: {e}")
