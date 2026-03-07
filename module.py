import asyncio
from pprint import pprint
from apis.circl import circl_api
from src.cve_search import search_cve
from src.cpe_search import search_cpe
from src.setup.enum import display_vulnerabilities


class CVE_Search:

    def __init__(self, vendor=None, product=None, version=None,cpes=None ,cpe=False):
        self.vendor = vendor
        self.product = product
        self.version = version
        self.check = cpe
        self.cpes0 = cpes

    async def check_cpe(self):
        if self.check == False:
             cpes = await self.extract_cpes()
             return await self.send_apis(cpes)
        elif self.check == True:
             self.vendor = None
             return await search_cve(self.cpes0)

    async def extract_cpes(self):
        if self.version is None:
             cpes = await search_cpe(self.vendor)
             return await display_vulnerabilities(cpes)
        cpes = await search_cpe(self.vendor, self.version)
        return await display_vulnerabilities(cpes)

    async def send_apis(self, cpes) -> dict:
        circl_cve, nvd_cve = await asyncio.gather(
                circl_api(self.vendor, self.product),
                search_cve(cpes)
        )
        final_cves = {
            "nvd_cves": nvd_cve,
            "circl_cves": circl_cve
        }

        return final_cves
