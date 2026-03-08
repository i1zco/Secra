import asyncio
from apis.circl import circl_api
from src.cve_search import search_cve
from src.cpe_search import search_cpe
from src.setup.enum import display_vulnerabilities


class CVE_Search:


    def __init__(self, vendor=None, product=None, version=None, cpes=None, **kwargs):
        self.vendor = vendor
        self.product = product
        self.version = version
        self.cpes = cpes
        self.extra_args = kwargs

    async def search_cpe(self):

        if self.version:
            query = " ".join(filter(None, [self.vendor, self.product, str(self.version)]))
        else:
            query = " ".join(filter(None, [self.vendor, self.product]))
        return await search_cpe(query, **self.extra_args)

    async def select_cpe(self, cpes):

        if not cpes:
            return None
        return await display_vulnerabilities(cpes)

    async def fetch_cves(self, cpes):

        circl_cve, nvd_cve = await asyncio.gather(
            circl_api(self.vendor, self.product, **self.extra_args),
            search_cve(cpes)
        )
        return {
            "nvd_cves": nvd_cve,
            "circl_cves": circl_cve
        }

    async def run_search(self):

        if self.cpes:
            cpe_selected = self.cpes
        else:
            cpes_list = await self.search_cpe()
            cpe_selected = await self.select_cpe(cpes_list)

        if not cpe_selected:
            print("[!] No CPE found or selected.")
            return None

        return await self.fetch_cves(cpe_selected)
