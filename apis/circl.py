import aiohttp
import asyncio

async def fetch_page(session, vendor, product, page):
    url = f"https://cve.circl.lu/api/search/{vendor}/{product}?page={page}"
    try:
        async with session.get(url) as r:
            if r.status == 200:
                return await r.json()
            else:
                print(f"Error {r.status} on page {page}")
                return None
    except Exception as e:
        print(f"Exception on page {page}: {e}")
        return None

async def circl_api(vendor=None, product=None, pages=10):
    cves = []
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_page(session, vendor, product, i) for i in range(pages)]
        results = await asyncio.gather(*tasks)

        for data in results:
            if not data:
                continue
            dataset = data.get("results", {})
            for key, entries in dataset.items():
                for item in entries:
                    try:
                        if key == "cvelistv5":
                            cve = item[1]
                            id_ = cve.get("cveMetadata", {}).get("cveId")
                            description = cve.get("containers", {}).get("cna", {}).get("descriptions", [{}])[0].get("value")
                            score = cve.get("containers", {}).get("cna", {}).get("metrics", [{}])[0].get("cvssV3_1", {})
                            cves.append({
                                "id": id_,
                                "description": description,
                                "score": score
                            })
                        elif key == "fkie_nvd":
                            cve = item[1]
                            id_ = cve.get("id")
                            score = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore")
                            description = cve.get("descriptions", [{}])[0].get("value")
                            cves.append({
                                "id": id_,
                                "description": description,
                                "score": score
                            })
                        elif key == "nvd":
                            cve = item[1]
                            id_ = cve.get("cveMetadata", {}).get("cveId")
                            description = cve.get("containers").get("cna").get("descriptions")[0].get("value")
                            score = cve.get("containers", "N/A").get("cna", "N/A").get("metrics", "N/A")[0].get("cvssV3_1", "N/A")
                            cves.append({
                                "id": id_,
                                "description": description,
                                "score": score
                            })
                    except Exception:
                        return "error"
    return cves
