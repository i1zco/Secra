import aiohttp
import asyncio

async def circl_api(vendor=None, product=None):
    url = f"https://cve.circl.lu/api/search/{vendor}/{product}"
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as r:
            data = await r.json()

    data2 = data.get("results", {})
    cves = []
    keys = []
    for key in data2.keys():
        keys.append(key)
    for e in keys:
      for i in data2.get(e, {}):
         if "cvelistv5" in keys:
            for y in data2.get(key, {}):
               cve = y[1]
               id = cve.get("cveMetadata").get("cveId",{})
               description = cve.get("containers").get("cna").get("descriptions")[0].get("value")
               score = cve.get("containers", "N/A").get("cna", "N/A").get("metrics", "N/A")[0].get("cvssV3_1", "N/A")

               cves.append({
                    "id": id,
                    "description": description,
                    "score": score
               })
            return cves
         try:
                cve = i[1]
                id = cve.get("id")
                score = cve.get("metrics", {}).get("cvssMetricV31",[{}])[0].get("cvssData", {}).get("baseScore")
                cves.append({
                    "ID": id,
                    "Score": score,
                    "Description": cve.get('descriptions')[0].get("value")
                })
         except Exception:
           return "circl_api error"

    return cves
