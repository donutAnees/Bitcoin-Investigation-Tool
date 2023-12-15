import requests
import re
from bs4 import BeautifulSoup

def getWebsiteWallet(websiteurl):
    response = requests.get(websiteurl)
    soup = BeautifulSoup(response.content, 'html.parser')

    regex_pattern = re.compile(r"[\s:=\>](bc(0([ac-hj-np-z02-9]{39}|[ac-hj-np-z02-9]{59})|1[ac-hj-np-z02-9]{8,87})|[13][a-km-zA-HJ-NP-Z1-9]{25,35})")

    matches = soup.find_all(string=regex_pattern)

    for tag in soup.find_all(string=regex_pattern):
        matches = re.findall(regex_pattern, tag)
        for match in matches:
            print(match[0])

if __name__ == "__main__":
    getWebsiteWallet("https://bitcointalk.org/index.php?topic=5476162.0")
