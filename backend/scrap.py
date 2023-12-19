import requests
import re
from bs4 import BeautifulSoup

def getWebsiteWallet(websiteurl):
    response = requests.get(websiteurl,  verify=False)
    soup = BeautifulSoup(response.content, 'html.parser')

    regex_pattern = re.compile(r"[\s:=\>](bc(0([ac-hj-np-z02-9]{39}|[ac-hj-np-z02-9]{59})|1[ac-hj-np-z02-9]{8,87})|[13][a-km-zA-HJ-NP-Z1-9]{25,35})")

    matches = soup.find_all(string=regex_pattern)

    for tag in soup.find_all(string=regex_pattern):
        matches = re.findall(regex_pattern, tag)
        for match in matches:
            print(match[0])

if __name__ == "__main__":
    with open("./crawling.csv" , "r") as file:
        for i in file:
          getWebsiteWallet(i.strip()) 