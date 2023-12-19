import requests
import re
import urllib3
import csv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from bs4 import BeautifulSoup
from requests.exceptions import Timeout


def getWebsiteWallet(websiteurl):
    # response = requests.get(websiteurl, verify=False)
    try:
        response = requests.get(
            websiteurl, verify=False, timeout=10
        )  # Adjust the timeout value as needed
        response.raise_for_status()  # Raise an HTTPError for bad responses
    except Timeout:
        print(f"Timeout: Connection to {websiteurl} timed out.")
        return
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return

    soup = BeautifulSoup(response.content, "html.parser")

    regex_pattern = re.compile(
        r"[\s:=\>](bc(0([ac-hj-np-z02-9]{39}|[ac-hj-np-z02-9]{59})|1[ac-hj-np-z02-9]{8,87})|[13][a-km-zA-HJ-NP-Z1-9]{25,35})"
    )

    matches = soup.find_all(string=regex_pattern)
    with open("output.csv", "a", newline="", encoding="utf-8") as csvfile:
        csv_writer = csv.writer(csvfile)
        for tag in soup.find_all(string=regex_pattern):
            matches = re.findall(regex_pattern, tag)
            for match in matches:
                csv_writer.writerow([websiteurl, match[0]])


if __name__ == "__main__":
    with open("output.csv", "w", newline="", encoding="utf-8") as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(["Website", "Wallet ID"])
    with open("./crawling.csv", "r") as file:
        for i in file:
            getWebsiteWallet(i.strip())
