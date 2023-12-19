from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor

# from urllib.parse import urljoin, urlparse
import csv
import os


class BitcoinCrawler(CrawlSpider):
    name = "bitcoin_crawler"
    allowed_domains = ["bitcoin.org"]
    start_urls = ["https://bitcoin.org/en/"]

    rules = (Rule(LinkExtractor(), callback="parse_item", follow=True),)

    def parse_item(self, response):
        # Extract links using XPath
        links = response.xpath("//a/@href").extract()

        current_dir = os.path.abspath(os.path.dirname(__file__))
        output_file = os.path.join(current_dir, "crawling.csv")

        # Save links to a CSV file (append mode)
        with open(output_file, "a", newline="", encoding="utf-8") as csvfile:
            csv_writer = csv.writer(csvfile)
            for link in links:
                # absolute_url = urljoin(response.url, link)
                # if self.is_valid_url(absolute_url):
                if link.startswith("http"):
                    csv_writer.writerow([link])
        self.log(f"Appended {len(links)} links to {output_file}.")


"""
        def is_valid_url(self, url):
            parsed_url = urlparse(url)
            return parsed_url.scheme and parsed_url.netloc"""
