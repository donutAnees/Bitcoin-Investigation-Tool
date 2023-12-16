from scrapy.spiders import CrawlSpider, Rule
from scrapy.linkextractors import LinkExtractor
import csv
import os


class BitcoinCrawler(CrawlSpider):
    name = "bitcoin_crawler"
    allowed_domains = ["bitcoin.com"]
    start_urls = ["https://www.bitcoin.com/"]

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
                csv_writer.writerow([link])

        self.log(f"Appended {len(links)} links to {output_file}.")
