# XSS spider
Spider for HTML forms and inputs, testing XSS based on a wordlists (script is prepped for SQL injection as well, but not yet fully implemented).

This also serves as example / tutorial project for using scrapy - which is a dynamic framework to quickly create such tools on-the-fly. 

This script incorporates:

- Conversion of a standard XSS wordlist, to be able to evaluate success in a Chromedriver browser
- Spidering a URL
- Automatic discovery of possible inputs, including forms
- Same for basic SQL injections, but I never truly worked this out - it's a starting point
- Output needs overhaul, scrapy's loglevel doesn't provide enough granularity to do what we would need
- script may fail for other reasons as well - this was a quick side project, but hopefully will help you

I adapted it only to one VulnHub machine yet: https://www.vulnhub.com/entry/pentester-lab-xss-and-mysql-file,66/
I also compiled a custom XSS wordlist with 400 entries.

## scrapy
https://scrapy.org/

Scrapy is a Python-based web scraping framework that enables efficient extraction of data from websites.

With scrapy it's important to use the framework cli tools, otherwise you'll be busy creating lots of boilerplate - which misses the point of the framework. It's meant to be used in the field, quickly build your own spider and adapt it to your needs.

```bash
$ pip3 install scrapy
$ scrapy startproject myproject
$ scrapy genspider myspider 192.168.2.57
$ scrapy crawl myspider
$ scrapy crawl myspider -o output.json
$ scrapy shell url
$ scrapy list
```
