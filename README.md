# xss-spider
Spider for forms and test XSS based on wordlists (script is prepped for SQL injection as well, but not yet fully implemented).

This script incorporates:

- Conversion of a standard XSS wordlist, to be able to evaluate success in a Chromedriver browser
- Spidering a URL
- Automatic discovery of possible inputs, including forms
- Same for basic SQL injections, but I never truly worked this out - it's a starting point
- Output needs overhaul, scrapy's loglevel doesn't provide enough granularity to do what we would need
- script may fail for other reasons as well - this was a quick side project, but hopefully will help you

I adapted it only to one VulnHub machine yet: https://www.vulnhub.com/entry/pentester-lab-xss-and-mysql-file,66/
I also compiled a custom XSS wordlist with 400 entries.
