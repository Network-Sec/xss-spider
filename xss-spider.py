import scrapy
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import urllib
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs
import json
import re
from jsbeautifier import beautify
from sys import stdout
from string import printable, ascii_lowercase, ascii_uppercase, digits
from random import randint
import selenium
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

DEBUG = False

xss_payloads = []
with open('XSS_payloads_short.txt', 'r') as f:
    for line in f:
        if "http" in line or "ftp" in line or "ssh" in line:
            continue

        line = re.sub(r'alert\([^\)]*\)', 'document.xss=1;', line)
        line = line.strip().replace('alert()', 'document.xss=1;').replace('alert(1)', 'document.xss=1;').replace('alert(document.cookie)', 'document.xss=1;').replace('prompt()', 'document.xss=1;').replace('prompt(document.cookie)', 'document.xss=1;').replace('confirm()', 'document.xss=1;').replace('confirm(document.cookie)', 'document.xss=1;').replace('console.log()', 'document.xss=1;').replace('console.log(document.cookie)', 'document.xss=1;')
        # throw away all remaining alert and prompt, they cause too much trouble
        if "alert" in line or "prompt" in line or "confirm" in line or "console.log" in line:
            continue
        xss_payloads.append(line)

if DEBUG:
    print("Finished compiling XSS payloads")

chrome_options = Options()
if not DEBUG:
    chrome_options.add_argument("--headless")

driver = webdriver.Chrome(options=chrome_options)

if DEBUG:
    print("Finished initializing Chrome driver")

def convert_bs(forms):
    __forms = {}
    c = 0
    for f in forms:
        __forms[c] = str(f)

    return __forms

def random_value():
    charset = ascii_lowercase + ascii_uppercase + digits
    return ''.join([charset[randint(0, len(charset) - 1)] for _ in range(randint(8, 16))])

def compare_responses(normal_response, injected_response):
    status_code_change = normal_response.status_code != injected_response.status_code
    doc_length_diff = abs(len(normal_response.text) - len(injected_response.text))
    significant_length_change = doc_length_diff > 50  # Adjust the threshold as needed

    return status_code_change or significant_length_change

def test_sql_injection(url, param_name, param_value, method, normal_response=None):
    sqli_payloads = [
        "'", '"', ";", " OR 1=1", " OR 1=1#", " OR 1=1--", "' OR '1'='1", '" OR "1"="1', " OR 1=1;",
        " OR '1'='1'", " OR '1'='1'--", " OR '1'='1'#", " OR '1'='1';", " OR '1'='1'; --",
        "' OR 'a'='a", '" OR "a"="a', " OR 'a'='a'", " OR 'a'='a'--", " OR 'a'='a'#", " OR 'a'='a';",
        " OR 'a'='a'; --", " AND 1=1", " AND '1'='1", " AND 1=1--", " AND '1'='1'", " AND '1'='1'--",
        " AND '1'='1'#", " AND '1'='1';", " AND '1'='1'; --", " AND 'a'='a", " AND 1=0", " AND '1'='2",
        " AND 1=1 AND '1'='1", " AND 1=1 AND '1'='1'"
    ]

    if not normal_response:
        if method == "GET":
            normal_response = requests.get(url, params={param_name: param_value}, allow_redirects=True)
        else:  # POST
            normal_response = requests.post(url, data={param_name: param_value}, allow_redirects=True)

    findings = {}
    vulnerable_payload = None
    response_details = None

    for payload in sqli_payloads:
        injected_value = param_value + payload
        data = {param_name: injected_value}
        findings[param_name] = {}

        if method == "GET":
            response = requests.get(url, params=data, allow_redirects=True)
        else:  # POST
            response = requests.post(url, data=data, allow_redirects=True)

            if response.status_code == 200 and compare_responses(normal_response, response):
                vulnerable_payload = payload
                
                # Parse the HTML text with Beautiful Soup
                soup = BeautifulSoup(response.text, 'html.parser')

                # Extract important information
                forms = soup.find_all('form')
                inputs = soup.find_all('input')
                links = soup.find_all('a')

                response_details = {
                    'headers': dict(response.headers),
                    'Parameter': param_name,
                    'URL': url,
                    'Payload': payload,
                    'status_code': response.status_code,
                    'forms': convert_bs(forms),
                    'inputs': convert_bs(inputs),
                    'links': convert_bs(links)
                }

                findings[param_name]["response_details"] = response_details
                findings[param_name]["url"] = url
                findings[param_name]["param_value"] = param_value
                findings[param_name]["payload"] = payload
                findings[param_name]["method"] = method
                findings[param_name]["payload"] = payload
  
    return findings

def url_XSS_injection(url, param_name, param_value, method):
    findings = {}
    vulnerable_payload = None
    response_details = None

    counter = 0
    total = 0
    for payload in xss_payloads:
        counter += 1
        total += 1
        if DEBUG and counter % 100 == 0:
            print("Testing payload: " + str(total) + " of " + str(len(xss_payloads)), "| payload: " + payload)
            counter = 0
        param_value = param_value or random_value()   
        injected_value = param_value + payload
        data = {param_name: injected_value}
        findings[param_name] = {}

        # Split the URL into components
        url_components = urlparse(url)

        # Remove existing query parameters and construct a new URL with injected parameters
        new_url_components = url_components._replace(query="")
        clean_url = urlunparse(new_url_components)
        injected_url = f"{clean_url}?{param_name}={injected_value}"
        if DEBUG:
            print("URL:", injected_url)

        if method.lower() == "get":
            driver.get(injected_url)
            response = requests.get(injected_url)
        else:  # POST - we can't do post requests directly with chromedriver, so we send it with requests and try to catch the response with chrome
            response = requests.post(injected_url)
            driver.get(response.url) 

        # Check if the payload was executed and set document.xss to 1
        try:
            is_vulnerable = driver.execute_script("return document.xss == 1;")
        except selenium.common.exceptions.UnexpectedAlertPresentException:
            is_vulnerable = True
        except:
            is_vulnerable = False

        if is_vulnerable:
            vulnerable_payload = payload

            # Store response_details
            soup = BeautifulSoup(driver.page_source, 'html.parser')
            forms = soup.find_all('form')
            inputs = soup.find_all('input')
            links = soup.find_all('a')

            response_details = {
                'headers': dict(response.headers),
                'Parameter': param_name,
                'URL': url,
                'Payload': payload,
                'status_code': response.status_code,
                'forms': convert_bs(forms),
                'inputs': convert_bs(inputs),
                'links': convert_bs(links)
            }

            findings[param_name]["response_details"] = response_details
            findings[param_name]["url"] = url
            findings[param_name]["param_value"] = param_value
            findings[param_name]["payload"] = payload
            findings[param_name]["method"] = method
            findings[param_name]["payload"] = payload


    return findings

def form_XSS_injection(url, form_inputs, method, normal_response=None):
    if DEBUG:
        print("Testing form XSS: " + url)

    findings = {}
    vulnerable_payload = None
    response_details = None

    current_finding = 0

    for payload in xss_payloads:
        injected_data = form_inputs.copy()
        for param_name, param_value in form_inputs.items():
            if param_name.lower() == 'submit':
                param_value = "1"

            param_value = param_value or random_value()      
            injected_data[param_name] = param_value + payload

        if not 'submit' in injected_data.keys():
            injected_data['submit'] = '1'

        findings[current_finding] = {}
        proxies = {}

        if DEBUG:
            print("Testing for XSS in " + url, "| method: " + method)
            print("Form inputs: " +  (beautify(json.dumps(injected_data)) if type(injected_data) is dict else injected_data))
            proxies = {"http":"http://localhost:8080"}

        if method.lower() == "get":
            driver.get(url + "?" + urllib.parse.urlencode(injected_data))
        else:  # POST
            response = requests.post(url, data=injected_data, proxies=proxies, allow_redirects=True)
            if DEBUG:
                print("Request Body: ", response.request.body)
            driver.get(response.url)

        # Check if the payload was executed and set document.xss to 1
        try:
            is_vulnerable = driver.execute_script("return document.xss == 1;")
        except selenium.common.exceptions.UnexpectedAlertPresentException:
            is_vulnerable = True
        except:
            is_vulnerable = False

        if is_vulnerable:
            if DEBUG:
                print("XSS Vulnerability found")

            vulnerable_payload = payload

            # Suppress the alert - doesn't always work. When chrome is stuck with a popup script might fail.
            # As it's a real browser, you can also just have eyes on the target to catch this situation
            driver.execute_script("window.originalAlert = window.alert; window.alert = function() {};")

            # Store response_details
            soup = BeautifulSoup(driver.page_source, 'html.parser')
            forms = soup.find_all('form')
            inputs = soup.find_all('input')
            links = soup.find_all('a')

            response_details = {
                'headers': dict(response.headers),
                'Parameter': param_name,
                'URL': url,
                'Payload': payload,
                'status_code': response.status_code,
                'forms': convert_bs(forms),
                'inputs': convert_bs(inputs),
                'links': convert_bs(links)
            }

            findings[current_finding]["response_details"] = response_details
            findings[current_finding]["url"] = url
            findings[current_finding]["payload"] = payload
            findings[current_finding]["method"] = method
            findings[current_finding]["payload"] = payload

            # Restore the original alert function
            driver.execute_script("window.alert = window.originalAlert;")

    return findings

def extract_form_data(form):
    action = form.css("::attr(action)").get()
    method = form.css("::attr(method)").get().lower() or "get"
    inputs = []

    for input_field in form.css("input"):
        input_name = input_field.css("::attr(name)").get()
        input_type = input_field.css("::attr(type)").get()
        input_value = input_field.css("::attr(value)").get()

        if input_name:
            inputs.append((input_name, input_type, input_value))
    
    for textarea_field in form.css("textarea"):
        textarea_name = textarea_field.css("::attr(name)").get()
        textarea_value = textarea_field.css("::text").get()

        if textarea_name:
            inputs.append((textarea_name, "textarea", textarea_value))



    return action, method, inputs

class MyspiderSpider(scrapy.Spider):
    name = 'myspider'
    allowed_domains = ['192.168.2.57']
    start_urls = ['http://192.168.2.57/']
    custom_settings = {
        'LOG_LEVEL': 'ERROR'
    }

    def parse(self, response):
        # Find all links
        links = response.css("a::attr(href)").getall()
        if DEBUG:
            print("Links:", links)

        # Follow the links to crawl the website recursively
        for link in links:
            next_page = response.urljoin(link)
            if DEBUG:
                print("Next Page:", next_page)
            yield scrapy.Request(next_page, callback=self.parse)


        # Find all forms
        forms = response.css("form") or response.xpath("//form")
        if DEBUG:
            print("Forms:", forms)

        for form in forms:
            action, method, inputs = extract_form_data(form)
            form_url = response.urljoin(action)

            # Process the form data, send requests, and test for vulnerabilities
            form_inputs = {input_name: input_value for input_name, input_type, input_value in inputs}
            findings = form_XSS_injection(form_url, form_inputs, method)
            if findings:
                self.logger.error(beautify(json.dumps(findings)).replace('\\"', '"')) 

            if not DEBUG:
                for input_name, input_type, input_value in inputs:
                    if input_type == 'text' or input_type is None:
                        # Test for SQL injection
                        findings = test_sql_injection(form_url, input_name, input_value or '', method)
                        if findings:
                            self.logger.error(beautify(json.dumps(findings)).replace('\\"', '"'))



        # For URL parameters:
        for url in response.css('a::attr(href)').getall():
            full_url = response.urljoin(url)

            # Assuming the URLs have query parameters
            url_parameters = urlparse(full_url).query
            query_params = parse_qs(url_parameters)

            for param_name, param_values in query_params.items():
                for param_value in param_values:
                    if not DEBUG:
                        # Test for SQL injection
                        findings = test_sql_injection(full_url, param_name, param_value, 'GET')
                        if findings:
                            self.logger.error(beautify(json.dumps(findings)).replace('\\"', '"'))

                        # Test for XSS
                        findings = url_XSS_injection(full_url, param_name, param_value, 'GET')
                        if findings:
                            self.logger.error(beautify(json.dumps(findings)).replace('\\"', '"'))
