"""Feature Extraction"""
from re import search, findall
import string
import urllib.parse
import random
from numpy import std
import requests
from bs4 import BeautifulSoup
from tld import get_tld
class FeatureExtraction:
    """FeatureExtraction Class"""
    def __init__(self):
        self.response = ""
        self.soup = ""
        self.forms = ""
        self.script_tags = ""
        self.parsed_url = ""
        self.hostname = ""
        self.path = ""
    async def getFeaturesList(self, url):
        self.features = list()
        self.url = url
        try:
            user_agents = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36","Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Mobile Safari/537.36","Mozilla/5.0 (iPhone; CPU iPhone OS 15_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Mobile/15E148 Safari/604.1","Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36")
            random_user_agent = random.choice(user_agents)
            self.response = requests.get(self.url,
                                 headers={'User-Agent': random_user_agent} , timeout=2)
            # tt=self.response.status_code
            # print("elf.response.status_code::::::::::",tt)
            if self.response.status_code==200:
                self.soup = BeautifulSoup(self.response.text, 'html.parser')
                self.forms = self.soup.find_all('form')
                self.script_tags = self.soup.find_all("script")
                self.parsed_url = urllib.parse.urlparse(self.url)
                self.hostname = self.parsed_url.hostname
                self.path = self.parsed_url.path  
                self.features.append(await self.calculate_underscore_count())
                self.features.append(await self.calculate_path_length())
                self.features.append(await self.calculate_dot_count_host())
                self.features.append(await self.calculate_ampersand_count())
                self.features.append(await self.count_questionmark())
                self.features.append(await self.calculate_special_char_count())
                self.features.append(await self.count_punctuation())
                self.features.append(await self.check_tld_in_path())
                self.features.append(await self.count_digits_in_host())
                self.features.append(await self.check_legitimate_url())
                self.features.append(await self.calculate_dot_count())
                self.features.append(await self.count_words_in_host())
                self.features.append(await self.has_hyphen_in_path())
                self.features.append(await self.calculate_equals_count())
                self.features.append(await self.calculate_redirected())
                self.features.append(await self.url_without_www())
                self.features.append(await self.has_hyphen_in_host())
                self.features.append(await self.check_spam_url())
                self.features.append(await self.count_subdomains())
                self.features.append(await self.dots_in_path())
                self.features.append(await self.https_protocol())
                self.features.append(await self.count_repeated_characters())
                self.features.append(await self.having_ip_address())
                self.features.append(await self.calculate_ampersand_count())
                self.features.append(await self.calculate_ampersand_count())
                self.features.append(await self.port_number_present())
                self.features.append(await self.domain_name_length())
                self.features.append(await self.url_length())
                self.features.append(await self.avg_word_length())
                self.features.append(await self.shortest_word())
                self.features.append(await self.longest_word_in_host_name())
                self.features.append(await self.digit_count())
                self.features.append(await self.letter_count())
                self.features.append(await self.vowel_consonant_ratio())
                self.features.append(await self.digit_letter_ratio())
                self.features.append(await self.word_length_diff())
                self.features.append(await self.word_length_std())
                self.features.append(await self.tilde_symbol())
                self.features.append(await self.num_numeric_chars())
                self.features.append(await self.calculate_at_count())
                self.features.append(await self.calculate_hyphen_count())
                self.features.append(await self.protocol_count())
                self.features.append(await self.count_subdirectories())
                self.features.append(await self.percent_20_in_path())
                self.features.append(await self.has_single_char_dirs())
                self.features.append(await self.count_zeros())
                self.features.append(await self.calculate_ratio())
                self.features.append(await self.count_or())
                self.features.append(await self.count_star())
                self.features.append(await self.count_colon())
                self.features.append(await self.count_dollar())
                self.features.append(await self.count_semicolon())
                self.features.append(await self.shortening_service())
                self.features.append(await self.existenceOfSensitiveWords())
                self.features.append(await self.fd_length())
                self.features.append(await self.get_tld_length())
                self.features.append(await self.punycode())
                self.features.append(await self.pct_ext_resource_urls())
                self.features.append(await self.insecure_forms())
                self.features.append(await self.relative_form_action())
                self.features.append(await self.ExtFormAction())
                self.features.append(await self.AbnormalFormAction())
                self.features.append(await self.frequent_domain_name_mismatch())
                self.features.append(await self.pop_up_window())
                self.features.append(await self.submit_info_to_email())
                self.features.append(await self.iframe_or_frame())
                self.features.append(await self.missing_title())
                self.features.append(await self.src_eval_cnt())
                self.features.append(await self.src_escape_cnt())
                self.features.append(await self.src_exec_cnt())
                self.features.append(await self.src_search_cnt())
                self.features.append(await self.images_only_in_form())
                self.features.append(await self.PctNullSelfRedirectHyperlinks())
                self.features.append(await self.links_pointing_to_page())
                self.features.append(await self.request_url())
                self.features.append(await self.linksmeta())
                return self.features
            else:
                return self.features
        except:
            return self.features
     #1
    async def calculate_underscore_count(self):
        """
        Calculate the number of underscores in the URL.

        Returns:
            int: The count of underscores in the URL.
        """
        underscore_count = self.url.count('_')
        return underscore_count
    #2
    async def calculate_path_length(self):
        """
        Calculate the length of the path in the URL.

        Returns:
            int: The length of the path in the URL.
        """
        path_length = len(self.path)
        return path_length
    #3
    async def calculate_dot_count_host(self):
        """
        Calculate the number of dots in the hostname of the URL.

        Returns:
            int: The count of dots in the hostname of the URL.
        """
        dot_count = str(self.hostname).count(".")
        return dot_count
    #4
    async def calculate_ampersand_count(self):
        """
        Calculate the number of ampersands in the URL.

        Returns:
            int: The count of ampersands in the URL.
        """
        ampersand_count = self.url.count("&")
        return ampersand_count
    #5
    async def count_questionmark(self):
        """
        Count the number of question marks in the URL.

        Returns:
            int: The count of question marks in the URL.
        """
        que_count = self.url.count("?")
        return que_count
    #6
    async def calculate_special_char_count(self):
        """
        Calculate the count of special characters in the URL.

        Returns:
            int: The count of special characters in the URL.
        """
        special_char_count = len(findall(r'[^A-Za-z0-9./]', self.url))
        return special_char_count
    #7
    async def count_punctuation(self):
        """
        Count the number of punctuation characters in the URL.

        Returns:
            int: The count of punctuation characters in the URL.
        """
        count = 0
        for char in self.url:
            if char in string.punctuation:
                count += 1
        return count
    #8
    async def check_tld_in_path(self):
        """
    Check if the top-level domain (TLD) appears in the URL path.

    Returns:
        int: Returns 1 if the TLD appears in the path, 0 otherwise.
    """
        tld_match = search(r"\.(\w+)/", self.url)
        if tld_match:
            tld = tld_match.group(1)
            path = self.url.split(tld)[0].split("/")[-1]
            return 1 if tld in path else 0
        else:
            return 0
    #9
    async def count_digits_in_host(self):
        """
        Count the number of digits in the hostname of the URL.

        Returns:
            int: The count of digits in the hostname of the URL.
        """
        return sum(c.isdigit() for c in str(self.hostname))
    #10
    async def check_legitimate_url(self):
        """
        Check if the URL is considered a legitimate URL.

        Returns:
            int: Returns 1 if the URL is considered legitimate, 0 otherwise.
        """
        domain = str(self.hostname).split("//")[-1]
        if "www." in domain or ".com" in domain:
            return 1
        else:
            return 0
    #11
    async def calculate_dot_count(self):
        """
        Calculate the count of dot characters in the URL.

        Returns:
            int: The count of dot characters in the URL.
        """
        dots_count = self.url.count(".")
        return dots_count
    #12
    async def count_words_in_host(self):
        """
        Count the number of words in the hostname of the URL.

        Returns:
            int: The count of words in the hostname of the URL.
        """
        return len(str(self.hostname).split("."))
    #13
    async def has_hyphen_in_path(self):
        """
        Check if the URL path contains a hyphen character.

        Returns:
            int: Returns 1 if the URL path contains a hyphen, 0 otherwise.
        """
        return 1 if "-" in self.path else 0
    #14
    async def calculate_equals_count(self):
        """
        Calculate the count of equals (=) characters in the URL.

        Returns:
            int: The count of equals (=) characters in the URL.
        """
        equal_count = self.url.count("=")
        return equal_count
    #15
    async def calculate_redirected(self):
        """
        Calculate the count of redirected (//) characters in the URL.

        Returns:
            int: The count of redirected (//) characters in the URL.
        """
        redirected_count = self.url.count("//")
        return redirected_count
    #16
    async def url_without_www(self):
        """
        Check if the URL does not start with "www.".

        Returns:
            int: Returns 1 if the URL does not start with "www.", 0 otherwise.
        """
        return 1 if not str(self.hostname).startswith("www.") else 0
    #17
    async def has_hyphen_in_host(self):
        """
        Check if the hostname of the URL contains a hyphen character.

        Returns:
            int: Returns 1 if the hostname contains a hyphen, 0 otherwise.
        """
        return 1 if "-" in str(self.hostname) else 0
    #18
    async def check_spam_url(self):
        """
        Check if the URL contains query parameters with values.

        Returns:
            int: Returns 1 if the URL contains query parameters with values, 0 otherwise.
        """
        if search(r"\?.*=.*", self.url):
            return 1
        else:
            return 0
    #19
    async def count_subdomains(self):
        """
        Count the number of subdomains in the URL.

        Returns:
            int: The count of subdomains in the URL.
        """
        domain = str(self.hostname).split("//")[-1]
        subdomains = str(domain).split(".")
        return len(subdomains) - 1
    #20
    async def dots_in_path(self):
        """
        Count the number of dot characters in the URL path.

        Returns:
            int: The count of dot characters in the URL path.
        """
        return self.path.count(".")
    #21
    async def https_protocol(self):
        """
        Check if the URL starts with "https".

        Returns:
            int: Returns 1 if the URL starts with "https", 0 otherwise.
        """
        if self.url.startswith("https"):
            return 1
        else:
            return 0
    #22
    async def count_repeated_characters(self):
        """
        Count the number of repeated characters in the URL.

        Returns:
            int: The count of repeated characters in the URL.
        """
        count = 0
        for i in range(len(self.url) - 1):
            if self.url[i] == self.url[i + 1]:
                count += 1
        return count
    #23
    async def having_ip_address(self):
        """
        Check if the URL contains an IP address.

        Returns:
            int: Returns 1 if the URL contains an IP address, 0 otherwise.
        """
        match = search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'  # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
            '[0-9a-fA-F]{7}', self.url)  # Ipv6
        if match:
            return 1
        else:
            return 0
    #24
    async def calculate_at_count(self):
        """
        Calculate the count of at (@) characters in the URL.

        Returns:
            int: The count of at (@) characters in the URL.
        """
        dots_count = self.url.count("@")
        return dots_count
    #25
    async def calculate_hyphen_count(self):
        """
        Calculate the count of hyphen (-) characters in the URL.

        Returns:
            int: The count of hyphen (-) characters in the URL.
        """
        dots_count = self.url.count("-")
        return dots_count
    #26
    async def port_number_present(self):
        """
        Check if a port number is present in the URL.

        Returns:
            int: Returns 1 if a port number is present, 0 if not present, -1 if an error occurred.
        """
        try:
            if str(self.parsed_url.port):
                return 1
            else:
                return 0
        except:
            return -1
    #27
    async def domain_name_length(self):
        """
        Calculate the length of the domain name in the URL.

        Returns:
            int: The length of the domain name.
        """
        return len(str(self.hostname))
    #28
    async def url_length(self):
        """
        Calculate the length of the URL.

        Returns:
            int: The length of the URL.
        """
        return len(self.url)
    #29
    async def avg_word_length(self):
        """
        Calculate the average word length in the URL.

        Returns:
            float: The average word length in the URL.
        """
        words = findall(r'\w+', self.url)
        if len(words) == 0:
            return 0
        else:
            avg_length = sum(len(word) for word in words) / len(words)
            return round(float(avg_length),5)
    #30
    async def shortest_word(self):
        """
        Find the length of the shortest word in the URL.

        Returns:
            int: The length of the shortest word in the URL.
        """
        words = findall(r'\b\w+\b', self.url)
        if len(words) == 0:
            return 0
        else:
            return min(len(word) for word in words)
    #31
    async def longest_word_in_host_name(self):
        """
        Find the length of the longest word in the host name of the URL.

        Returns:
            int: The length of the longest word in the host name.
        """
        host_name = str(self.hostname)
        if host_name is None:
            return 0
        return max(len(word) for word in host_name.split('.'))
    #32
    async def digit_count(self):
        """
        Count the number of digits in the URL.

        Returns:
            int: The count of digits in the URL.
        """
        return sum(1 for i in self.url if i.isnumeric())
    #33
    async def letter_count(self):
        """
        Count the number of letters in the URL.

        Returns:
            int: The count of letters in the URL.
        """
        return sum(1 for i in self.url if i.isalpha())
    #34
    async def vowel_consonant_ratio(self):
        """
        Calculate the ratio of vowels to consonants in the URL.

        Returns:
            float: The vowel-to-consonant ratio.
        """
        vowels = "aeiouAEIOU"
        vowels_count = sum(1 for char in self.url if char.isalpha() and char in vowels)
        consonants_count = sum(1 for char in self.url if char.isalpha() and char not in vowels)
        if consonants_count == 0:
            return 0
        return round(vowels_count / consonants_count, 5)
        #35
    async def digit_letter_ratio(self):
        """
        Calculate the ratio of digits to letters in the URL.

        Returns:
            float: The digit-to-letter ratio.
        """
        digits = sum(1 for char in self.url if char.isdigit())
        letters = sum(1 for char in self.url if char.isalpha())
        if letters == 0:
            return 0
        return round(digits / letters, 5)
    #36
    async def word_length_diff(self):
        """
        Calculate the difference between the lengths of the longest and shortest words in the URL.

        Returns:
            int: The difference in word lengths.
        """
        words = self.url.split(".")[0].split("/")[-1].split("-")
        word_lengths = [len(word) for word in words]
        return max(word_lengths) - min(word_lengths)
    #37
    async def word_length_std(self):
        """
        Calculate the standard deviation of word lengths in the host name of the URL.

        Returns:
            float: The standard deviation of word lengths.
        """
        words = str(self.hostname).split('.')
        word_lengths = [len(word) for word in words]
        return round(float(std(word_lengths)), 5)
    #38
    async def tilde_symbol(self):
        """
        Check if the tilde symbol (~) is present in the URL.

        Returns:
            int: Returns 1 if the tilde symbol is present, 0 otherwise.
        """
        if "~" in self.url:
            return 1
        else:
            return 0
    #39
    async def num_numeric_chars(self):
        """
        Count the number of numeric characters in the URL.

        Returns:
            int: The count of numeric characters.
        """
        return sum(c.isdigit() for c in self.url)
    #40
    async def calculate_per_count(self):
        """
        Count the number of percentage (%) symbols in the URL.

        Returns:
            int: The count of percentage symbols.
        """
        dots_count = self.url.count("%")
        return dots_count
    #41
    async def calculate_hash_count(self):
        """
        Count the number of hash (#) symbols in the URL.

        Returns:
            int: The count of hash symbols.
        """
        dots_count = self.url.count("#")
        return dots_count
    #42
    async def protocol_count(self):
        """
        Count the number of occurrences of 'http' and 'https' in the URL.

        Returns:
            int: The count of 'http' and 'https'.
        """
        http_count = self.url.count('http')
        https_count = self.url.count('https')
        http_count = http_count - https_count
        return (http_count + https_count)
    #43
    async def count_subdirectories(self):
        """
        Count the number of subdirectories in the URL path.

        Returns:
            int: The count of subdirectories.
        """
        path = self.parsed_url.path
        return len(path.split('/')) - 1
    #44
    async def percent_20_in_path(self):
        """
        Check if '%20' is present in the URL path.

        Returns:S
        int: Returns 1 if '%20' is present, 0 otherwise.
        """
        path = self.parsed_url.path
        return 1 if '%20' in path else 0
    #45
    async def has_single_char_dirs(self):
        """
        Check if the URL path contains single-character directories.

        Returns:
            int: Returns 1 if there are single-character directories, 0 otherwise.
        """
        dirs = self.path.split("/")
        single_char_dirs = [dir for dir in dirs if len(dir) == 1]
        return 1 if single_char_dirs else 0
    #46
    async def count_zeros(self):
        """
        Count the number of '0' characters in the URL.

        Returns:
            int: The count of '0' characters.
        """
        return self.url.count('0')
    #47
    async def calculate_ratio(self):
        """
        Calculate the ratio of uppercase to lowercase characters in the URL.

        Returns:
            float: The uppercase-to-lowercase ratio.
        """
        upper_count = sum(c.isupper() for c in self.url)
        lower_count = sum(c.islower() for c in self.url)
        if lower_count == 0:
            return 0
        else:
            return round(float(upper_count / lower_count),5)
    #48
    async def count_or(self):
        """
        Count the number of '|' symbols in the URL.

        Returns:
            int: The count of '|' symbols.
        """
        return self.url.count('|')
    #49
    async def count_star(self):
        """
        Count the number of '*' symbols in the URL.

        Returns:
            int: The count of '*' symbols.
        """
        return self.url.count('*')
    #50
    async def count_colon(self):
        """
        Count the number of ':' symbols in the URL.

        Returns:
            int: The count of ':' symbols.
        """
        return self.url.count(':')
    #51
    async def count_dollar(self):
        """
        Count the number of '$' symbols in the URL.

        Returns:
            int: The count of '$' symbols.
        """
        return self.url.count('$')
    #52
    async def count_semicolon(self):
        """
        Count the number of ';' symbols in the URL.

        Returns:
            int: The count of ';' symbols.
        """
        return self.url.count(';')
    #53
    async def shortening_service(self):
        """
        Check if the URL is generated by a URL shortening service.

        Returns:
            int: Returns -1 if the URL is generated by a shortening service, 1 otherwise.
        """
        match = search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                        r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                        r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                        r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                        r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                        r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                        r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                        r'tr\.im|link\.zip\.net',
                        self.url)
        if match:
            return -1
        else:
            return 1
    #54
    async def existenceOfSensitiveWords(self):
        """
        Check if the URL contains sensitive words related to phishing.

        Returns:
            int: Returns 1 if sensitive words are present, 0 otherwise.
        """
        phishingWords = ["secure","account","login","signin","confirm","submit", "webscr"]
        phishing = False
        for i in range(len(phishingWords)):
            if(phishingWords[i] in self.url):
                phishing = True
        if(phishing == True):
            return 1
        else:
            return 0
    #55
    async def fd_length(self):
        """
        Get the length of the first directory in the URL path.

        Returns:
            int: The length of the first directory.
        """
        try:
            return len(self.path.split('/')[1])
        except:
            return 0
    #56
    async def get_tld_length(self):
        """
        Get the length of the top-level domain (TLD) in the URL.

        Returns:
            int: The length of the TLD, or -1 if it cannot be determined.
        """
        try:
            tld = get_tld(self.url, fail_silently=True)
            return len(tld) if tld else -1
        except:
            return -1
    #57
    async def punycode(self):
        """
        Check if the URL contains Punycode encoding.

        Returns:
            int: Returns 1 if Punycode encoding is present, 0 otherwise.
        """
        if self.url.startswith("http://xn--") or self.url.startswith("http://xn--"):
            return 1
        else:
            return 0
    #58
    async def pct_ext_resource_urls(self):
        """
        Calculate the percentage of external resource URLs in the HTML page.

        Returns:
            float: The percentage of external resource URLs, or -1 if it cannot be determined.
        """
        try:
            ext_urls = [tag['src'] for tag in self.soup.find_all(src=True) if 'http' in tag['src']]
            total_urls = len(self.soup.find_all(src=True))
            pct_ext_urls = round((len(ext_urls) / total_urls) * 100, 5)
            return pct_ext_urls
        except:
            return -1
    #59
    async def insecure_forms(self):
        """
        Check if there are insecure (HTTP) form actions in the HTML page.

        Returns:
            int: Returns 1 if insecure form actions are present, 0 otherwise.
        """
        try:
            return 1 if any(form.get('action').startswith('http://') for form in self.forms) else 0
        except:
            return -1
    #60
    async def relative_form_action(self):
        """
        Check if there are relative (non-HTTP) form actions in the HTML page.

        Returns:
            int: Returns 1 if relative form actions are present, 0 otherwise.
        """
        try:
            return 1 if any(not form.get('action').startswith(('http://', 'https://')) for form in self.forms) else 0
        except:
            return -1
    #61
    async def ExtFormAction(self):
        """
        Check if there are external form actions in the HTML page.

        Returns:
            int: Returns 1 if external form actions are present, 0 otherwise.
        """
        try:
            ext_form = False
            for form in self.forms:
                action = form.get("action")
                if action:
                    parsed_action = requests.utils.urlparse(action)
                    action_hostname = parsed_action.hostname
                    if action_hostname != self.hostname:
                        ext_form = True
                        break
            if ext_form:
                return 1
            else:
                return 0
        except:
            return -1
    #62
    async def is_normal_form_action(form_action_url):
        """
        Check if a form action URL is a normal form action.

        Args:
            form_action_url (str): The form action URL.

        Returns:
            bool: True if the form action URL is a normal form action, False otherwise.
        """
        normal_form_action_url_starts = [
            "https://",
            "http://",
            "mailto:"
        ]
        for normal_form_action_url_start in normal_form_action_url_starts:
            if form_action_url.startswith(normal_form_action_url_start):
                return True
        return False
    async def AbnormalFormAction(self):
        """
        Check if there are abnormal form actions in the HTML page.

        Returns:
            int: Returns 1 if abnormal form actions are present, 0 otherwise.
        """
        try:
            num_abnormal_form_actions = 0
            for form in self.forms:
                form_action_url = form.get("action")
                if not self.is_normal_form_action(form_action_url):
                    num_abnormal_form_actions += 1
            if num_abnormal_form_actions > 0:
                return 0
            else:
                return 1
        except:
            return -1
    #63
    async def frequent_domain_name_mismatch(self):
        """
        Check if there is a frequent domain name mismatch in the HTML page.

        Returns:
            int: Returns 1 if a frequent domain name mismatch is present, 0 otherwise.
        """
        try:
            urls = [link.get('href') for link in self.soup.find_all('a')] + [self.url]
            hostnames = [requests.utils.urlparse(u).hostname for u in urls if u is not None]
            most_frequent_hostname = max(set(hostnames), key=hostnames.count)
            return 1 if most_frequent_hostname != requests.utils.urlparse(self.url).hostname else 0
        except:
            return -1
    #64
    async def pop_up_window(self):
        """
        Check if there are pop-up windows in the HTML page.

        Returns:
            int: Returns 1 if pop-up windows are present, 0 otherwise.
        """
        try:
            return 1 if any('window.open' in script.text for script in self.script_tags) else 0
        except:
            return -1
    #65
    async def submit_info_to_email(self):
        """
        Check if form actions submit information to an email address.

        Returns:
            int: Returns 1 if form actions submit information to an email address, 0 otherwise.
        """
        try:
            return 1 if any('mailto:' in form.get('action', '') for form in self.forms) else 0
        except:
            return -1
    #66
    async def iframe_or_frame(self):
        """
        Check if the HTML page contains iframes or frames.

        Returns:
            int: Returns 1 if iframes or frames are present, 0 otherwise.
        """
        try:
            iframes = self.soup.find_all('iframe')
            frames = self.soup.find_all('frame')
            if len(iframes) > 0 or len(frames) > 0:
                return 1
            return 0
        except:
            return -1
    #67
    async def missing_title(self):
        """
        Check if the HTML page has a title.

        Returns:
            int: Returns 1 if the title is missing, 0 otherwise.
        """
        try:
            title = self.soup.find('title')
            if title:
                return 0
            return 1
        except:
            return -1
    #68
    async def src_eval_cnt(self):
        """
        Count the number of occurrences of "eval(" in script tags.

        Returns:
            int: The count of "eval(" occurrences.
        """
        try:
            return sum(tag.text.count("eval(") for tag in self.script_tags)
        except:
            return -1
    #69
    async def src_escape_cnt(self):
        """
        Count the number of occurrences of " escape(" in script tags.

        Returns:
            int: The count of " escape(" occurrences.
        """
        try:
            return sum(tag.text.count(" escape(") for tag in self.script_tags)
        except:
            return -1
    #70
    async def src_exec_cnt(self):
        """
        Count the number of occurrences of "exec(" in the HTML content.

        Returns:
            int: The count of "exec(" occurrences.
        """
        try:
            html_content = self.response.text
            return html_content.count("exec(")
        except:
            return -1
    #71
    async def src_search_cnt(self):
        """
        Count the number of occurrences of "search(" in the HTML content.

        Returns:
            int: The count of "search(" occurrences.
        """
        try:
            html_content = self.response.text
            search_cnt = len(findall('search\(', html_content))
            return search_cnt
        except:
            return -1
    #72
    async def images_only_in_form(self):
        """
        Check if all children of forms are img tags.

        Returns:
            int: Returns 1 if all children of forms are img tags, 0 otherwise.
        """
        try:
            return 1 if any(all(child.name == 'img' for child in form.children) for form in self.forms) else 0
        except:
            return -1
    #73
    async def PctNullSelfRedirectHyperlinks(self):
        """
        Calculate the percentage of hyperlinks with null or self-redirecting href.

        Returns:
            float: The percentage of null or self-redirecting hyperlinks.
        """
        try:
            all_links = self.soup.find_all('a')
            null_links = 0
            for link in all_links:
                if link.get('href') == '' or link.get('href')=="#" or link.get('href') is None:
                    null_links += 1
            pct_null_links = null_links / len(all_links) * 100
            return round(float(pct_null_links),5)
        except:
            return -1
    #74
    async def links_pointing_to_page(self):
        """
        Count the number of links pointing to the page.

        Returns:
            int: The count of links pointing to the page.
        """
        try:
            links = [link.get("href") for link in self.soup.find_all("a")]
            return len(links)
        except:
            return -1
    #75
    async def request_url(self):
        """
        Check if any embedded resources (img, video, audio) are requested from a different domain.

        Returns:
            int: Returns 1 if embedded resources are requested from a different domain, 0 otherwise.
        """
        try:
            for obj in self.soup.find_all(['img', 'video', 'audio']):
                src = obj.get('src') or obj.get('data-src')
                domain = requests.utils.urlparse(src).netloc
                url_domain = requests.utils.urlparse(self.response.url).netloc
                if domain != url_domain:
                    return 1
            return 0
        except:
            return -1
    #76
    async def linksmeta(self):
        """
        Calculate the percentage of links in meta, script, and link tags that belong to the same domain.

        Returns:
            float: The percentage of links belonging to the same domain.
        """
        try:
            if self.response.status_code == 200:
                meta_links = [meta.get('content') for meta in self.soup.find_all('meta') if meta.get('content')]
                script_links = [script.get('src') for script in self.soup.find_all('script') if script.get('src')]
                link_links = [link.get('href') for link in self.soup.find_all('link') if link.get('href')]
                all_links = meta_links + script_links + link_links
                same_domain_links_count = 0
                for link in all_links:
                    if link.startswith(self.url) or link.startswith(self.url.split('//')[-1].split('/')[0]):
                        same_domain_links_count += 1
                same_domain_links_percentage = same_domain_links_count / len(all_links) * 100
                return round(float(same_domain_links_percentage),5)
            else:
                return -1
        except:
            return -1
