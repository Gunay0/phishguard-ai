"""Offline URL analysis. Never visits URLs or makes network requests."""



import ipaddress

import re

from dataclasses import dataclass

from urllib.parse import urlsplit





@dataclass(frozen=True)

class URLFinding:

    url: str

    rule_id: str

    explanation: str

    weight: int





URL_PATTERN = re.compile(

    r"https?://[^\s<>\"']+",

    re.IGNORECASE,

)





def extract_urls(text: str) -> list[str]:

    """Extract HTTP/HTTPS URLs from a message."""

    urls = []



    for match in URL_PATTERN.finditer(text):

        url = match.group(0).rstrip(".,;!?)]}")



        if url and url not in urls:

            urls.append(url)



    return urls





def analyze_url(url: str) -> list[URLFinding]:

    """Analyze a URL without opening it."""

    findings = []



    try:
        parsed = urlsplit(url)
    except ValueError:
        return findings

    hostname = parsed.hostname

    if not hostname:
        return findings

    hostname = hostname.lower()
    try:

        ipaddress.ip_address(hostname)

    except ValueError:

        pass

    else:

        findings.append(URLFinding(

            url=url,

            rule_id="ip_address_host",

            explanation="URL uses an IP address instead of a domain name.",

            weight=5

        ))
    if parsed.username is not None:
        findings.append(URLFinding(

            url=url,

            rule_id="embedded_credentials",

            explanation="URL contains embedded login credentials, which may be suspicious.",

            weight=8

        ))


    if len(url) > 120:

        findings.append(URLFinding(

            url=url,

            rule_id="long_url",

            explanation="URL is unusually long, which may indicate phishing.",

            weight=4

        ))
    if parsed.scheme.lower() == "http":

        findings.append(URLFinding(

            url=url,

            rule_id="insecure_http",

            explanation="URL uses HTTP instead of encrypted HTTPS.",

            weight=3

        ))
    if hostname.count(".") >= 4:

        findings.append(URLFinding(

            url=url,

            rule_id="many_subdomains",

            explanation="URL contains many domain levels, which may be suspicious.",

            weight=4

        ))
    return findings


