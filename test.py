import requests
from bs4 import BeautifulSoup

# URL of the page to scrape
url = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a"  # Replace with the actual URL

# Send a GET request to fetch the HTML content of the page
response = requests.get(url)
response.raise_for_status()  # Raise an error for bad responses

# Parse the HTML content using BeautifulSoup
soup = BeautifulSoup(response.text, 'html.parser')

# Find all <a> tags that contain the keyword 'xml' in their href
xml_links = soup.find_all('a', href=True)

# Filter links that contain 'xml'
xml_urls = []
for link in xml_links:
    href = link['href']
    if 'xml' in href:  # Check if 'xml' is in the href
        full_url = href if href.startswith('http') else f"https://www.cisa.gov{href}"  # Form the complete URL
        xml_urls.append(full_url)

# Print the extracted XML URLs
for xml_url in xml_urls:
    print(xml_url)



import requests
from bs4 import BeautifulSoup

# Function to scrape XML and extract URLs
def extract_urls_from_xml(xml_url):
    # Fetch the XML content from the provided URL
    response = requests.get(xml_url)
    response.raise_for_status()

    # Parse the XML content using BeautifulSoup
    soup = BeautifulSoup(response.content, 'xml')

    # Find all elements where 'xsi:type' is 'URIObj:URIObjectType'
    urls = []
    for uri_object in soup.find_all(attrs={"xsi:type": "URIObj:URIObjectType"}):
        # Find the <URIObj:Value> tag inside the <cybox:Properties> element
        uri_value = uri_object.find('URIObj:Value')
        if uri_value and uri_value.text.strip():  # Ensure there's a valid URL
            urls.append(uri_value.text.strip())

    return urls

# Example usage
xml_url = xml_urls[0]  # Replace with the actual XML URL
urls = extract_urls_from_xml(xml_url)

# Print extracted URLs
for url in urls:
    print(url)
