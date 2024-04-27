import urllib.request
from collections.abc import Iterable
import nilsimsa
from tldextract import extract

def get_webpage_info(ip_list: Iterable[str]):
  for ip in ip_list:
    resp = urllib.request.urlopen("http://{}".format(ip))
    tmp = extract(resp.url)
    mybytes = resp.read()
    mystr = mybytes.decode("utf8")
    print(resp)

get_webpage_info(["gooogle.com"])