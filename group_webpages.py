import ipaddress
from nilsimsa import Nilsimsa, compare_digests
import numpy as np
import pandas as pd
from urllib.request import urlopen
from utils import extract_domain

from utils import validate_ip


IP_File = "output/tranco_top1k_dist1/cymru_ips.txt"

ips = []
with open(IP_File, 'r') as ip_file:
  ips = ip_file.read().splitlines() 

distances = np.zeros((len(ips), len(ips)))
ip_hashes = []
ip_urls = []
for i, ip in enumerate(ips):
  if validate_ip(ip) and not ipaddress.ip_address(ip).is_private:
    try:
      response = urlopen('http://' + ip)
    except Exception as e:
      print(e)
      continue
    nilsima_obj = Nilsimsa(response.read()) #Might want to read object in
    ip_hashes.append(nilsima_obj.hexdigest())
    ip_urls.append(response.url)
    for j in range(i):
      distance = compare_digests(ip_hashes[j], ip_hashes[i])
      distances[i,j] = distance
      distances[j,i] = distance

print(distances)
print(ip_urls)
def wei_shiang():
  import sys
  import json
  import subprocess
  from datetime import datetime
  # Read ED1 TD
  with open(sys.argv[1], "r") as openfile:
    ED1_TD_list = json.load(openfile)
  for cc in ED1_TD_list:
    subprocess.run(["mkdir", cc])
    print(cc)
    now = datetime.now()
    cur_time = now.strftime("%H:%M:%S")
    print(cur_time)
    for TD in ED1_TD_list[cc]:
      print(TD)
      try:
        subprocess.run(["google-chrome", "--headless=new", "--screenshot", "--window-size=1280,800", "--virtual-time-budget=5000", "http://"+TD], timeout = 7, stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)
        if subprocess.check_output(["stat", "-c", "%s", "screenshot.png"]) != b'5900\n':
          subprocess.run(["mv", "screenshot.png", cc+"/"+TD+".png"])
      except subprocess.TimeoutExpired:
        pass