import json
import pandas as pd
from utils import  validate_ip
from collections.abc import Iterable
import subprocess
import platform
import os

def to_team_cymru_ip_file(ips: Iterable[str], out_file: str):
  with open(out_file, 'w') as f:
    f.write('begin\n')
    #f.write('verbose\n')
    f.writelines(ip + '\n' for ip in ips)
    f.write('end')

def process_zdns(zdns_output_file: str, domain_to_ip_file: str, cymru_ip_file: str, logging: bool = False):
  with open(zdns_output_file, 'r') as f:
    zdns_output = f.read()

  domain_to_ip = []
  ips = set()
  for line in zdns_output.splitlines():
    json_data = json.loads(line)
    if 'answers' in json_data['data'].keys():
      fqdn = json_data['name']
      for answer in json_data['data']['answers']:
        if answer["type"] == "CNAME":
          a = "TODO"
        elif answer["type"] == "A":
          ip_addr = answer['answer']
          if validate_ip(ip_addr):
            domain_to_ip.append([fqdn, ip_addr])
            ips.add(ip_addr)
          elif logging:
            print("Invalid Ip: {}".format(ip_addr))
  to_team_cymru_ip_file(ips, cymru_ip_file)
  domain_to_ip_df = pd.DataFrame(domain_to_ip, columns=['Domain', 'IP'])
  domain_to_ip_df.to_pickle(domain_to_ip_file)
  print("Unique Domains: {}".format(domain_to_ip_df['Domain'].nunique()))
  print("Unique Ips: {}".format(domain_to_ip_df['IP'].nunique()))

def get_team_cymru_data(ip_file: str, cyrmu_data_out_txt_file: str, cyrmu_data_out_pkl_file: str):
  if platform.system() == 'Windows':
    ip_file = os.path.abspath(ip_file)
    run_str = ['type', ip_file + '|', 'wsl', 'netcat', 'whois.cymru.com', '43', '|', 'sort', '/unique', '>', cyrmu_data_out_txt_file]
  else:
    run_str = ["netcat", "whois.cymru.com", "43", "<", ip_file, "|", "sort", "-n", ">", cyrmu_data_out_txt_file]
  subprocess.check_output(run_str, shell=True)
  column_names = ['AS Number', 'IP', 'AS Name']
  df = pd.read_csv(cyrmu_data_out_txt_file, sep='|', header=None, names=column_names)
  df.to_pickle(cyrmu_data_out_pkl_file)

if __name__ == "__main__":
  zdns_output_file = ""
  domain_to_ip_file = "tmp.pkl"
  cymru_ip_file = "ip_file.txt"
  cymru_output = "cymru_output.txt"
  cymru_df = "cymru_output.pkl"
  process_zdns(zdns_output_file, domain_to_ip_file, cymru_ip_file, True)
  get_team_cymru_data(cymru_ip_file, cymru_output, cymru_df)