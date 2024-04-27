import pandas as pd
from multiprocessing import Pool
import os
from urllib.request import urlopen
import time
import json
import requests
import re
import matplotlib.pyplot as plt


from utils import validate_ip
from virus_total.VT_Domain_Scanner_py3 import DomainReportReader, ipReportReader

UNSURE_OWNERS = [
  "AMAZON-02, US"
  "AMAZON-AES, US"
]

ANALYSIS_TYPES = [
  'defensive', #Gos directly to original domains ip
  'same_AS_as_owner', #Higher Probability that it is owned by Original Domain Owner
  'defensive_redirect', #Gets redirected to original domain
  'malicous_redirect' #Get redirected to a malicous domain
  'malicous_ip', #Has at least one positive on VT for IP or Redirect
  'ad_parking',
  'non_malicous', #Has no positives for an IP on VT
  'unkown' #Has not been processed
]

OUT_COLS = ['domain', 'orig_domain', 'ips', 'type']

def autopct_format(values):
  def my_format(pct):
    total = sum(values)
    val = int(round(pct*total/100.0))
    return "{:.1f}%".format(pct)
    #return '{:.1f}%\n({v:d})'.format(pct, v=val)
  return my_format

def getOutCharts(out_master_file, tranco_rank_file, analysis_out_dir):
  out_master_df = pd.read_pickle(out_master_file)
  rankings_df = pd.read_csv(tranco_rank_file, names=["rank", "domain"])

  print("Bitflip Domains Per Type")
  type_counts = out_master_df['type'].value_counts()
  print(type_counts.head(10))
  result_df = pd.DataFrame({'Value': type_counts.index, 'Count': type_counts.values})
  result_df.to_csv(os.path.join(analysis_out_dir, 'type_counts.csv'), index=False)
  counts = [
    type_counts.loc['defensive'] + type_counts.loc['defensive_redirect'],
    type_counts.loc['malicous_ip'] + type_counts.loc['malicous_redirect'],
    type_counts.loc['non_malicous'],
    type_counts.loc['unkown']
    ]
  labels = ['Defensive', 'Malicous', 'Non Malicous', 'Unknown']
  colors = ['green', 'red', 'grey', 'black']
  #plt.pie(type_counts, labels = type_counts.index, autopct=autopct_format(type_counts))
  plt.pie(counts, labels = labels, autopct=autopct_format(counts), colors=colors)
  plt.title("Bitflip Domains Per Type")
  plt.savefig(os.path.join(analysis_out_dir, 'bitflip_domains_per_type.png'))
  plt.clf()

  print("Number of Bitflip Domains Per Original Domain")
  total_bf_counts = out_master_df['orig_domain'].value_counts()
  print(total_bf_counts.head(10))
  result_df = pd.DataFrame({'Domain': total_bf_counts.index, 'Count': total_bf_counts.values})
  result_df.to_csv(os.path.join(analysis_out_dir, 'bitflipdomainsPerOriginal.csv'), index=False)

  print("Top Defensive Registrations")
  defensive_types = {'defensive', 'defensive_redirect'}
  defensive_df = out_master_df.loc[out_master_df['type'].isin(defensive_types)]
  def_value_counts = defensive_df['orig_domain'].value_counts()
  result_df = pd.DataFrame({'Domain': def_value_counts.index, 'Count': def_value_counts.values})
  result_df.to_csv(os.path.join(analysis_out_dir, 'defCounts.csv'), index=False)
  print(def_value_counts.head(10))

  print("Top Malicous Targets")
  mal_types = {'malicous_ip', 'malicous_redirect'}
  mal_df = out_master_df.loc[out_master_df['type'].isin(mal_types)]
  mal_value_counts = mal_df['orig_domain'].value_counts()
  result_df = pd.DataFrame({'Domain': mal_value_counts.index, 'Count': mal_value_counts.values})
  result_df.to_csv(os.path.join(analysis_out_dir, 'malCounts.csv'), index=False)
  print(mal_value_counts.head(10))

  #print("Targets by Popularity")
  ordered_orig_names = rankings_df['domain'].tolist()[:1000]
  sorted_mal_value_counts = mal_value_counts.reindex(ordered_orig_names)
  sorted_mal_value_counts.fillna(0, inplace=True)
  plt.scatter(range(1000),sorted_mal_value_counts.values, marker='.')
  plt.xlabel('Tranco Domain Rank')
  plt.ylabel('Number of Malicous Bitflip Domains')
  plt.title('Number of Malicous Bitflip Domains by Tranco Domain Rank')
  plt.savefig(os.path.join(analysis_out_dir, 'bitflip_domains_by_tranco_rank.png'))
  plt.clf()
  #Ordered by string length
  mappings = dict()
  for domain, count in sorted_mal_value_counts.items():
    domain_len = len(domain)
    if domain_len not in mappings.keys():
      mappings[domain_len] = [0,0]
    mappings[domain_len][0] += 1
    mappings[domain_len][1] += count

  total_domains = sum([int(key) for key in mappings.keys()])
  domain_ratios = []
  max_key = max(mappings.keys())
  avg_mal_domains = []
  for sl in range(1, max_key + 1):
    if sl in mappings.keys():
      domain_ratios.append(mappings[sl][0] / total_domains)
      avg_mal_domains.append(mappings[sl][1] / mappings[sl][0])
    else:
      domain_ratios.append(0)
      avg_mal_domains.append(0) 

  # Create first subplot
  fig, ax1 = plt.subplots()

  # Plot the first data as scatter on the first y-axis
  ax1.plot(range(1, max_key + 1), avg_mal_domains, color='red', label='Average Number of Malicous Bitflip Domains', marker='.')#, s=10)
  ax1.set_xlabel('Domain Length')
  ax1.set_ylabel('Average Number of Malicous Bitflip Domains', color='red')

  # Create second y-axis and plot the second data as scatter
  ax2 = ax1.twinx()
  ax2.plot(range(1, max_key + 1), domain_ratios, color='blue', label='Ratio of Total Domains', marker='.')#, s=10)
  ax2.set_ylabel('Ratio of Total Domains', color='blue')

  # Adding legend
  lines1, labels1 = ax1.get_legend_handles_labels()
  lines2, labels2 = ax2.get_legend_handles_labels()
  #ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper right')
  fig.suptitle('Average Malicous Bitflip Domains by String Length')
  fig.savefig(os.path.join(analysis_out_dir, 'bitflip_domains_by_string_length.png'))

def process_VT(ip_file, output_file, start, end, delay):
  with open(ip_file) as f:
    ips = f.read().splitlines()
  ips_to_read = ips[start:min(end, len(ips))]

  try:
    with open(output_file, 'r') as out_f:
      vt_data = json.load(out_f)
  except FileNotFoundError as e:
    vt_data = dict()
    print(e)

  for idx, ip in enumerate(ips_to_read):
    if ip not in vt_data.keys() or vt_data[ip][3]:
      try:
        resp, error_code = ipReportReader(ip, delay)#DomainReportReader(ip, delay)
        if error_code is not None:
          print(f"{ip} error:{error_code}")
          vt_data[ip] = ['','','',True]
        else:
          resp.append(False)
          vt_data[ip] = resp
      except Exception as e:
        print(e)
      time.sleep(delay)
    print(f"completed: {idx + 1}")

  with open(output_file, 'w') as out_f:
    json.dump(vt_data, out_f)

def classify_1(domain_to_ip_file, bf_domain_2_org_domain_file, out_master_file):
  domains_to_ips = pd.read_pickle(domain_to_ip_file)
  bitflipdomains = domains_to_ips.Domain.unique()
  bf_2_orig_mappings = pd.read_pickle(bf_domain_2_org_domain_file)
  new_out_master = []
  
  for idx, bitflipdomain in enumerate(bitflipdomains):
    mapping_row = bf_2_orig_mappings.loc[bf_2_orig_mappings.bitflipDomain == bitflipdomain]
    if mapping_row.LevDistance.iat[0] > 0:
      original_domain = mapping_row.OriginalDomain.iat[0]
      orig_ips = domains_to_ips.loc[domains_to_ips.Domain == original_domain].IP
      bitflip_ips = domains_to_ips.loc[domains_to_ips.Domain == bitflipdomain].IP

      #Get if domain points to any of orginal domains ips
      intersection = pd.merge(bitflip_ips, orig_ips, how='inner', on=['IP'])
      if intersection.shape[0] > 0:
        type = 'defensive'
      else:
        type = 'unkown'
      #OUT_COLS = ['domain', 'orig_domain', 'ips', 'type']
      new_out_master.append([bitflipdomain, original_domain, list(bitflip_ips), type])
    if (idx + 1) % 100 == 0:
      print(f"completed: {idx + 1}")
  #Write to File
  mapping_df = pd.DataFrame(new_out_master, columns=OUT_COLS)
  mapping_df.to_pickle(out_master_file)

def get_top_unkown_ips(out_master_file, out_ip_file):
  out_master_df = pd.read_pickle(out_master_file)
  unkown_rows = out_master_df.loc[out_master_df.type == 'unkown'].explode('ips').reset_index(drop=True)
  ip_counts = unkown_rows.groupby('ips').size()
  ip_counts_sorted = ip_counts.sort_values(ascending=False)
  
  with open(out_ip_file, 'w+') as f:
    for ip, count in ip_counts_sorted.items():
      #print(f"IP: {ip}, Count: {count}")
      f.write(f"{ip}\n")

def classify_2(ip_2_vt_file, out_master_file):
  #Check if domain is malicous or redirects
  out_master_df = pd.read_pickle(out_master_file)
  unkown_rows = out_master_df.loc[out_master_df.type == 'unkown']
  new_out_master = out_master_df.set_index('domain').to_dict('index')
  with open(ip_2_vt_file, 'r') as f:
    ip_2_vt_data = json.load(f)
  
  for index, row in unkown_rows.iterrows():
    bitflip_ips = row.ips
    for ip in bitflip_ips:
      if ip in ip_2_vt_data.keys():
        ip_data = ip_2_vt_data[ip]
        if ip_data[3] == False and ip_data[0] > 0:
          #Malicous
          new_out_master[row.domain]['type'] = 'malicous_ip'
          break
        elif ip_data[3] == False:
          #Not Malicous
          new_out_master[row.domain]['type'] = 'non_malicous'
  new_out_master_df = pd.DataFrame.from_dict(new_out_master, orient='index').reset_index(names='domain')
  new_out_master_df.to_pickle(out_master_file)
  print(f"unknown:{len(new_out_master_df.loc[new_out_master_df.type == 'unkown'])} known:{len(new_out_master_df.loc[new_out_master_df.type != 'unkown'])}")

OTHER_MATCHING = {
  "cdninstagram.com" : "instagram.com",
  "unity3d.com"      : "unity.com",
  "timeweb.ru"       : "timeweb.com\/ru\/"
}
MALICOUS_DOMAINS = {
  "choto.xyz",
  "136.243.255.89"
}
def check_domains(domains_origs):
  timeout_seconds = 3
  redirect_codes = {302, 301, 307}
  redirect_domains = []
  lines_out = []
  malicous_domains = []
  for domain_orig in domains_origs:
    line_out = None
    domain, orig_domain = domain_orig
    r = None
    try:
      url = f"https://{domain}"
      r = requests.get(url, allow_redirects=False, timeout=timeout_seconds)
    except Exception as e:
      url = f"http://{domain}"
      try:
        r = requests.get(url, allow_redirects=False, timeout=timeout_seconds)
      except:
        continue
    if r != None:
      if r.status_code in redirect_codes:
        try:
          redirect_domain = r.headers['Location']
        except Exception as e:
          print(e)
          continue
        is_match = False
        mal = False
        for match_domain in MALICOUS_DOMAINS:
            pattern = "(https?:\/\/)?(?:www\\.)?(?<![a-zA-Z])" + match_domain.replace('.', r'\.') + "(?::\d+)?(?:[\/?#]|$)"
            match = re.search(pattern, redirect_domain)
            if match:
              mal = True
              malicous_domains.append(domain)
              break
        if not mal:
          domains_to_match = [orig_domain]
          if orig_domain in OTHER_MATCHING.keys():
            domains_to_match.append(OTHER_MATCHING[orig_domain])
          for match_domain in domains_to_match:
            pattern = "(https?:\/\/)?(?:www\\.)?(?<![a-zA-Z])" + match_domain.replace('.', r'\.') + "(?::\d+)?(?:[\/?#]|$)"
            match = re.search(pattern, redirect_domain)
            if match:
              is_match = True
              redirect_domains.append(domain)
              break
        
        line_out = f"bitflip_domain:{domain} code:{r.status_code} redirect:{redirect_domain} orig_domain:{orig_domain} match:{is_match} malicous:{mal}"
      else:
        line_out = f"bitflip_domain:{domain} code:{r.status_code}"

    if line_out != None:
      lines_out.append(line_out)
      print(line_out)

  return redirect_domains, malicous_domains, lines_out

def chunks(l, n):
  """Yield n number of striped chunks from l."""
  for i in range(0, n):
    yield l[i::n]

def classify_3(out_master_file, out_searched_file):
  num_threads = 8
  out_master_df = pd.read_pickle(out_master_file)
  non_malicous_rows = out_master_df.loc[out_master_df.type == 'non_malicous']
  new_out_master = out_master_df.set_index('domain').to_dict('index')

  searched_domains = set()
  with open(out_searched_file, 'r') as f:
    for line in f:
      bitflip_domain_str = line.split()[0]
      if bitflip_domain_str.find("bitflip_domain:") >= 0:
        bitflip_domain = bitflip_domain_str[len("bitflip_domain:"):].strip()
        searched_domains.add(bitflip_domain)

  domains_origs = list(zip(non_malicous_rows.domain, non_malicous_rows.orig_domain))
  search_Domains = [item for item in domains_origs if item[0] not in searched_domains]
  redirect_domains = []
  malicous_domains = []
  lines_out = []
  with Pool(processes=num_threads) as pool:
    result = pool.map(check_domains, chunks(search_Domains, num_threads))
  for res in result:
    redirect_domains.extend(res[0])
    malicous_domains.extend(res[1])
    lines_out.extend(res[2])

  for domain in redirect_domains:
    new_out_master[domain]['type'] = 'defensive_redirect'
  for domain in malicous_domains:
    new_out_master[domain]['type'] = 'malicous_redirect'

  new_out_master_df = pd.DataFrame.from_dict(new_out_master, orient='index').reset_index(names='domain')
  new_out_master_df.to_pickle(out_master_file)

  with open(out_searched_file, 'a') as f:
    f.write("\n".join(lines_out))
    f.write("\n")
  
def gen_ip_to_owner(domain_to_ip_file, out_master_file, orig_domain_to_owner_file, cymru_ouput_file):
  out_master_df = pd.read_pickle(out_master_file)
  domains_to_ips = pd.read_pickle(domain_to_ip_file)
  cymru_df = pd.read_pickle(cymru_ouput_file).applymap(lambda x: x.strip() if isinstance(x, str) else x)
  original_domains = out_master_df.orig_domain.unique()
  orig_domain_to_owner = dict()
  with open(orig_domain_to_owner_file, 'w') as f:
    for domain in original_domains:
      orig_ips = domains_to_ips.loc[domains_to_ips.Domain == domain].IP
      orig_ASs = cymru_df.loc[cymru_df['IP'].isin(orig_ips)]['AS Name'].unique()
      AS_str = '|'.join(str(x) for x in orig_ASs)
      print(f"{domain}|{AS_str}\n")
      f.write(f"{domain}|{AS_str}\n")

if __name__ == "__main__":
  BASE_NAME = "output/tranco_top1k_dist1/"
  IP_FILE = os.path.join(BASE_NAME, "ips.txt")
  BITFLIP_DOMAIN_TO_ORIGINAL_DOMAIN_FILE = os.path.join(BASE_NAME, "bitflip_domains_2_orig_domains.pkl")
  DOMAIN_TO_IP_FILE = os.path.join(BASE_NAME, "domain_2_ip_file.pkl")
  UNKOWN_IPS = os.path.join(BASE_NAME, "unkown_ips.txt")
  OUT_MASTER = os.path.join(BASE_NAME, "out_master.pkl")
  IP_TO_VT = os.path.join(BASE_NAME, "ip_to_vt.json")
  IP_TO_OWNER = os.path.join(BASE_NAME, "orig_domain_to_owner.txt")
  CYMRU_FILE = os.path.join(BASE_NAME, "cymru_output.pkl")
  SEARCHED_DOMAINS = os.path.join(BASE_NAME, "searched_domains.txt")
  ANALYSIS_OUT_DIR = os.path.join(BASE_NAME, "analysis")
  TRANCO_RANK_FILE = "data/tranco_11FEB24-11MAR24.csv"
  #FULL RUN After VT
  #classify_1(DOMAIN_TO_IP_FILE, BITFLIP_DOMAIN_TO_ORIGINAL_DOMAIN_FILE, OUT_MASTER)
  #classify_2(IP_TO_VT, OUT_MASTER)
  classify_3(OUT_MASTER, SEARCHED_DOMAINS)
  #gen_ip_to_owner(DOMAIN_TO_IP_FILE, OUT_MASTER, IP_TO_OWNER, CYMRU_FILE)

  #During Testing
  #for i in range(16):
  #  get_top_unkown_ips(OUT_MASTER, UNKOWN_IPS)
  #  process_VT(UNKOWN_IPS, IP_TO_VT, 0, 20, delay = 15)
  #  classify_2(IP_TO_VT, OUT_MASTER)

  #Stats
  getOutCharts(OUT_MASTER, TRANCO_RANK_FILE, ANALYSIS_OUT_DIR)