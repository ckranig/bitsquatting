import json
import matplotlib.pyplot as plt
import os
from utils import validate_ip
import numpy as np
import pandas as pd
import ipaddress

FIG_DIR = 'figs'
if not os.path.exists(FIG_DIR):
  os.makedir(FIG_DIR)

def _get_orgs_and_asns(ips, df_table):
  results = df_table[df_table['IP'].isin(ips)]
  asns = set(results['AS Number'])
  asn_names = set(results['AS Name'])
  return {'asns': asns, 'asn_names': asn_names, 'ips': set(ips)}

def show_defensive_reg(domain_to_ips: dict, td_to_od_idx_lev: dict, od_idx_to_od: dict, 
                       out_file_name: str = FIG_DIR + '/tranco1k_', 
                       cyrmu_file: str = "data/tranco_top1k_lev2_cymru_DEC2023.txt", **kwargs):
  max_lev = len(list(od_idx_to_od.values())[0][1])
  #Check is by org from whois and asn from aslookup uses cymru
  column_names = ['AS Number', 'IP', 'AS Name']
  df = pd.read_csv(cyrmu_file, sep='|', header=None, names=column_names)
  for name in column_names:
    df[name] = df[name].str.strip()
  od_to_data = dict()

  non_matching_ips = dict()
  for od in od_idx_to_od.values():
      domain = od[0]
      if domain in domain_to_ips.keys():
        data = _get_orgs_and_asns(domain_to_ips[domain], df)
      else:
        data = {'asns': set(), 'asn_names': set(), 'ips': set()}
      data.update(
        {'matching_ip' : [0]*max_lev, 'matching_asn': [0]*max_lev, 'matching_as_name': [0]*max_lev, 
          'non_match_domains': [0]*max_lev, 'private_domains': [0]*max_lev}
      )
      od_to_data[domain] = data
      non_matching_ips[domain] = set()

  for domain in domain_to_ips.keys() - od_to_data.keys():
    data = _get_orgs_and_asns(domain_to_ips[domain], df)
    od = od_idx_to_od[str(td_to_od_idx_lev[domain][0])][0]
    lev_dist = td_to_od_idx_lev[domain][1] - 1
    #IPs
    if len(data['ips'].intersection(od_to_data[od]['ips'])) > 0:
      od_to_data[od]['matching_ip'][lev_dist] = od_to_data[od]['matching_ip'][lev_dist] + 1
    #ASNs
    elif len(data['asns'].intersection(od_to_data[od]['asns'])) > 0:
      od_to_data[od]['matching_asn'][lev_dist] = od_to_data[od]['matching_asn'][lev_dist] + 1
    #ASN Names
    elif len(data['asn_names'].intersection(od_to_data[od]['asn_names'])) > 0:
      od_to_data[od]['matching_as_name'][lev_dist] = od_to_data[od]['matching_as_name'][lev_dist] + 1
    #Private IPs
    elif all([ipaddress.ip_address(ip).is_private for ip in domain_to_ips[domain]]):
      od_to_data[od]['private_domains'][lev_dist] = od_to_data[od]['private_domains'][lev_dist] + 1
    #Non Matching AS
    else:
      non_matching_ips[od].update(data['ips'])
      if lev_dist == 0:
        print(domain)
      od_to_data[od]['non_match_domains'][lev_dist] = od_to_data[od]['non_match_domains'][lev_dist] + 1
  with open(out_file_name + 'non_matching_ips.json', 'w') as f:
    for domain in non_matching_ips.keys():
      non_matching_ips[domain] = list(non_matching_ips[domain])
    json.dump(non_matching_ips, f)
  with open(out_file_name + 'defensive_reg_data.json', 'w') as f:
    for domain in od_to_data.keys():
      for key in od_to_data[domain].keys():
        od_to_data[domain][key] = list(od_to_data[domain][key])
    json.dump(od_to_data, f)
    
  num_od = min(len(od_to_data.keys()),100)
  figure, axis = plt.subplots(max_lev, 1, layout='constrained')
  x_axis = range(num_od)
  matching_ips = np.zeros((max_lev, num_od))
  matching_asns = np.zeros((max_lev, num_od))
  matching_as_names = np.zeros((max_lev, num_od))
  num_typo_domains = np.zeros((max_lev, num_od))
  non_match_domains = np.zeros((max_lev, num_od))
  private_domains = np.zeros((max_lev, num_od))
  for od_idx in range(num_od):
    od_info = od_idx_to_od[str(od_idx)]
    domain = od_info[0]
    data = od_to_data[domain]
    matching_ips[:, od_idx] = data['matching_ip']
    matching_asns[:, od_idx] = data['matching_asn']
    matching_as_names[:, od_idx] = data['matching_as_name']
    non_match_domains[:, od_idx] = data['non_match_domains']
    private_domains[:, od_idx] = data['private_domains']
    num_typo_domains[:, od_idx] = od_info[1]
  #Plot Defensive Regular
  data_arrs = {
    'Matching IPs': matching_ips,
    'Matching ASNs': matching_asns,
    'Matching AS Names': matching_as_names
  }
  for lev, ax in enumerate(axis):
    ax.get_xaxis().set_ticks([])
    bottom = [0]*num_od
    for label, data_arr in data_arrs.items():
      if lev == 0:
        ax.bar(x_axis, data_arr[lev,:], 0.5, label=label, bottom=bottom)
      else:
        ax.bar(x_axis, data_arr[lev,:], 0.5, bottom=bottom)
      bottom += data_arr[lev,:]
        
  figure.legend(loc='outside upper right', ncol=3)
    
  plt.savefig(out_file_name + 'match_numbers.png')
  plt.clf()
  figure, axis = plt.subplots(max_lev, 1, layout='constrained')
  for lev, ax in enumerate(axis):
    ax.get_xaxis().set_ticks([])
    bottom = [0]*num_od
    for label, data_arr in data_arrs.items():
      data_percentages = data_arr[lev,:] / num_typo_domains[lev, :]
      if lev == 0:
        ax.bar(x_axis, data_percentages, 0.5, label=label, bottom=bottom)
      else:
        ax.bar(x_axis, data_percentages, 0.5, bottom=bottom)
      bottom += data_percentages
  figure.legend(loc='outside upper right', ncol=3)
  plt.savefig(out_file_name + 'match_percentages.png')
  plt.clf()

  non_match_data_arrs = {
    'Non-Matching AS': non_match_domains,
    'Private Domains': private_domains
  }
  figure, axis = plt.subplots(max_lev, 1, layout='constrained')
  for lev, ax in enumerate(axis):
    ax.get_xaxis().set_ticks([])
    bottom = [0]*num_od
    for label, data_arr in non_match_data_arrs.items():
      if lev == 0:
        ax.bar(x_axis, data_arr[lev,:], 0.5, label=label, bottom=bottom)
      else:
        ax.bar(x_axis, data_arr[lev,:], 0.5, bottom=bottom)
      bottom += data_arr[lev,:]
        
  figure.legend(loc='outside upper right', ncol=3)
    
  plt.savefig(out_file_name + 'non_match_numbers.png')
  plt.clf()
  figure, axis = plt.subplots(max_lev, 1, layout='constrained')
  for lev, ax in enumerate(axis):
    ax.get_xaxis().set_ticks([])
    bottom = [0]*num_od
    for label, data_arr in non_match_data_arrs.items():
      data_percentages = data_arr[lev,:] / num_typo_domains[lev, :]
      if lev == 0:
        ax.bar(x_axis, data_percentages, 0.5, label=label, bottom=bottom)
      else:
        ax.bar(x_axis, data_percentages, 0.5, bottom=bottom)
      bottom += data_percentages
  figure.legend(loc='outside upper right', ncol=3)
  plt.savefig(out_file_name + 'non_match_percentages.png')
  plt.clf()

  width = 0.3
  figure, axis = plt.subplots(max_lev, 1, layout='constrained')
  for lev, ax in enumerate(axis):
    ax.get_xaxis().set_ticks([])
    bottom = [0]*num_od
    for label, data_arr in data_arrs.items():
      if lev == 0:
        ax.bar(x_axis, data_arr[lev,:], width, label=label, bottom=bottom)
      else:
        ax.bar(x_axis, data_arr[lev,:], width, bottom=bottom)
      bottom += data_arr[lev,:]
    bottom = [0]*num_od
    for label, data_arr in non_match_data_arrs.items():
      if lev == 0:
        ax.bar([x + width for x in x_axis], data_arr[lev,:], width, label=label, bottom=bottom)
      else:
        ax.bar([x + width for x in x_axis], data_arr[lev,:], width, bottom=bottom)
      bottom += data_arr[lev,:]
        
  figure.legend(loc='outside upper right', ncol=3)
    
  plt.savefig(out_file_name + 'match_numbers_side_by_side.png')
  plt.clf()
  figure, axis = plt.subplots(max_lev, 1, layout='constrained')
  for lev, ax in enumerate(axis):
    ax.get_xaxis().set_ticks([])
    bottom = [0]*num_od
    for label, data_arr in data_arrs.items():
      data_percentages = data_arr[lev,:] / num_typo_domains[lev, :]
      if lev == 0:
        ax.bar(x_axis, data_percentages, width, label=label, bottom=bottom)
      else:
        ax.bar(x_axis, data_percentages, width, bottom=bottom)
      bottom += data_percentages
    bottom = [0]*num_od
    for label, data_arr in non_match_data_arrs.items():
      data_percentages = data_arr[lev,:] / num_typo_domains[lev, :]
      if lev == 0:
        ax.bar([x + width for x in x_axis], data_percentages, width, label=label, bottom=bottom)
      else:
        ax.bar([x + width for x in x_axis], data_percentages, width, bottom=bottom)
      bottom += data_percentages
  figure.legend(loc='outside upper right', ncol=3)
  plt.savefig(out_file_name + 'match_percentages_side_by_side.png')
  plt.clf()  

def show_domain_parking(ip_to_domains: dict, td_to_od_idx_lev: dict, out_file_name: str = FIG_DIR + '/domain_parking.png', **kwargs):
  previously_mapped = dict()
  color = 'r'
  ip_to_domains.pop('127.0.0.1', None)
  for ip in ip_to_domains.keys():
    typo_domains = ip_to_domains[ip]
    original_domains = set()
    num_original_domains_in_typo_domains = 0
    for typo_domain in typo_domains:
      original_domains.update(td_to_od_idx_lev[typo_domain][0])
    #Remove original domains
    for typo_domain in typo_domains:
      if typo_domain in original_domains:
        num_original_domains_in_typo_domains += 1
        color = 'b'
    x_y_c = (len(original_domains), len(typo_domains) - num_original_domains_in_typo_domains, color)
    if x_y_c not in previously_mapped.keys():
      previously_mapped[x_y_c] = 0
    previously_mapped[x_y_c] = previously_mapped[x_y_c] + 1

  x = []
  y = []
  c = []
  bubble_sizes = []
  for x_y_c in previously_mapped.keys():
    if x_y_c[1] > 0:
      x.append(x_y_c[0])
      y.append(x_y_c[1])
      c.append(x_y_c[2])
      bubble_sizes.append(previously_mapped[x_y_c])
    else:
      print(x_y_c)

  # Create a bubble chart
  plt.scatter(x, y, s=bubble_sizes, c=c, label='Data Points', alpha=0.5)

  # Add labels and a title
  plt.xlabel('Original Domains')
  plt.ylabel('Total Typo Domains')
  plt.title('Domain Parking')

  # Add a legend
  #plt.legend()

  # Save Fig
  plt.savefig(out_file_name)

  # Display the plot
  plt.clf()

if __name__ == "__main__":
  FUNS_TO_CALL = {
    show_defensive_reg
  }
  #ip_to_domains: dict, typo_domain_to_original_domains
  SAVED_FILE_PREFIX = FIG_DIR + '/' + 'tranco1k_'
  IP_MAPPING_FILE = 'data/tranco_top1k_lev2_mappings.json'
  TYPO_DOMAINS_TO_ORIGINAL_DOMAINS_FILE  = 'data/tranco_top1k_lev2_typo_mappings.json'
  with open(IP_MAPPING_FILE, 'r') as f:
    mapping_data = json.load(f)

  with open(TYPO_DOMAINS_TO_ORIGINAL_DOMAINS_FILE, 'r') as f:
    typo_domain_to_original_domains_mappings = json.load(f)

  args = {
    'ip_to_domains' : mapping_data['ip_to_domains'],
    'domain_to_ips' : mapping_data['domain_to_ips'],
    'td_to_od_idx_lev' : typo_domain_to_original_domains_mappings['typo2origIDX'],
    'od_idx_to_od' : typo_domain_to_original_domains_mappings['idx2orig']
  }
  for fun in FUNS_TO_CALL:
    fun(**args)