import json
import csv
import pandas as pd
import sys
from utils import extract_domain
import itertools

def char2bits(s):
  return bin(ord(s))[2:].zfill(8)

def generate_bitsquatting_keys_rfc1034(num_flips: int = 1):
  """
  Generates all characters allowed for domain names in rfc1034.
  """
  allowed_chars = set('1234567890-abcdefghijklmnopqrstuvwxyz')
  ret = {}
  for c in allowed_chars:
    bit_flipped_chars = []
    bit_string = char2bits(c)
    # Iterate through all possible bit positions
    for positions in itertools.combinations(range(len(bit_string)), num_flips):
        # Flip the selected bits
        flipped_bitstring = list(bit_string)
        for position in positions:
            flipped_bitstring[position] = str(1 - int(flipped_bitstring[position]))

        # Convert the flipped bitstring back to a character
        flipped_bitstring = ''.join(flipped_bitstring)
        flipped_character = chr(int(flipped_bitstring, 2)).lower()
        if flipped_character in allowed_chars and flipped_character != c:
          bit_flipped_chars.append(flipped_character)
    ret[c] = bit_flipped_chars
  return ret

def _edits1(domain:str , allowed_characters: dict):
  "All edits that are one edit away from `domain`."
  splits     = [(domain[:i], domain[i:])    for i in range(len(domain) + 1)]
  replaces   = [L + c + R[1:]           for L, R in splits if R for c in allowed_characters[R[0]]]
  return set(replaces)

def _gen_bitsquatted_domains(domain: str, max_dist: int, logging: bool = False):
  ret = {domain: 0}
  levels = [{domain}]
  counts = [1]
  allowed_characters_at_level = []
  for cur_dist in range(1, max_dist+1):
    allowed_characters_at_level.append(generate_bitsquatting_keys_rfc1034(cur_dist))
    thisLevel = set()
    for j in range(cur_dist):
      #First get all additional l
      for d in levels[-(j+1)]:
        thisLevel.update(_edits1(d, allowed_characters_at_level[j]))

    thisLevel.discard('') #For edge case where single letter domains return an empty value
    cur_level = thisLevel.difference(ret.keys())
    for bitflip_domain in cur_level:
      ret[bitflip_domain] = cur_dist
    counts.append(len(cur_level))
    levels.append(cur_level)
    if logging:
      print("finished {} domains within {} for {}".format(len(cur_level), cur_dist, domain))
  return ret, counts
  
def generate_bitsquatted_domains(
  top_domain_file: str,
  out_domain_file: str = 'data/bitflip_domains.txt',
  out_mapping_file: str = None,
  num_top_domains: str = 1000,
  max_bit_flips: int = 1,
  logging: bool = False
):
  """
  Function that takes in a top domain file and generates bitflip domains within given max_bit_flips distance.
  
  Args:
    top_domain_file : str
      csv file of top domains that bitflip domains will be generated from
    out_domain_file: str, default 'data/bitflip_domains.txt'
      The file where bitflip domain strings will be written to for use by zdns.
    out_mapping_file: str, default None
      A pkl file containing a DataFrame with columns 'Original Domain', 'bitflip Domain', and 'bit Distance'
    num_top_domains: str, default 1000
      The number of top domains to generate bitflip domains for.
    max_bit_flips: int, default 1
      The maximum levenshtein distance generated bitflip domains will be from the original domain.
    logging: bool, default False
      Will print extra logging information
  Returns:
    output_mappings: pd.DataFrame
      A dict containg the mappings of each bitflip domain to its list of original domains
  """
  etld_plus1s = []
  generated_domains = []
  mapping_rows = []
  try:
    with open(top_domain_file, newline='') as csvfile:
      reader = csv.reader(csvfile)
      for row in reader:
        etld_plus1s.append(row[1])
        if len(etld_plus1s) >= num_top_domains:
          break
  except Exception as e:
    print(e)
  
  for etld_plus1 in etld_plus1s:
    base_domain, etld = extract_domain(etld_plus1)
    bitflip_domains, _ = _gen_bitsquatted_domains(base_domain, max_bit_flips, logging)
    #Add Suffix
    generated_domains.extend([td + etld for td in bitflip_domains.keys()])
    #row: 'Original Domain', 'bitflip Domain', 'bit Distance'
    new_rows = [[etld_plus1, td + etld, bitflip_domains[td]] for td in bitflip_domains.keys()]
    mapping_rows.extend(new_rows)
  print("Domains Generated:{}".format(len(generated_domains)))

  if out_domain_file is not None:
    with open(out_domain_file, 'w') as outfile:
      outfile.write("\n".join(generated_domains))
  mapping_df = pd.DataFrame(mapping_rows, columns=['Original Domain', 'bitflip Domain', 'Lev Distance'])
  if out_mapping_file is not None:
    mapping_df.to_pickle(out_mapping_file)
  return mapping_df

if __name__ == "__main__":
  INPUT_DOMAIN_FILE = "data/tranco_11FEB24-11MAR24.csv"
  OUT_BITFLIP_DOMAIN_FILE = 'output/top1k_bitflip_domains.txt' #'data/test_tranco_top1k_lev2_bitflip_domains.txt' #""
  OUT_BITFLIP_MAPPING_FILE = 'output/top1k_bitflip_mappings.pkl' #'data/test_tranco_top1k_lev2_bitflip_mappings.pkl'
  generate_bitsquatted_domains(INPUT_DOMAIN_FILE, OUT_BITFLIP_DOMAIN_FILE, OUT_BITFLIP_MAPPING_FILE, max_bit_flips = 1, num_top_domains=1000, logging = True)