import time
import subprocess
import platform
import os
import Levenshtein
from tldextract import extract

def validate_ip(s):
    a = s.split('.')
    if len(a) != 4:
        return False
    for x in a:
        if not x.isdigit():
            return False
        i = int(x)
        if i < 0 or i > 255:
            return False
    return True

def extract_domain(etld_plus1: str):
  tmp = extract(etld_plus1)
  return tmp.domain, '.' + tmp.suffix

def extract_domain_old(etld_plus1: str):
  idx = etld_plus1.find('.')
  etld = ''
  if etld_plus1[:4] == "www.":
    idx2 = etld_plus1.find('.', idx+1)
    if idx2 > 0:
      domain =  etld_plus1[idx+1:idx2]
      etld = etld_plus1[idx2:]
    else:
      domain = etld_plus1[idx+1:]
  else:
    if idx > 0:
      domain = etld_plus1[:idx]
      etld = etld_plus1[idx:]
    else:
      domain = etld_plus1
  return domain, etld

def query_dns(input_domain_name_file, num_threads = 1000, local_recursion = False, output_file = None):
  if output_file == None:
    cur_t = time.gmtime()
    #Passed to --output-file
    ifile_name = input_domain_name_file.split('/')[-1].split('.')[0]
    output_file = 'data/zdns_input-{}_date-{}-{}-{}-time-{}-{}.txt'.format(ifile_name, cur_t.tm_year, 
                                                                            cur_t.tm_mon, cur_t.tm_mday,
                                                                            cur_t.tm_hour, cur_t.tm_min)
  cat = 'cat'
  if platform.system() == 'Windows':
    cat = 'type'
    input_domain_name_file = os.path.abspath(input_domain_name_file)

  run_str = [cat, input_domain_name_file + '|', 'zdns', 'A', '--ipv4-lookup', '--threads', str(num_threads),
             '--output-file', output_file]
  if local_recursion:
    run_str.append('--iterative')
  subprocess.check_output(run_str, shell=True)

def get_levenshtein(w1, w2, mappings: dict = None):
  if mappings is not None:
    return mappings[w1][1]
  else:
    return Levenshtein.distance(w1,w2)