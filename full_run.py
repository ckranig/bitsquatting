import os
from bit_squatting import generate_bitsquatted_domains
from process_zdns import process_zdns, get_team_cymru_data
from utils import query_dns

BASE_NAME = "output/tranco_top1k_dist1/"
INPUT_DOMAIN_FILE = "data/tranco_11FEB24-11MAR24.csv"
OUT_BITFLIP_DOMAIN_FILE = os.path.join(BASE_NAME, "bitflip_domains.txt")
BITFLIP_DOMAIN_TO_ORIGINAL_DOMAIN_FILE = os.path.join(BASE_NAME, "bitflip_domains_2_orig_domains.pkl")
DOMAIN_TO_IP_FILE = os.path.join(BASE_NAME, "domain_2_ip_file.pkl")
OUT_ZDNS_FILE = os.path.join(BASE_NAME, "zdns.txt")
CYMRU_IP_FILE = os.path.join(BASE_NAME, "cymru_ips.txt")
CYMRU_OUTPUT_TXT_FILE = os.path.join(BASE_NAME, "cymru_output.txt")
CYMRU_OUTPUT_DF_FILE = os.path.join(BASE_NAME, "cymru_output.pkl")

generate_bitsquatted_domains(INPUT_DOMAIN_FILE, OUT_BITFLIP_DOMAIN_FILE, out_mapping_file = BITFLIP_DOMAIN_TO_ORIGINAL_DOMAIN_FILE, num_top_domains = 1000, max_bit_flips = 1)
#query_dns(OUT_BITFLIP_DOMAIN_FILE, output_file=OUT_ZDNS_FILE, num_threads=2000)
#process_zdns(OUT_ZDNS_FILE, DOMAIN_TO_IP_FILE, CYMRU_IP_FILE, True)
#get_team_cymru_data(CYMRU_IP_FILE, CYMRU_OUTPUT_TXT_FILE, CYMRU_OUTPUT_DF_FILE)