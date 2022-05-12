import argparse
import os
import requests
import json
import csv
import ipaddress
import socket
import ssl
import OpenSSL.crypto as crypto


# CONSTANTS
RQL = {
    'aws': {
        'ips': '''config from cloud.resource where api.name = 'aws-ec2-describe-network-interfaces' AND json.rule
         = attachment.status equals \"attached\" and association.publicIp exists addcolumn association.publicIp''',
    },
    'gcp': {
        'dns': '''config from cloud.resource where api.name = 'gcloud-dns-managed-zone' addcolumn dnsName''',
    }
}


def get_prisma_token():
    """
    Make an authentication request to Prisma.
    :return:
    """
    headers = {
        'Accept': 'application/json; charset=UTF-8',
        'Content-Type': 'application/json; charset=UTF-8'
    }
    url = f'{PRISMA_URL}/login'
    body = {
        'username': PRISMA_API_KEYID,
        'password': PRISMA_API_SECRET
    }
    try:
        resp = requests.post(url=url, headers=headers, data=json.dumps(body), verify=verify_ssl)
    except Exception as e:
        print(f'Something went wrong: {e}')
        exit(2)
    return resp.json()['token']


def get_prisma_config(query):
    """
    Get Prisma's configuration by executing a query.
    :param query:
    :return:
    """

    headers = {
        'Accept': 'application/json; charset=UTF-8',
        'Content-Type': 'application/json; charset=UTF-8',
        'x-redlock-auth': get_prisma_token()
    }

    url = f'{PRISMA_URL}/search/config'
    body = {
        'withResourceJson': True,
        'query': query
    }
    try:
        resp = requests.post(url=url, headers=headers, data=json.dumps(body), verify=verify_ssl)
    except Exception as e:
        print(f'Something went wrong: {e}')
        exit(2)
    return resp.json()['data']


def get_my_ips(ips_file):
    """
    Fetch IP addresses belongs to the company's AWS accounts from Prisma.
    :param ips_file:
    :return:
    """

    ips = []
    if ips_file:
        # IPs comes from a static file
        try:
            for ip in open(ips_file, 'r').readlines():
                ips.append(ip)
        except IOError:
            print(f'could not read file: {ips_file}')
            exit(2)
    elif PRISMA_URL and PRISMA_API_KEYID and PRISMA_API_SECRET:
        # Pulling ips from prisma cloud.
        data = get_prisma_config(RQL['aws']['ips'])
        for interface in data['items']:
            ips.append(interface['dynamicData']['association.publicIp'])
    else:
        print('didnt provided an ips file or Prisma config variables')
        exit(2)
    return ips


def get_static_cns(cns_file_path):
    """
    Gets the common names (CN) list from the provided file's path.
    :param cns_file_path:
    :return:
    """

    try:
        with open(cns_file_path, 'r') as cns_file:
            cns = []
            for cn in cns_file.readlines():
                cns.append(cn.rstrip())
    except IOError:
        print(f'could not read file: {cns_file_path}')
        exit(2)
    return cns


def is_aws(ip):
    """
    Check whether the given IP address belongs to AWS or not.
    :param ip:
    :return:
    """

    # Iterating through known AWS IP ranges.
    for prefix in aws_ranges['prefixes']:
        # Iterating through ipv4 ranges only.
        if 'ip_prefix' in prefix:
            try:
                # IP is part of this range
                if ipaddress.ip_address(ip) in ipaddress.ip_network(prefix['ip_prefix']):
                    return True
            except:
                break
    return False


def write_row(writer, ip, name):
    """
    Write DNS record to CSV file.
    :param writer:
    :param ip:
    :param name:
    :return:
    """

    row = {'IP': ip.rstrip(), 'Domain': name.rstrip()}
    writer.writerow(row)


def get_cn(name):
    """
    Fetch the server's SSL certificate.
    :param name:
    :return:
    """

    try:
        dst = (name, 443)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(dst)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=dst[0])
        cert_bin = s.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
        # Returning the certificate's Common Name.
        return x509.get_subject().CN
    except:
        return 'N/A'


def is_certificate_mine(name):
    """
    Checks whether a given CN matches to our list of known CNs.
    :param name:
    :return:
    """
    common = get_cn(name)
    if common != 'N/A':
        # We have the certificate's Common Name.
        for cn in cns:
            if cn in common:
                # False Positive - Server belongs to the company.
                return True
    return False


def main(domains_file, ranges_file, cns_file, ips_file, verify, output_path):
    """
    The main method for the tool.
    :param domains_file:
    :param ranges_file:
    :param cns_file:
    :param ips_file:
    :param verify:
    :return:
    """

    # Initializing variables.
    global aws_ranges
    global my_ips
    global cns
    global verify_ssl
    verify_ssl = verify

    # Define our environment variables.
    global PRISMA_URL
    global PRISMA_API_KEYID
    global PRISMA_API_SECRET
    PRISMA_URL = os.getenv('PRISMA_URL')
    PRISMA_API_KEYID = os.getenv('PRISMA_API_KEYID')
    PRISMA_API_SECRET = os.getenv('PRISMA_API_SECRET')

    # Trying to read data from provided files.
    try:
        domains = json.load(open(domains_file, 'r'))
    except IOError:
        print(f'could not read file: {domains_file}')
        exit(2)
    cns = get_static_cns(cns_file)
    try:
        aws_ranges = json.load(open(ranges_file, 'r'))
    except IOError:
        print(f'could not read file: {ranges_file}')
        exit(2)
    my_ips = get_my_ips(ips_file)

    # Headers for output CSV file.
    csv_headers = ['Domain', 'IP']
    # @todo Allow the user to control the output file's name.
    csv_file = f"{output_path}/output.csv"

    try:
        writer = csv.DictWriter(open(csv_file, 'w', encoding='utf-8'), fieldnames=csv_headers)
        writer.writeheader()
        for domain in domains:
            # Iterating through A and CNAME records.
            if domain['record_type'] in ['A', 'CNAME']:
                ip = domain['record_value']
                if domain['record_type'] == 'CNAME' and str(domain['record_value']).startswith('ec2-'):
                    # Extracting ip from EC2 domain name.
                    ip = str(domain['record_value']).split('.')[0][4:].replace('-', '.')
                if is_aws(ip) and ip not in my_ips and not is_certificate_mine(domain['name']):
                    # Record suspected as dangling.
                    write_row(writer, domain['record_value'], domain['name'])

    except IOError:
        print(f'could not read file: {csv_file}')
        exit(2)


def interactive():
    parser = argparse.ArgumentParser(description='Execute unclaimed ips')

    # Add the arguments.
    parser.add_argument('-d', '--domains', help='Full path to domains file', dest='domains',
                        required=True)
    parser.add_argument('-o', '--output', help='Full path to output directory', dest='output',
                        required=True)
    parser.add_argument('-r', '--ranges', help='Full path to AWS ranges file', dest='ranges',
                        required=True)
    parser.add_argument('-cn', '--ssl-common-names', help='Full path to common names (CN) file for exclusion', dest='common',
                        required=True)
    parser.add_argument('-i', '--ips', help='Full path to owned IPs file', default='', dest='ips',
                        required=False)
    parser.add_argument('-v', '--skip-verify-ssl', help='Skip SSL verification for external HTTPS calls',
                        action='store_false', default=True, dest='verify', required=False)
    args = parser.parse_args()

    main(domains_file=args.domains,
         ranges_file=args.ranges,
         cns_file=args.common,
         ips_file=args.ips,
         verify=args.verify,
         output_path=args.output
         )


if __name__ == '__main__':
    interactive()
