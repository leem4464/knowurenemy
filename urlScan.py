from time import sleep

import argparse
import sys
import client


parser = argparse.ArgumentParser(description="Obtaining for scanning and obtaining information from potentially malicious websites using by CriminalIP and urlScan")
#parser.add_argument("--scan-type", type=str, default="public", help="URL Scan Type (default: Public)")
#parser.add_argument("--no-browser", action="store_true", help="Do not open a browser")
parser.add_argument("--k", "--key", type=str, help="CriminalIP API Key")
parser.add_argument("--s", "--query", type=str, help="Input data for Searching")
args = parser.parse_args()

if (len(sys.argv)) < 2:
    print("Usage : python urlScan.py --k <Criminal API Key> --s <query search>")
    print("Example : python urlScan.py --k <Criminal API Key> --s naver.com")


try:
    print("==============================================================")
    print(" _____        _             _                _   _____ ______")
    print("/  __ \      (_)           (_)              | | |_   _|| ___ \\" )
    print("| /  \/ _ __  _  _ __ ___   _  _ __    __ _ | |   | |  | |_/ /")
    print("| |    | '__|| || '_ ` _ \ | || '_ \  / _` || |   | |  |  __/ ")
    print("| \__/\| |   | || | | | | || || | | || (_| || |  _| |_ | |    ")
    print(" \____/|_|   |_||_| |_| |_||_||_| |_| \__,_||_|  \___/ \_|    ")
    print("==============================================================")
    print()
    Criminal_API_KEY = args.k
    query = args.s

    print("Criminal API Key: " + Criminal_API_KEY)
    print("What Search: " + query)

    api = client.CriminalIP(Criminal_API_KEY)

    # Find scan_id using by domain scan
    scan_result = api.criminal_domain_scan(query)
    scan_id = scan_result['data']['scan_id']
    real_ip_list = []
    screen_shots = []
    print('scan_id: ', end='')
    print(scan_id)

    # Find ip using by domain search
    if scan_id != '':
        sleep(5)
        i = 1
        scan_ip = ''
        try:
            while(True):
                report_result = api.criminal_domain_report(scan_id)
                # Find Data using by scan_id
                if (i < 50):
                    ++i
                    if 'No Search Data' in report_result['message']:
                        continue
                    else:
                        #report_result_list = report_result['data']['network_logs']
                        report_result_list = report_result['data']['mapped_ip']
                        for list in report_result_list:
                            #scan_ip = list['ip_port']
                            scan_ip = list['ip']
                            real_ip_list.append(scan_ip)
                        report_result_screen_shots = report_result['data']['screenshots']
                        for screen_list in report_result_screen_shots:
                            screen_shots.append(screen_list)
                        break
                        
                break
        except Exception as e:
            print(e)
    else:
        print("Cannot find Scan_id")

    if len(real_ip_list) > 0:
        for ip in real_ip_list:
            results = {}
            asset_list = api.criminal_asset_data(ip)
            results['ip'] = asset_list['ip']
            results['tags'] = asset_list['tags']
            results['score'] = asset_list['score']
            results['domain'] = asset_list['domain']
            results['whois'] = asset_list['whois']
            results['ip_category'] = asset_list['ip_category']
            #results['port'] = asset_list['port']
            results['vulnerability'] = asset_list['vulnerability']
            print(results)
            open_tcp_port = []
            open_udp_port = []

            
            for is_vulnerability in asset_list['port']['data']:
                if is_vulnerability['is_vulnerability'] == False and is_vulnerability['socket'] == 'tcp':
                    open_tcp_port.append(is_vulnerability['open_port_no'])
                elif is_vulnerability['is_vulnerability'] == False and is_vulnerability['socket'] == 'udp':
                    open_udp_port.append(is_vulnerability['open_port_no'])
            
            print("*" * 30)
            print("Open TCP Port: ", end = '')
            print(open_tcp_port)
            print("Open UDP Port: ", end = '')
            print(open_udp_port)
            print("Screenshots: ", end='')
            print(screen_shots)
            print("*" * 30)
    
except Exception as e:
    print(e)