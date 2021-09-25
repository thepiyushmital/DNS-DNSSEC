import time
import dns.dnssec
import sys
import dns.rrset
import traceback as tb
import dns.message
import dns.query
from datetime import datetime

root_server_ip_list = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241',
                       '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42',
                       '202.12.27.33']


def resolve_single_query_basic(host, rdtype, dest_ip_ns):
    # Function for resolving the basic dns query
    query = dns.message.make_query(host, rdtype)
    # Custom dns timeout given as 5 seconds
    resp = dns.query.udp(query, dest_ip_ns, 5)
    return resp


def print_result(host, rdtype, dns_resp, duration, when, message_size):
    # Fucntion to print the proper output of the response from the dns_basic resolver
    print('\n')
    print("QUESTION:")
    print(host, "\t", "IN", "\t", rdtype)

    print('\n')
    ans_len = 0
    print("ANSWER:")
    # Flip the output sequence to make more sense of the response answer output
    for j in range(len(dns_resp.answer)):
        k = len(dns_resp.answer) - j - 1
        ans_len += len(dns_resp.answer[k].to_text())
        for x in dns_resp.answer[k].to_text().split(" "):
            print(x, "\t", end=" ")
        print("\n")

    print('\n')

    print('Query time: ', int(duration * 1000), ' msec')
    print('WHEN: ', when)
    print('MSG SIZE rcvd: ', message_size)
    print('\n')


def dns_basic(cname_list, host, rdtype):
    for root_ip in root_server_ip_list:
        try:
            # Check the first response from the basic query
            base_response = resolve_single_query_basic(host, rdtype, root_ip)
            # Check if answer exists in the base resposne
            if base_response.answer:
                # If answer exists then venture into the answer
                rrset_items = base_response.answer
                for element in rrset_items:
                    # Do preprocessing on the rrsets to get the right answer
                    rrset_values = element.to_text().split(" ")

                    if rrset_values[3] == 'CNAME':
                        # if the answer has a CNAME then resolve the CNAME and that would be your final answer
                        cname_list.append(rrset_values[4])
                        response = dns_basic(cname_list, rrset_values[4], rdtype)
                        response.answer.append(element)
                        base_response = response
                    break
            elif base_response is not None:
                # If response is not null and if answer section is used up
                response = base_response
                while not response.answer:
                    # check for the answer section being empty here
                    if response.additional:
                        # check if the additional seciton has the ip for the next section
                        additional_rrsets = response.additional
                        for rrsets in additional_rrsets:
                            rrsets = rrsets.to_text().splitlines()
                            for rrset in rrsets:
                                try:
                                    rrset_values = rrset.split(" ")
                                    # IF additional section utilizes ipv6 queries, then skip this rrset and go to the next one
                                    if rrset_values[3] == 'AAAA':
                                        continue
                                    # resolve single query for original host and the newly found ip in additional section
                                    response = resolve_single_query_basic(host, rdtype, rrset_values[4])
                                    # Assign this new response to the base response so that it doesnt get overwritten
                                    if response.answer:
                                        base_response = response
                                        break
                                    # Check if both additional  nad authority are empty or not.
                                    elif response.additional or response.authority:
                                        break
                                except Exception as e:
                                    print(e)
                                    continue
                    elif response.authority:
                        # check if authority section is usable and non empty
                        authority_rrsets = response.authority
                        for resrec_sets in authority_rrsets:
                            rrsets = resrec_sets.to_text().splitlines()
                            # Do preprocessing and remove individual rrsets from the authority section
                            flag = False
                            if (len(rrsets) == 1 and rrsets[0].split(" ")[3] == "SOA" and (
                                    rdtype == 'MX' or rdtype == 'NS')):
                                # This check here is for making sure that even SOA outputs for MX and NS records get catered to.
                                base_response.answer.append(resrec_sets)
                                response.answer.append(resrec_sets)
                                break
                            for rrset in rrsets:
                                try:
                                    rrset_values = rrset.split(" ")
                                    '''
                                    if ns server ip has to be resolve, go below. 
                                    resolve that ip and then put the answer section of it into the additonal section of response
                                    '''
                                    ns_name = rrset_values[4]
                                    response_auth = dns_basic(cname_list, ns_name, 'A')
                                    response.additional.append(response_auth.answer[0])
                                    flag = False
                                    break
                                except Exception:
                                    flag = False
                                    continue
                            if response.additional:
                                break
                            if response.answer:
                                break
                if base_response.answer:
                    rrset_items = base_response.answer
                    # If answer exists then venture into the answer
                    for element in rrset_items:
                        # Do preprocessing on the rrsets to get the right answer
                        rrset_values = element.to_text().split(" ")
                        if rrset_values[3] == 'CNAME':
                            # if the answer has a CNAME then resolve the CNAME and that would be your final answer
                            cname_list.append(rrset_values[4])

                            response = dns_basic(cname_list, rrset_values[4], rdtype)
                            response.answer.append(element)
                            base_response = response
                        break
        except Exception as e:
            print(e)
            continue
        if base_response is not None:
            break
    return base_response


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(" Wrong arguments passed to mydig command. Pass Hostname and RDTYPE for correct output")
    else:
        host = str(sys.argv[1])
        rdtype = str(sys.argv[2])
        cann_list = []
        begin_time = time.time()
        dns_resp = dns_basic(cann_list, host, rdtype)
        end_time = time.time()
        when = datetime.now().strftime("%a %b %d %H:%M:%S %Y")

        duration = end_time - begin_time
        print_result(host, rdtype, dns_resp, duration, when, len(dns_resp.to_text()))
