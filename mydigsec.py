import time
from enum import Enum
import dns.dnssec
import re
import ipaddress
import dns.rrset
import traceback as tb
import dns.message
from cryptography.fernet import Fernet
import dns.query
import cryptography
from datetime import datetime
import sys

root_server_ip_list = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241',
                       '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42',
                       '202.12.27.33']
anchor_dictionary = {
    2010: dns.rrset.from_text('.', 15202, 'IN', 'DNSKEY',
                              '257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0=')[
        0].to_text(),
    2017: dns.rrset.from_text('.', 1, 'IN', 'DNSKEY',
                              '257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=')[
        0].to_text()
}

# ------------------------------------ CODE FOR BASIC DNS ---------------------------------------------------------------
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


# -------------------------------------------------------- CODE FOR DNSSEC ----------------------------------------------
NULL_ANS = 35
EXIST_ANS = 36
DNSSEC_NOT_EXIST = 37
VERIFY_DNSSEC_CRASH = 38


def ds_resp_check(response):
    for res_rec in response.authority:
        if res_rec.rdtype == 43:
            return True
    return False


def resolve_single_query(host, rdtype, dest_ip_ns, dnssec_req):
    query = dns.message.make_query(host, rdtype, want_dnssec=dnssec_req)
    # print(query)
    try:
        resp = dns.query.udp(query, dest_ip_ns, 1)
        return resp
    except Exception as exp:
        print(exp, "could not find resolution for single query")
        return None


def resolve_combined_query(host, rdtype, ip, domain_host, domain_type):
    # Get the first response for the resolution of the hostname with the root server ip
    # Get the Resource Record containting both root PublicKSK and PublicZSK
    return resolve_single_query(host, rdtype, ip, dnssec_req=True), resolve_single_query(domain_host, domain_type, ip,
                                                                                         dnssec_req=True)


def check_alt_response(alt_response):
    if len(alt_response.answer) != 0:
        return EXIST_ANS
    if not ds_resp_check(alt_response):
        print(" Server hasn't responded with a rdtype 43, so DNSSEC NOT SUPPORTED")
        return DNSSEC_NOT_EXIST


def resolve_single_query_basic(host, rdtype, dest_ip_ns):
    query = dns.message.make_query(host, rdtype)
    # print(query)
    try:
        resp = dns.query.udp(query, dest_ip_ns, 5)
        return resp
    except Exception as exp:
        print(exp, "could not find resolution for single query")
        return None


def validate_ds_ns_records(response, dict_name_key, dns_key):
    try:
        digi_sig, resource_record_signature, name_digi_sig = fetch_ns_ds_resource_record(response)

        # To decrypt RRSIG of DS record, Public zsk is required, which is available as a part of DNSKEY
        dns.dnssec.validate(digi_sig, resource_record_signature, {dict_name_key: dns_key})
        # Verify the DS record and it RRSIGN against the verified DNSKEY fetched already
    except Exception as e:
        tb.print_exc()
        raise e

    # Verification complete for given DS or NS record


def fetch_cname(res_record_set):
    try:
        for rrset in res_record_set:
            return rrset.to_text().split(" ")[4]
    except Exception as e:
        print('CNAME couldnt be extracted', e)


def dnssec(host, rdtype, cnames):
    for ip in root_server_ip_list:
        try:
            alt_response = None
            dns_key_response = None
            status = NULL_ANS

            response, parent_dns_key = resolve_combined_query(host, rdtype, ip, '.', 'DNSKEY')

            if len(response.additional) == 0:
                continue

            # The key name of the rrset and the dns_key are returned after validation
            # Success here means DNSKEY set is good to be used
            dict_name_key, dns_key = validate_dnskey_or_a_record(parent_dns_key, 'DNSKEY', None, None)

            # Checking if the public KSK given by the root matches with the trust anchors we've already used
            for key in dns_key:
                if (key.flags == 257):
                    if (key.to_text() == anchor_dictionary[2010] or key.to_text() == anchor_dictionary[2017]):
                        continue
                    else:
                        tb.print_exc()
                        raise Exception(
                            'Trusted anchor public ksk doesnt match with the public ksk provided by root server')

            # print("Root validation Done! Trust anchor and root public ksk match!")

            # Validation of DS records against dns_key fetched earlier.
            validate_ds_ns_records(response, dict_name_key, dns_key)

            # if TLD information is missing, check the next root server in the list
            while status == NULL_ANS:
                if response.additional:
                    # fetch and keep the name of the rrset in the authority
                    future_name = response.authority[0].name.to_text()
                    for rrset in response.additional:
                        next_ip = rrset.to_text().split(' ')[4]
                        try:
                            alt_response, dns_key_response
                            alt_response, dns_key_response = resolve_combined_query(host, rdtype, next_ip, future_name,
                                                                                    'DNSKEY')

                            if (check_alt_response(alt_response) == EXIST_ANS) or (
                                    check_alt_response(alt_response) == DNSSEC_NOT_EXIST):
                                status = check_alt_response(alt_response)
                                break

                            dict_name_key, dns_key = validate_dnskey_or_a_record(dns_key_response, 'DNSKEY', None, None)
                            validate_ds_ns_records(alt_response, dict_name_key, dns_key)
                            zone_verification(None, response, dns_key_response, "ZONE")

                            response = alt_response
                            parent_dns_key = dns_key_response
                            break
                        except Exception as e:
                            tb.print_exc()
                            print("Error with the current RRSET, trying next one")
                            continue
                else:
                    authority_rrsets = response.authority
                    for rrsets in authority_rrsets:
                        rrsets = rrsets.to_text().splitlines()
                        for rrset in rrsets:
                            try:
                                rrset_values = rrset.split(" ")
                                ns_name = rrset_values[4]
                                # print("reached here")
                                alt_response = dns_basic(cnames, ns_name, 'A')
                                response.additional.append(alt_response.answer[0])
                                break
                            except Exception as e:
                                continue
                        if response.additional:
                            break
                    if not response.additional:
                        return response

            if status == DNSSEC_NOT_EXIST:
                return status, alt_response

            # Fetch answer type after all resolutions: Either can be CNAME or something else
            rrset_type = alt_response.answer[0].rdtype

            if (rrset_type == 5 and rdtype == 'CNAME'):
                for res_record in response.answer:
                    try:
                        return dnssec(fetch_cname(res_record), rdtype, cnames)
                    except Exception as e:
                        tb.print_exc()
                        continue
            else:
                try:
                    dict_name_key, dns_key = validate_dnskey_or_a_record(dns_key_response, 'DNSKEY', None, None)
                    validate_dnskey_or_a_record(alt_response, 'A', dict_name_key, dns_key)
                    zone_verification(None, response, dns_key_response, "ZONE")
                except Exception as e:
                    print(e)
                    return VERIFY_DNSSEC_CRASH, alt_response
                return status, alt_response
            break
        except Exception as e:
            tb.print_exc()


def fetch_dnskey_a_resource_record(response):
    try:
        resrec_dns_key_a_rec = None
        resrec_sig = None
        resrec_name = None
        for resrecord in response.answer:
            # RRSIGN rdtype is 46
            # check if rrset type is of A record or dnskey
            if resrecord.rdtype == 1 or resrecord.rdtype != 46:
                resrec_dns_key_a_rec = resrecord
                resrec_name = resrecord.name
            else:
                resrec_sig = resrecord
        return resrec_dns_key_a_rec, resrec_sig, resrec_name
    except Exception as re:
        tb.print_exc()
        #Unable to fetch dnskey or A resource record
        raise re


def fetch_ns_ds_resource_record(response):
    try:
        resrec_ds_ns_rec = None
        resrec_sig = None
        resrec_name = None
        for resrecord in response.authority:
            # RRSIGN rdtype is 46
            if resrecord.rdtype == 2 or resrecord.rdtype != 46:
                resrec_ds_ns_rec = resrecord
                resrec_name = resrecord.name
            else:
                resrec_sig = resrecord
        # print("resrec_name:", resrec_name, " sig:", resrec_sig, " resrec_name:", resrec_name)
        return resrec_ds_ns_rec, resrec_sig, resrec_name
    except Exception as re:
        tb.print_exc()
        # Unable to fetch ds or ns resource record
        raise re


def validate_ds_ns_records(response, dict_name_key, dns_key):
    try:
        digi_sig, resource_record_signature, name_digi_sig = fetch_ns_ds_resource_record(response)
        # Verify the DS record and it RRSIGN against the verified DNSKEY fetched already
        # Public zsk is required to decrypt RRSIG of DS record. It's available as a part of DNSKEY
        dns.dnssec.validate(digi_sig, resource_record_signature, {dict_name_key: dns_key})
    except Exception as e:
        tb.print_exc()
        raise e

    # Verification complete for given DS or NS record


def validate_dnskey_or_a_record(response, recordType, name_key, dns_key):
    try:
        if recordType == 'DNSKEY':
            dns_key, rrsig, name = fetch_dnskey_a_resource_record(response)
            dns.dnssec.validate(dns_key, rrsig, {name: dns_key})
            #Verification Complete of DNSKEYS
            return name, dns_key
        else:
            a_record, rrsig_record_a, name = fetch_dnskey_a_resource_record(response)
            dns.dnssec.validate(a_record, rrsig_record_a, {name_key: dns_key})
            #Verification of A records done succesfully
    except Exception as e:
        tb.print_exc()
        raise e


def zone_verification(org_dnskey, parent_resp, response, zone_type):
    cypher_type = 'SHA256'
    digi_sig, rrsig_digi_sig, ds_name = fetch_ns_ds_resource_record(parent_resp)

    if digi_sig[0].digest_type != 2:
        cypher_type = 'SHA1'

    dnskey, rrsig_key, name_key = fetch_dnskey_a_resource_record(response)
    public_key_sign_key = None
    for element in dnskey:
        if element.flags == 257:
            public_key_sign_key = element
            break

    if public_key_sign_key == None:
        tb.print_exc()
        raise Exception(" Public Key Sign Key not found when required")

    hashed_ds = dns.dnssec.make_ds(ds_name, public_key_sign_key, cypher_type)
    if digi_sig[0] != hashed_ds:
        tb.print_exc()
        raise Exception('Cannot validate/verify public ksk against parent zone DS')

    #Verification completed for given zone

def final_output(status, host, rdtype, dns_resp, duration, when, msg_size):
    if status == EXIST_ANS:
        print("DNSSEC Verification Successful")
        print_result(host, rdtype, dns_resp, duration, when, msg_size)
        print('\n')
    elif status == VERIFY_DNSSEC_CRASH:
        print('\n')
        print('DNSSec Verification failed')
        print('\n')

    elif status == DNSSEC_NOT_EXIST:
        print('\n')
        print('DNSSEC not supported')
        print('\n')

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(" Wrong arguments passed to mydig command. Pass Hostname and RDTYPE for correct output")
    else:
        host = str(sys.argv[1])
        rdtype = str(sys.argv[2])
        begin_time = time.time()
        status, dns_resp = dnssec(host, rdtype, [])
        end_time = time.time()
        when = datetime.now().strftime("%a %b %d %H:%M:%S %Y")

        duration = end_time - begin_time
        final_output(status, host, rdtype, dns_resp, duration, when, len(dns_resp.to_text()))