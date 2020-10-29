#!/usr/bin/python
# -*- coding: utf-8 -*-

from optparse import OptionParser

import re
import sys
import time
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError
from pprint import pprint
# rebuild by Hiepnh21
# Update by Hiepnh21 HT2304200700, HT0206200623

# server info
QUERY_TIME = 300
INDEX = "aarenet_alert-*"
KIBANA_SERVER = '118.70.194.14:9200'
AUTHEN = ('monitor', 'ftel@mon2019')

# AUTHEN = ('sccftel', 'scC@ft3l')
# Status code
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3

# Parsing argurments
parser = OptionParser()

parser.add_option("-H", dest="host", type="string",
                  help="Hostname/IP Address of device", metavar=' ')

(options, args) = parser.parse_args()

# Check for required options
# for option in ('host', 'nameService'):
#   if not getattr(options, option):
#     print 'Option %s not specified' % option
#     parser.print_help()
#     sys.exit(UNKNOWN)

if options.host:
    query_host = options.host
else:
    query_host = '*'
    host = ''


def get_data_log(
        server,
        auth,
        queryTime,
        index,
        host_device,
        errors='errors',
        timeout=3):
    if errors not in ['errors', 'raise', 'ignore']:
        raise ValueError(
            'errors options you need to set: errors, raise, ignore')

    now = time.time()
    # now = 1591012573
    # now = 1571819391.39
    # now = 1572415740.12
    # now = 1572511399.96
    # now = 1572511540.12
    # print now
    past = now - queryTime
    now = int(now * 1000)
    past = int(past * 1000)
    try:
        es = Elasticsearch([server], http_auth=auth, timeout=timeout)
        logMsg = es.search(
            index=index,
            body={
                "from": 0, "size": 1000,
                "query": {

                    "bool": {
                        "must": [
                            {
                                "range": {
                                    "@timestamp": {
                                        "gte": past, "lte": now
                                    }
                                }
                            },

                            {
                                "query_string": {
                                    "default_field": "remote_ip",
                                    "query": host_device,
                                }
                            },
                            {
                                "query_string": {
                                    "fields": ["message"],
                                    "query": "(AlarmLogger) OR (JdbcStatement) OR (LbEndpointUdp) OR (RatingPricelist) OR (TransactionProvider) OR (MediaConnection) OR (MediaServerProvider) OR (MediaServer) OR (TrafficShaper) OR (License) OR (JdbcProfile) OR (AddressHeaderForm) OR (Connection) OR (LbServiceCenter) OR (RestConnection) OR (JdbcLink) OR (SysCompDatabase) OR (\[ERROR\]) OR (aareswitch) OR (JdbcStatement) OR (JdbcConnector) OR (AddressTabbedPane) OR (Call) OR (DalAccessor) OR (CommunicationsException) OR (JdbcLink) OR (Algorithm)"
                                    # "query" : "Mrchu"

                                }
                            }
                            # {
                            #     "query_string": {
                            #         "fields": ["source"],
                            #         "query": "\/hni",
                            #     }
                            # }
                        ]
                    }
                }
            }

        )
    except ConnectionError as e:
        if errors == 'errors':
            print("UNKNOWN - Can't connection to: %s" % server)
            sys.exit(UNKNOWN)
        elif errors == 'raise':
            raise
        else:
            pass
        return None
    else:
        # pprint(logMsg)
        return logMsg


def search_name(pattern_regex, string):
    """ pattern_regex: regex need to match search
        string: input data need to search
    """

    pattern = re.compile(pattern_regex)
    result = pattern.search(string)

    return result


def check_in_message(logMsg):
    message_critical = []
    message_warning = []
    #-----Warning-----#
    # message = "com.mysql.jdbc.exceptions.jdbc4.CommunicationsException: Communications link failure"
    # message = "2020-07-31-16:45:26.798 [WARN ]            TrafficShaper (#5) start shaping: 400 INVITE per second"
    # message = "2020-06-20-00:22:02.754 [ERROR]                 JdbcLink (jd) Could not reconnect to link aareswitch_rating/2"
    #-----Critical-----#
    # message = "2020-04-07-00:13:35.081 [ERROR]                Algorithm (38) Missing configuration for the time slot"

    for row in logMsg['hits']['hits']:
        if "/share/hni/" in row['_source']['source']:   
            message = row['_source']['message']
            if ("not available anymore" in message) or ("loop broken" in message) or ("No Connection could be retrieved" in message) or \
            ("Cannot evalute status" in message) or ("Table 'aareswitch_config.account' doesn't exist" in message) or \
            ("Table 'aareswitch_config.account_rule_map' doesn't exist" in message) or ("[error] error: file not found" in message) or ("server_errno=2013" in message) or \
            ("refreshing mediaserver" in message) or ("replication-check" in message) or ("Cannot persist" in message) or ("Could not reconnect to link aareswitch" in message) or ("Missing configuration" in message) or \
            ("ACK per second" in message) or ("INVITE per second" in message):

                message_critical.append(message)
            elif ("Cannot execute statement" in message) and ("UPDATE siptrunk" in message):
                # print message
                message_warning.append(message)

            elif ("Cannot execute statement" in message) and ("INSERT INTO siptrunk" in message):
                message_warning.append(message)

            elif ("LbEndpointUdp (as) cannot send to device /172.28" in message) or ("No rate found for call at" in message) or \
            ("TransactionProvider (lb) cannot accept further messages" in message) or ("Cannot handle outgoing message" in message) or \
            ("no writer to media-server available" in message) or ("start shaping" in message) or \
            ("license warning" in message) or ("slow execution time" in message) or ("No account found for address" in message) or \
            ("Could not send invite" in message) or ("connection-dispatch" in message) or ("detected fraud call to number" in message) or ("Communications link failure" in message):

                message_warning.append(message)


        else:
            continue

    return message_critical, message_warning


# print logMsg
def main(logMsg):
    if logMsg:

        # messages = (message['_source']['message']
        #             for message in logMsg['hits']['hits'])
        # if not messages:
        #     print('UNKNOWN - There is no messages log on KIBANA')
        #     sys.exit(UNKNOWN)
        msg_critical, msg_warning = check_in_message(logMsg)

    else:
        print('There is no log on kibana for host: %s' % options.host)
        sys.exit(UNKNOWN)

    if msg_critical:
        status = CRITICAL
        # msg = re.sub(r'\s+', ' ', msg_critical[-1])
        lst_crit = [re.sub(r'\s+', ' ', msg_crit) for msg_crit in msg_critical]
        lst_crit.reverse()
        msg = ','.join(lst_crit)
    elif msg_warning:
        status = WARNING
        # msg = re.sub(r'\s+', ' ', msg_warning[-1])
        lst_war = [re.sub(r'\s+', ' ', msg_war) for msg_war in msg_warning]
        lst_war.reverse()
        msg = ','.join(lst_war)
    else:
        status = OK
        msg = 'ALL log OK'
    print({0: 'OK', 1: 'WARNING', 2: 'CRITICAL', '3': UNKNOWN}
          [status] + ' -' + host + '- ' + msg)
    sys.exit(status)


# main(
#     logMsg=get_data_log(
#         KIBANA_SERVER,
#         AUTHEN,
#         QUERY_TIME,
#         INDEX,
#         host_device=query_host))

-------- Used to test---------#
logMsg = {
        u'_shards': {u'failed': 0, u'skipped': 0, u'successful': 6, u'total': 6},
        u'hits': {
                u'hits': [{
                            u'_id': u'Mt9BYnQBuyhWyXgolL2j',
                            u'_index': u'aarenet_alert-2020.09',
                            u'_score': 5.8225527000000001,
                            u'_source': {u'@timestamp': u'2020-09-06T07:11:38.343Z',
                                   u'@version': u'1',
                                   u'input': {u'type': u'log'},
                                   #u'message': u'2020-08-23-17:21:30.105 148 sc1428014868178 [ALARM][CALL][ROUTE] detected fraud call to number 0978915678 by account HNVO11218_Viettel_2',
                                   #-----Ok-----#
                                   # u'message': u'',

                                   #-----Warning-----#
                                   # u'message': u'com.mysql.jdbc.exceptions.jdbc4.CommunicationsException: Communications link failure',
                                   #-----Critical-----#
                                   u'message': u'2020-04-07-00:13:35.081 [ERROR]                Algorithm (38) Missing configuration for the time slot',
                                   # u'message': u'2020-06-20-00:22:02.754 [ERROR]                 JdbcLink (jd) Could not reconnect to link aareswitch_rating/2',
                                   # u'message': u'2020-07-31-16:45:26.798 [WARN ]            TrafficShaper (#5) start shaping: 400 INVITE per second',
                                   #u'message': '2020-07-31-14:42:26.907 [WARN ]            TrafficShaper (#5) start shaping: 500 ACK per second',

                                   u'offset': 13366414,
                                   u'prospector': {u'type': u'log'},
                                   u'remote_ip': u'172.31.14.161',
                                   u'source': u'/share/hni/sc01/servicecenter/alarm.log',
                                   u'tags': [u'_grokparsefailure'],
                                   u'type': u'scc'},
                      u'_type': u'doc'}],
            u'max_score': 6.3635335,
            u'total': 2487},
 u'timed_out': False,
 u'took': 7}

main(logMsg)

# if __name__ == "__main__":
#     # messages = ["JdbcStatement (58) Cannot execute statement 'com.mysql.jdbc.JDBC4PreparedStatement@4c535ad6: INSERT INTO siptrunk (GROUP_ID,NAME,INFO,FLAGS,SIP_CONTACT,EP_ID,USER_AGENT,Q,ROUTE1,ROUTE2) VALUES(2,'183.80.190.215-Asterisk-SCC-Test1','183.80.190.215-Asterisk-SCC-Test1',8,'sip:183.80.190.215:5060',5,'Dialogic',1000,'sip:172.28.0.12:5060','sip:118.69.115.150:5060')'", "yellow 2019-07-02-15:11:46.572 [ERROR]                  License (ue) license warning: 'owner' is 'unknown' (expected is 'FPT2 by AareNet, FPT')", "2019-07-02-15:16:46.601 [WARN ]                  License (ue) grace time remaining: 03:49:59"]
#     messages = ["[INFO ] JdbcProfile (-9) slow execution time: 10744ms: SELECT * FROM rule WHERE RULESET_ID = 41", "JdbcStatement (13) Cannot execute statement 'com.mysql.jdbc.JDBC4PreparedStatement@2e299916: UPDATE siptrunk SET GROUP_ID=2,NAME='111.111.110.179:10000_Pri_MPLS_SBC-HCM',INFO='SIP Trunk Profile SGVO04297 HOMECREDIT IP-1.1.0.179:5060_Pri_MPLS_SBC-"]
#     critical, warning = check_in_message(messages)
#     print('WARNING: ', warning, '\n', len(warning))
#     print('CRITICAL:', critical, '\n', len(critical))
