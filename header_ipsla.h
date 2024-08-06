#ifndef      HEADER_IPSLA
#define      HEADER_IPSLA

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "test_debug.h"
#include "mysql_header.h"

/*
mysql> desc IpSla_Cofiguraion_Parameter;
+----------------+-------------+------+-
| Field          | Type        | Null | 
+----------------+-------------+------+-
| id             | int         | NO   | 
| Profile_name   | varchar(18) | YES  | 
| Probe_mode     | varchar(20) | YES  | 
| Protocol       | varchar(20) | YES  | 
| ICMP_host_en   | int         | YES  | 
| HTTP_host_en   | int         | YES  | 
| DNS_host_en    | int         | YES  | 
| Host1          | varchar(32) | YES  | 
| Host2          | varchar(32) | YES  | 
| Latency        | int         | YES  | 
| Jitter         | int         | YES  | 
| Packet_loss    | int         | YES  | 
| check_interval | int         | YES  | 
| Failure_count  | int         | YES  | 
| Restore_count  | int         | YES  | 
| Enable         | int         | YES  | 
+----------------+-------------+------+-
16 rows in set (0.01 sec)

*/
typedef struct userdata_for_ipsla
{
    short profile_enabled;
    short icmp_h_enable;
    short http_h_enable;
    short dns_h_enable;
    short Latency;
    short Jitter;
    short Packet_loss;
    short check_interval;
    short failure_before_inactive;
    short restore_link_after;
    char *Profile_name;
    char *Probe_mode;
    char *Protocol;
    char *Host1;
    char *Host2;
    char **wan;
    short no_wan;
    short thead_index;
    short int **response_flags;
} userdata;



/*
Pings: 5
Min: 11.548
Max: 24.113
Ave: 17.126
Jitter: 6.480
Loss: 0.0
*/
typedef struct tcp_ping_response
{
    int Pings_count;
    double latency_max;
    double latency_min;
    double latency_average;
    double Jitter;
    double Loss;

}tcp_ping_response;

/*      
-c, --count COUNT    
-p, --port PORT      
-i, --interval SEC   
-s, --skip COUNT     
-t, --timeout SEC    
-I, --interface interface name
*/

typedef struct tcp_ping_parameter_required
{
    int Pings_count_perform;
    int port;
    int interval;
    int Pings_count_skip;
    int timeout;
    char *interface;
    char *host1;
    char *host2;
}requires_tcp_ping_parameter;

typedef struct tcpping_performs_interface
{
    short index;
    tcp_ping_response *ping_response;
    //requires_tcp_ping_parameter requires_tcp_ping;
    userdata input;

}interface_tcpping;

//Global Variables
interface_tcpping **interfaces; 

// Define the opcodes enumeration type
/*+----------------+-------------+------+-
| Field          | Type        | Null | 
+----------------+-------------+------+-
| id             | int         | NO   | 
| Profile_name   | varchar(18) | YES  | 
| Probe_mode     | varchar(20) | YES  | 
| Protocol       | varchar(20) | YES  | 
| ICMP_host_en   | int         | YES  | 
| HTTP_host_en   | int         | YES  | 
| DNS_host_en    | int         | YES  | 
| Host1          | varchar(32) | YES  | 
| Host2          | varchar(32) | YES  | 
| Latency        | int         | YES  | 
| Jitter         | int         | YES  | 
| Packet_loss    | int         | YES  | 
| check_interval | int         | YES  | 
| Failure_count  | int         | YES  | 
| Restore_count  | int         | YES  | 
| Enable         | int         | YES  | 
+----------------+-------------+------+-*/
typedef enum {
    op_profile_enable,
    op_profile,
    op_Probe_mode,
    op_Protocol,
    op_Host1,
    op_Host2,
    op_Latency,
    op_Jitter,
    op_Packet_loss,
    op_check_interval,
    op_failure_before_inactive,
    op_restore_link_after,
    op_icmp_h_enable,
    op_http_h_enable,
    op_dns_h_enable,
    Invalid_Option
} opcodes;

// Define the keyword table structure
static const struct {
    char *name;
    opcodes key;
} keyword_table[] = {
    {"Enable", op_profile_enable},
    {"Profile_name", op_profile},
    {"Probe_mode", op_Probe_mode},  
    {"Protocol", op_Protocol},
    {"Host1", op_Host1},
    {"Host2", op_Host2},
    {"Latency", op_Latency},
    {"Jitter", op_Jitter},
    {"Packet_loss", op_Packet_loss},
    {"check_interval", op_check_interval},
    {"Failure_count", op_failure_before_inactive},
    {"Restore_count", op_restore_link_after},
    {"ICMP_host_en", op_icmp_h_enable},
    {"HTTP_host_en", op_http_h_enable},
    {"DNS_host_en", op_dns_h_enable},
    {NULL, Invalid_Option},
};

//Macros

#define ONE_KB 1024
//tcpping -c 5 -i 0.5 -I enp1s0 -d clean google.com
#define TCP_PING_DEFAULT "tcpping -c 3 -i 0.5 -t 1 -I %s -d clean %s"

// tcpping -c 5 -s 2 -i 0.5 -I enp1s0 -d clean google.com
#define TCP_PING_WITH_SKIP_COUNT " tcpping -c %d -s %d -i %if -I %s -d clean %s"

#define TCP_PING_WITH_TIMEOUT " tcpping -c %d -t %lf -i %if -I %s -d clean %s"


#define TCP_PING_WITH_SKIP_COUNT_TIMEOUT " tcpping -c %d -s %d -t %lf -i %if -I %s -d clean %s"


#define RESPONSE_RESULT_FILE_PATH_TEST "/home/zenadmin/sagar/SDWAN/Ip_Sla/%s.%s"

#define RESPONSE_RESULT_FILE_PATH   "/proc/net/nf_condition/IPSLA%s_%s"


#define CLEAR_IPTABLE_RULE_CHAIN  "for chain in $(iptables -L -n -v --line-numbers -t mangle | grep Chain | grep QnIPSLA@ | cut -d ' ' -f2); do iptables -t mangle -F $chain; iptables -t mangle -X $chain;done"

//1.%s = profile_id 2.profile_id 3.wan interface name 4.wan interface name
#define APPLY_IPTABLE_RULE         "iptables -t mangle -I QnIPSLA@%s -m condition --condition IPSLA%s_%s -j qn%smark -w"

//1.%s = profile_id 2.profile_id
#define CREATE_IPTABLE_RULE_CHAIN   "if ! iptables -t mangle -n -L QnIPSLA@%s &>/dev/null; then     iptables -t mangle -N QnIPSLA@%s; fi"


#define APPLY_IPTABLE_RULE_DEFAULT_ROUTE  "iptables -t mangle -A QnIPSLA@%s -m condition --condition wan_%s -j qn%smark -w"

#define DELETE_IPTABLE_RULE_DEFAULT_ROUTE  "iptables -t mangle -D QnIPSLA@%s -m condition --condition wan_%s -j qn%smark -w"

#define BINARY_FILE_NAME            "Ipsla"
#define CABLE_STATUS_FILE_NAME      "cat /opt/%s.carrier"
#endif /*end of HEADER_IPSLA */
