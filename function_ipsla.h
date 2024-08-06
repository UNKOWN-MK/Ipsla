#ifndef FUNCTION_IPSLA
#define FUNCTION_IPSLA

#include "header_ipsla.h"
#include "IpSla_healper_function.h"




opcodes get_opcode_flied_name(const char * flied)
{
    for (int i = 0; keyword_table[i].name; i++) {
		if (strcasecmp(flied, keyword_table[i].name) == 0) {
			return keyword_table[i].key;
		}
	}
    printf("Error: Invalid key === %s\n",flied);

    return Invalid_Option;

}


int read_ipSla_user_input(MYSQL *db)
{
       //SELECT * FROM your_table_name WHERE BGP_ID = 2;
    char query[200];
     int num_rows =0;
    snprintf(query,199,"SELECT * FROM %s","IpSla_Cofiguraion_Parameter");

     if(execute_query(db,query))
        {
            MYSQL_RES *result = mysql_store_result(db);
            if (result == NULL)
            {
                finish_with_error(db);
            }
 
            num_rows = mysql_num_rows(result);
            int num_cols = mysql_num_fields(result);
 
            if (num_rows == 0)
            {
                printf("No rows found\n");
                mysql_free_result(result);
                return 0;
            }
            interfaces = (interface_tcpping **)malloc(sizeof(interface_tcpping *) * num_rows);
            if(interfaces == NULL)
            {
                 perror("network memory allocation failed: ");
                 return 0;
            }
 
            int row_index = 0;
            MYSQL_ROW row;
            MYSQL_FIELD *field;
 
            while ((row = mysql_fetch_row(result)))
            {
                interfaces[row_index] = (interface_tcpping *)malloc(sizeof(interface_tcpping));
                interfaces[row_index]->index = row_index;
                for (int i = 0; i < num_cols; i++)
                {
                    
                    field = mysql_fetch_field_direct(result, i);
                    int op = get_opcode_flied_name(field->name);
                    if(op == Invalid_Option)
                    {
                        continue;
                    }

                    switch (op)
                    {
                    case op_profile:
                        interfaces[row_index]->input.Profile_name = strdup(row[i] ? row[i] : "NULL");
                        TEST_PRINT("profile_name ===> %s\n",interfaces[row_index]->input.Profile_name);
                        break;
                    case op_Probe_mode:
                        interfaces[row_index]->input.Probe_mode = strdup(row[i] ? row[i] : "NULL");
                        TEST_PRINT("probe mode ===> %s\n",interfaces[row_index]->input.Probe_mode);
                        break;
                    case op_Protocol:
                        interfaces[row_index]->input.Protocol = strdup(row[i] ? row[i] : "NULL");
                        TEST_PRINT("protocol ===> %s\n",interfaces[row_index]->input.Protocol);
                        break;
                    case op_Host1:
                        interfaces[row_index]->input.Host1 = strdup(row[i] ? row[i] : "NULL");
                        TEST_PRINT("host1 ===> %s\n",interfaces[row_index]->input.Host1);
                        break;
                    case op_Host2:
                        interfaces[row_index]->input.Host2 = strdup(row[i] ? row[i] : "NULL");
                        TEST_PRINT("host2 ===> %s\n",interfaces[row_index]->input.Host2);
                        break;
                    case op_Latency:
                        interfaces[row_index]->input.Latency = (unsigned) (short) atoi(row[i] ? row[i] : "0");
                        TEST_PRINT("Latency ===> %d\n",interfaces[row_index]->input.Latency);
                        break;
                    case op_Jitter:
                        interfaces[row_index]->input.Jitter = (unsigned) (short) atoi(row[i] ? row[i] : "0");
                        TEST_PRINT("Latency ===> %d\n",interfaces[row_index]->input.Jitter);
                        break;
                    case op_Packet_loss:
                        interfaces[row_index]->input.Packet_loss = (unsigned) (short) atoi(row[i] ? row[i] : "0");
                        TEST_PRINT("Packet_loss ===> %d\n",interfaces[row_index]->input.Packet_loss);
                        break;
                     case op_check_interval:
                        interfaces[row_index]->input.check_interval = (unsigned) (short) atoi(row[i] ? row[i] : "0");
                        TEST_PRINT("check_interval ===> %d\n",interfaces[row_index]->input.check_interval);
                        break;
                    case op_restore_link_after:
                        interfaces[row_index]->input.restore_link_after = (unsigned) (short) atoi(row[i] ? row[i] : "0");
                        TEST_PRINT("restore_link_after ===> %d\n",interfaces[row_index]->input.restore_link_after);
                        break;
                    case op_failure_before_inactive:
                        interfaces[row_index]->input.failure_before_inactive = (unsigned) (short) atoi(row[i] ? row[i] : "0");
                        TEST_PRINT("failure_before_inactive ===> %d\n",interfaces[row_index]->input.failure_before_inactive);
                        break;
                     case op_profile_enable:
                        interfaces[row_index]->input.profile_enabled = (unsigned) (short) atoi(row[i] ? row[i] : "0");
                        TEST_PRINT("profile_enabled ===> %d\n",interfaces[row_index]->input.profile_enabled);
                        break;
                     case op_icmp_h_enable:
                        interfaces[row_index]->input.icmp_h_enable = (unsigned) (short) atoi(row[i] ? row[i] : "0");
                        TEST_PRINT("icmp_h_enable ===> %d\n",interfaces[row_index]->input.icmp_h_enable);
                        break;
                     case op_http_h_enable:
                        interfaces[row_index]->input.http_h_enable = (unsigned) (short) atoi(row[i] ? row[i] : "0");
                        TEST_PRINT("http_h_enable ===> %d\n",interfaces[row_index]->input.http_h_enable);
                        break;
                     case op_dns_h_enable:
                        interfaces[row_index]->input.dns_h_enable = (unsigned) (short) atoi(row[i] ? row[i] : "0");
                        TEST_PRINT("dns_h_enable ===> %d\n",interfaces[row_index]->input.dns_h_enable);
                        break;
                    default:
                        break;
                    }

                }
             row_index++;
         }
        
         mysql_free_result(result);
        }
                                                     
    return num_rows;

}

int read_participation_wan_interfaces(MYSQL *mysql, int index)
{

#ifndef TEST
    char query[200],tmp[ONE_KB/12] = {0},port[10] = {0};
    int num_rows =0;
    snprintf(query,199,"select Wan_port_no from IPSla_Wan where ProfileID ='%s' AND connection_usage=1",interfaces[index]->input.Profile_name);

     if(execute_query(mysql,query))
     {
        MYSQL_RES *result = mysql_store_result(mysql);
            if (result == NULL)
            {
                finish_with_error(mysql);
            }
 
        num_rows = mysql_num_rows(result);
        MYSQL_ROW row;

        interfaces[index]->input.wan = (char **)malloc(num_rows * sizeof(char *));
        if(interfaces[index]->input.wan == NULL)
        {
            printf("Couldn't allocate memory for wan\n");
            return 0;
        }
        int i=0;
        while ((row = mysql_fetch_row(result)))
        {
            strcpy(port,row[0] ? row[0] : "NULL");
            TEST_PRINT("wan == %s\n",port);
            if(strcmp(port,"NULL") != 0)
            {
                strcpy(tmp,get_interface_name(port,tmp));
                if(tmp == NULL)
                {
                    printf("Couldn't get wan name\n");
                    return 0;
                }
                interfaces[index]->input.wan[i] = strdup(tmp);
                TEST_PRINT_2("wan == %s\n",interfaces[index]->input.wan[i])
            }
            i++;  
            memset(tmp,0,sizeof(tmp)); 
        }
     }
     interfaces[index]->input.no_wan = num_rows;
     return num_rows;
#endif

#ifdef TEST
#warning "TESTING IS ENABLE"
        interfaces[index]->input.wan = (char **)malloc(2 * sizeof(char *));
        if(interfaces[index]->input.wan == NULL)
        {
            printf("Couldn't allocate memory for wan\n");
            return 0;
        }
        interfaces[index]->input.wan[0] = strdup("enp1s0");
        interfaces[index]->input.wan[1] = strdup("wlp2s0");
        interfaces[index]->input.no_wan = 2;
        return 2;
#endif

}

int ICMP_tcp_ping(userdata *Data,int thread_index)
{
        TEST_PRINT("icmp method == %s\n",Data->wan[thread_index]);
        char *ip =NULL,cmd[ONE_KB] ={0};
        tcp_ping_response response_result;
        int response =0,fail =0,success =0;
        short applay_rule_flag=1;
		if (Data->icmp_h_enable == 0 )
		{
			update_isp_dns(Data->wan[thread_index],Data);
			
		}	
		while(1)
		{
			//ip=get_ipaddr(Data->wan[index]);
			//TEST_PRINT_2("Running Thread for Profile: %s Wan: %s\n",Data->Profile_name,Data->wan[thread_index]);
			snprintf(cmd, sizeof(cmd), TCP_PING_DEFAULT,Data->wan[thread_index],Data->Host1);
			//printf("%s\n",cmd);	
            //check wan cable connection
            if(check_wan_cable_status(Data->wan[thread_index]) == 0)
            {
                TEST_PRINT_2("no cable connection : %s\n",Data->wan[thread_index]);
                Negative_Response(Data,Data->wan[thread_index],thread_index);

               /*if(applay_rule_flag == 0)
                {
                    char cmd[ONE_KB/8] = {0};
                    snprintf(cmd, sizeof(cmd),DELETE_IPTABLE_RULE_DEFAULT_ROUTE,Data->Profile_name,Data->wan[thread_index],Data->wan[thread_index]);
                    excute_command(cmd);
                    applay_rule_flag =1;
                }*/   
            }
            else
            {
                response = read_tcp_ping_response_parameters(Data,&response_result,cmd);//read the tcp ping response from primary server

			    if(response == 1) //if the response is negative the try with secondary server
			    {
				    //TEST_PRINT_2("Checking for host2...host1 fail = %s\n",Data->Host1);
				    snprintf(cmd, sizeof(cmd), TCP_PING_DEFAULT,Data->wan[thread_index],Data->Host2);
		
				    response =read_tcp_ping_response_parameters(Data,&response_result,cmd);;
			    }
			    if (response == 0)
                {
                    fail=0;
                    if(success != Data->restore_link_after)
                        success++;
                }
			    else
                {
                    success =0;
				    if(fail != Data->failure_before_inactive)
						    fail++;
			    }
			
			    if ( fail == Data->failure_before_inactive)
			    {
				    Negative_Response(Data,Data->wan[thread_index],thread_index);
			    }
			    else if (success == Data->restore_link_after)
                {
                    Positive_Response(Data,Data->wan[thread_index],thread_index);
                }
               
            }

             if(applay_rule_flag == 1)
                {   //TEST_PRINT_2("checking .. for %s %s\n",Data->Profile_name,Data->wan[thread_index]);
                    for(int i=0; i<Data->no_wan; i++)
                    {
                        short tmp = *(Data->response_flags[i]);
                        applay_rule_flag = applay_rule_flag & tmp;
                    }
                    if(applay_rule_flag == 1)
                    {
                        char cmd[ONE_KB/8] = {0};
                        snprintf(cmd, sizeof(cmd),APPLY_IPTABLE_RULE_DEFAULT_ROUTE,Data->Profile_name,Data->wan[thread_index],Data->wan[thread_index]);
			TEST_PRINT_2("command = %s\n",cmd);
                        excute_command(cmd);
                        TEST_PRINT_2("default rule applied\n");
                        applay_rule_flag = 0;
                    }
                    else
                    {
                        applay_rule_flag = 1;
                    }
                }
            
			sleep(Data->check_interval);
		}
}

int run_thread_based_on_method_Ipsla(userdata *Data,int thread_index)
{
    if (strcasecmp(Data->Protocol,"ping") == 0)
    {
         ICMP_tcp_ping(Data,thread_index);
    }
    else if(strcasecmp(Data->Protocol,"HTTP") == 0)
    {
        //HTTP_tcp_ping(Data);
    }
    else if(strcasecmp(Data->Protocol,"DNS") == 0)
    {
        //DNS_tcp_ping(Data);
    }
    else
    {
        return -1;
    }

    return 0;
}



#endif /*end of function_ipsla*/
