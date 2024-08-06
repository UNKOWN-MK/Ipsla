#ifndef IPSLA_HEALPER_FUNCTIONS
#define IPSLA_HEALPER_FUNCTIONS


#include "header_ipsla.h"


/*
excute_command_return_first_string is used to excute a command and 
it returns the first string output from the command output stream
*/
char *excute_command_return_first_string(const char * cmd,char *res)
{
    FILE *f = popen(cmd, "r");
    if(!f)
    {
        perror("command execution failed in get_interface_name : ");
        return NULL;
    }

    while (fgets(res,ONE_KB/8,f));
    res[strcspn(res, "\n")] = '\0';
    TEST_PRINT("command output : %s\n",res);

    pclose(f);
    return res;

}
/*
Excute the command without taking the output stream
*/
int excute_command(const char *cmd)
{
    if(system(cmd) == -1)
    {
        sleep(1);
        if(system(cmd) == -1)
        {
            perror("Unable to clean IPtable rule chain: ");
            return -1;
        }
    }
    return 0;
}

char *get_interface_name(char const * port,char *res)
{
    char cmd[ONE_KB] = {0},tmp[ONE_KB/12] = {0};
    snprintf(cmd, ONE_KB-1," mysql -u root -D sdwan -e \"SELECT LinkMethod from wan_configuration where InterfacePort='%s'\" -B --column-names=0",port);
    strcpy(tmp,excute_command_return_first_string(cmd,tmp));

    if(strcasecmp(tmp,"pppoe") == 0)
    {
        strcpy(res,"pppoe-");
    }
    memset(cmd,0,sizeof(cmd));
    memset(tmp,0,sizeof(tmp));
    snprintf(cmd, ONE_KB-1," mysql -u root -D sdwan -e \"SELECT PortName from Interface where Port='%s'\" -B --column-names=0",port);
    strcpy(tmp,excute_command_return_first_string(cmd,tmp));
    if(tmp[0] != '\0')
    {
        TEST_PRINT("NAME WAN tmp : %s\n",tmp);
        strcat(res,tmp);
        TEST_PRINT("NAME WAN : %s\n",res);
    }
    else
    {
        printf("Error: Unable find wan name\n");
        return NULL;
    }
    memset(cmd,0,sizeof(cmd));
    memset(tmp,0,sizeof(tmp));
    snprintf(cmd, ONE_KB-1," mysql -u root -D sdwan -e \"SELECT EnableVLAN from wan_configuration where InterfacePort='%s'\" -B --column-names=0",port);
    
    if(1 == atoi(excute_command_return_first_string(cmd,tmp)))
    {
        memset(cmd,0,sizeof(cmd));
        memset(tmp,0,sizeof(tmp));
        snprintf(cmd, ONE_KB-1,"mysql -u root -D sdwan -e \"SELECT VlanId from wan_configuration where InterfacePort='%s'\" -B --column-names=0",port);
        strcpy(tmp,excute_command_return_first_string(cmd,tmp));
        strcat(res,".");
        strcat(res,tmp);
    }
    return res;

}


/*******************************************************************************************
When user don't provide the primary and secondary Host address in that case update_isp_dns
function will be called to get the default host address from /tmp/interface_name.dns file
*********************************************************************************************/
void update_isp_dns(char const *interface,userdata *p_response)
{
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;int dnscnt=0;
    char *dnsfile;
    dnsfile=(char*)malloc(sizeof(char)*50);
    strcpy(dnsfile,"/tmp/");
    strcat(dnsfile,interface);
    strcat(dnsfile,".dns");
    fp = fopen(dnsfile, "r");
    if (fp == NULL)
            exit(EXIT_FAILURE);

    while ((read = getline(&line, &len, fp)) != -1)
    {
        dnscnt++;
        line[strlen(line)-1]='\0';

        if (line)
        {
                if(dnscnt==1)
                        strcpy(p_response->Host1,line);
                if(dnscnt==2)
                        strcpy(p_response->Host2,line);
        }
    }
    fclose(fp);
    if (line)
        free(line);

}
/************************************************************************************************
read_tcp_ping_response_parameters function performs tcpping and the compare the response with the
user set threshold if it matches the threshold then returns 0 otherwise returns 1
*************************************************************************************************/
int read_tcp_ping_response_parameters(userdata *Data,tcp_ping_response *p_response,char *cmd)
{
    FILE * file = popen(cmd,"r");

    char buffer[ONE_KB/8] = {0},key[ONE_KB/12] = {0},value[ONE_KB/12] = {0};

    if(!file)
    {
        perror("tcpping cmd failed: ");
        return -1;
    }
    while (fgets(buffer,ONE_KB/8,file) != NULL)
    {
        sscanf(buffer,"%s %s", key, value);

        key[strcspn(key,":")] = '\0';
        key[strcspn(key,"\n")] = '\0';
        value[strcspn(value,":")] = '\0';
        value[strcspn(value,"\n")] = '\0';

        if(strcasecmp(key,"Pings") == 0)
        {
            p_response->Pings_count = atoi(value);
        }
        else if(strcasecmp(key,"Ave") == 0)
        {
            p_response->latency_average = atof(value);
        }
        else if(strcasecmp(key,"Jiter") == 0)
        {
            p_response->Jitter = atof(value);
        }
        else if(strcasecmp(key,"Loss") == 0)
        {
            p_response->Loss = atof(value);
        }

    }
    pclose(file);
    if(p_response->Loss == 100)
    {
        return 1;
    }
    else if(p_response->Loss <= Data->Packet_loss && p_response->Jitter <= Data->Jitter && p_response->latency_average <= Data->Latency)
    {
        return 0;
    }
    return 1;
    
}

void Negative_Response(userdata *p_response,char *wan,int index)
{
    char file_path[ONE_KB/8] ={0},cmd[ONE_KB/6] ={0};

#ifndef TEST
    snprintf(file_path,ONE_KB/8,RESPONSE_RESULT_FILE_PATH,p_response->Profile_name,wan);
    if(access(file_path,R_OK) == 0)
    {
         //*(p_response->response_flags[p_response->thead_index]) =0;
        snprintf(cmd,ONE_KB/6,"echo 0 > %s",file_path);
        if(excute_command(cmd) != 0)
        {
            printf("Error: command failed of file write\n");
        }
    }
    else
    {
        snprintf(cmd,ONE_KB/6,CREATE_IPTABLE_RULE_CHAIN,p_response->Profile_name,p_response->Profile_name);
        if(excute_command(cmd) != 0)
        {
            printf("Error: command failed of iptable rule chain\n");
        }
        //APPLY_IPTABLE_RULE
	TEST_PRINT_2("APPLYING RULE MAIN NEGATIVE \n");
        snprintf(cmd,ONE_KB/6,APPLY_IPTABLE_RULE,p_response->Profile_name,p_response->Profile_name,wan,wan);
	TEST_PRINT_2("cmd = %s\n",cmd);
        if(excute_command(cmd) != 0)
        {
            printf("Error: command failed of iptable rule apply\n");
        }
        *(p_response->response_flags[index]) =1;
        snprintf(cmd,ONE_KB/6,"echo 0 > %s",file_path);
        system(cmd);
    }
#endif


#ifdef TEST
    snprintf(file_path,ONE_KB/8,RESPONSE_RESULT_FILE_PATH_TEST,p_response->Profile_name,wan);
    if(access(file_path,R_OK) == 0)
    {
        snprintf(cmd,ONE_KB/6,"echo 0 > %s",file_path);
        system(cmd);
    }
    else
    {
        snprintf(cmd,ONE_KB/6,"touch %s",file_path);
        system(cmd);
        snprintf(cmd,ONE_KB/6,"echo 0 > %s",file_path);
        system(cmd);
    }
#endif
}
void Positive_Response(userdata *p_response,char *wan,int index)
{
    char file_path[ONE_KB/8] ={0},cmd[ONE_KB/6] ={0};

#ifndef TEST
    snprintf(file_path,ONE_KB/8,RESPONSE_RESULT_FILE_PATH,p_response->Profile_name,wan);
    if(access(file_path,R_OK) == 0)
    {
       // *(p_response->response_flags[p_response->thead_index]) =0;
        snprintf(cmd,ONE_KB/6,"echo 1 > %s",file_path);
        if(excute_command(cmd) != 0)
        {
            printf("Error: command failed of file write\n");
        }
    }
    else
    {
        snprintf(cmd,ONE_KB/6,CREATE_IPTABLE_RULE_CHAIN,p_response->Profile_name,p_response->Profile_name);
        if(excute_command(cmd) != 0)
        {
            printf("Error: command failed of iptable rule chain\n");
        }
        //APPLY_IPTABLE_RULE
	TEST_PRINT_2("APPLYING RULE MAIN POSITIVE \n");
        snprintf(cmd,ONE_KB/6,APPLY_IPTABLE_RULE,p_response->Profile_name,p_response->Profile_name,wan,wan);
	TEST_PRINT_2("cmd = %s\n",cmd);
        if(excute_command(cmd) != 0)
        {
            printf("Error: command failed of iptable rule apply\n");
        }
        *(p_response->response_flags[index]) =1;
        snprintf(cmd,ONE_KB/6,"echo 1 > %s",file_path);
        system(cmd);
    }
#endif


#ifdef TEST
    snprintf(file_path,ONE_KB/8,RESPONSE_RESULT_FILE_PATH_TEST,p_response->Profile_name,wan);
    if(access(file_path,R_OK) == 0)
    {
        snprintf(cmd,ONE_KB/6,"echo 1 > %s",file_path);
        system(cmd);
    }
    else
    {
        snprintf(cmd,ONE_KB/6,"touch %s",file_path);
        system(cmd);
        snprintf(cmd,ONE_KB/6,"echo 1 > %s",file_path);
        system(cmd);
    }
#endif
}


int kill_previous_running_process()
{
    char command[ONE_KB/12] ={0},res[ONE_KB/16] ={0};
    snprintf(command,ONE_KB/12,"pgrep -x %s",BINARY_FILE_NAME);

    int current_process = getpid();

    FILE *file = fopen(command,"r");
    if(file == NULL)
    {
        printf("no such process %s",command);
        perror("Failed to open command kill:");
        return -1;
    }
    while(fgets(res,sizeof(res),file))
    {
        res[strcspn(res,"\n")] = '\0';
        if((int)current_process != atoi(res))
        {
            TEST_PRINT_2("killing process %s\n",res);
            sprintf(command,"kill -2 %s",res);
            system(command);
        }
    }
    pclose(file);
}


int check_wan_cable_status(char *wan_name)
{
    char command[ONE_KB/12] ={0};
    sprintf(command,CABLE_STATUS_FILE_NAME,wan_name);
    FILE *file = popen(command,"r");

    if(!file)
    {
        perror("Unable to execute cable status cmd:");
        //pclose(file);
        return 1;
    }
    char res[10];
    while(fgets(res,sizeof(res),file) != NULL)
    {
        res[strcspn(res,"\n")] = '\0';
        if(atoi(res) == 0)
        {
            TEST_PRINT_2("CABLE UNPLUG %s\n",wan_name);
            pclose(file);
            return 0;
        }
        else if(atoi(res) == 1)
        {
            pclose(file);
            return 1;
        }
    }
    return 1;
    pclose(file);
}
#endif /* IPSLA_HEALPER_FUNCTIONS */
