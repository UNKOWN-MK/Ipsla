
#include "function_ipsla.h"
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/types.h>

typedef struct
{
    int thread_index;
    userdata use_data;
}process_And_thread_seq;


pid_t **process;
int no_profile = 0;

void sigint_handler(int signum)
{
    for(int i = 0; i < no_profile;i++)
    {
        if (*process[i] > 0)
        {
            kill(*process[i],SIGKILL);
        }
        waitpid(*process[i], NULL, 0);
    }
    //kill()
}



void *running_thread(void * userInput)
{
    process_And_thread_seq *thread_seq = (process_And_thread_seq *)userInput;
    TEST_PRINT("Initial  %s thread_seq->thread_index =%d\n",thread_seq->use_data.wan[thread_seq->thread_index],thread_seq->thread_index);
    run_thread_based_on_method_Ipsla(&thread_seq->use_data,thread_seq->thread_index);
    
}


int process_for_profile(interface_tcpping *profile)
{
    TEST_PRINT_2("Process Id of %s : %d\n",profile->input.Profile_name,getpid());

    pthread_t thread_wan[profile->input.no_wan];
    process_And_thread_seq seq_thread[profile->input.no_wan];

    /*response flags array memory allocation the respone flags array is use for applying rule in iptable
    In case both wan are giving -ve response the then there must a rule for default route and this default rule is must be
    below the main rule so that this response flags array tracks that the main rules are applied or not 
    */
    profile->input.response_flags = (short **)malloc(sizeof(short *) * profile->input.no_wan);
    if(profile->input.response_flags == NULL)
    {
        return -1;
    }
    for(int i=0;i<profile->input.no_wan;i++)
    {
        profile->input.response_flags[i] = (short *)malloc(sizeof(short));
        if(profile->input.response_flags[i] == NULL)
        {
            return -1;
        }
        *(profile->input.response_flags[i]) = 0;
    }
    for(int i = 0; i < profile->input.no_wan; i++)
    {
        //profile->input.thead_index = i;
        //process_And_thread_seq seq_thread;
        seq_thread[i].thread_index =i;
        seq_thread[i].use_data = profile->input;
        pthread_create(&thread_wan[i], NULL, running_thread,(void *)&seq_thread[i]);
        TEST_PRINT("Initial running thread -%d for %s\n", i, profile->input.wan[i]);
    }
    for(int i = 0; i < profile->input.no_wan; i++)
    {   
        pthread_join(thread_wan[i], NULL);
    }


   
}

int main(int argc, char **argv)
{
    //read_tcp_ping_response_parameters(0);
    MYSQL *con =NULL;

    con = connect_mysql(con);
    if(con == NULL)
    {
        printf("connect_mysql failed\n");
        return 0;
    }

   no_profile = read_ipSla_user_input(con);
   if(no_profile)
   {
          for(int i = 0; i <no_profile; i++)
          {
             read_participation_wan_interfaces(con,interfaces[i]->index);
          }
          for(int i = 0; i < no_profile; i++)
          {
            TEST_PRINT("profile : %d\n",i);
            for(int j = 0; j < interfaces[i]->input.no_wan;j++)
            {
                 TEST_PRINT_2("profile wan : %s\n",interfaces[i]->input.wan[j]);
            }

          }
   }
   else
   {
        printf("Error : no profile found\n");
        return 0;
   }



   //Creating for Process for each profile
#if 1
 #ifndef TEST
    //clean iptable rule chain before new configuration write
    if(system(CLEAR_IPTABLE_RULE_CHAIN) == -1)
    {
        sleep(1);
        perror("Unable to clean IPtable rule chain trying ... : ");
        if(system(CLEAR_IPTABLE_RULE_CHAIN) == -1)
        {
            perror("Unable to clean IPtable rule chain: ");
            return -1;
        }
    }
    kill_previous_running_process();
 #endif
    signal(SIGINT, sigint_handler);
    TEST_PRINT_2("main process id : %d\n",getpid());
    process = (pid_t **) malloc(sizeof(pid_t *) *no_profile);
    if(process == NULL)
    {
        return -1;
    }
   for(int i = 0; i < no_profile; i++)
   {
        process[i]= (pid_t *) malloc(sizeof(pid_t));
        if(process[i] == NULL)
        {
            return -1;
        }
        if((*process[i] = fork()) == 0)
        {
            // This code runs in the child process
            signal(SIGINT, SIG_DFL);
            process_for_profile(interfaces[i]);
            exit(EXIT_SUCCESS);
        }
       
   } 
    for (int i = 0; i < no_profile; ++i)
    {
        int status;
        if (waitpid(*process[i], &status, 0) == -1)
        {
            perror("waitpid");
        }
        else
        {
            // Check the exit status of the child process if necessary
            if (WIFEXITED(status)) {
                printf("Child process %d exited with status %d\n", *process[i], WEXITSTATUS(status));
            } else {
                printf("Child process %d exited abnormally\n", *process[i]);
            }
        }
    }
#endif



    return 0;
}