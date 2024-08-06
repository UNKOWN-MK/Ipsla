#ifndef MYSQL_HEADER
#define MYSQL_HEADER
#include <mysql/mysql.h>
#include <stdio.h>



#define TABLE_NAME "IpSla_Cofiguraion_Parameter"

typedef struct  mysql_conf
{
  char host[50];
  char username[50];
  char password[50];
  char database[50];
}mysql_conf;

void finish_with_error(MYSQL *con)
{
  fprintf(stderr, "%s\n", mysql_error(con));
  mysql_close(con);
  exit(1);
}
int execute_query(MYSQL *con, char *query)
{
     if (mysql_query(con, query))
     {
        finish_with_error(con);
        return 0;
     }
     return 1;

}
MYSQL * connect_mysql(MYSQL *con)
{
  con = mysql_init(NULL);
   if (con == NULL)
    {
        fprintf(stderr, "%s\n", mysql_error(con));
        exit(1);
    }

    if (mysql_real_connect(con, "localhost", "admin", "sagar@123456r",
          "sdwan", 0, NULL, 0) == NULL)
    {
        finish_with_error(con);
    }
    return con;
}

#endif
