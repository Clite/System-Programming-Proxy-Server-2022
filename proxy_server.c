#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>
#include <pwd.h>
#include <fcntl.h>            // For open()
#include <netdb.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/sha.h>	    // SHA1()
#include <pthread.h>

#define BUFFSIZE 1024
#define MSGBUFF 16384           // BIGBUFFER
#define PORTNO 39999            // Port no. for browser connection
#define HTTPPORT 80             // Port no. for web server connection(HTTP)

///////////////////////////////////////////////////////////////////////
// File Name : proxy_server.c
// Os : Ubuntu 16.04.5
// Author : Clite
// -----------------------------------------------------------------
// Description : Networking with web browser client & web server
//               When host name of browser request is HIT, send response msg in cache file
//               If not, get response msg from web server
//		 In this assignment, use semaphore
//	         for just one process can access the log file
//               And use thread for parallelism
///////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////
// p
// =================================================================
// input : int semid -> semaphore ID
// -----------------------------------------------------------------
// output : None
// -----------------------------------------------------------------
// purpose : Set semaphore to unavailable
///////////////////////////////////////////////////////////////////////
void p(int semid)
{
    struct sembuf pbuf = {0, -1, SEM_UNDO};
    if((semop(semid, &pbuf, 1)) == -1)
    {
        perror("p : semop failed");
        exit(1);
    }
}

///////////////////////////////////////////////////////////////////////
// v
// =================================================================
// input : int semid -> semaphore ID
// -----------------------------------------------------------------
// output : None
// -----------------------------------------------------------------
// purpose : Set semaphore to available
///////////////////////////////////////////////////////////////////////
void v(int semid)
{
    struct sembuf vbuf = {0, 1, SEM_UNDO};
    if((semop(semid, &vbuf, 1)) == -1)
    {
        perror("v : semop failed");
        exit(1);
    }
}

///////////////////////////////////////////////////////////////////////
// getHomeDir
// =================================================================
// input : char* home -> empty(or else) char* pointer
// -----------------------------------------------------------------
// output : char* home -> user's home directory, if succeed
// -----------------------------------------------------------------
// purpose : get home directory
///////////////////////////////////////////////////////////////////////
char* getHomeDir(char* home)
{
  struct passwd *usr_info = getpwuid(getuid());
  strcpy(home,usr_info->pw_dir);

  return home;
}

///////////////////////////////////////////////////////////////////////
// sha1_hash
// =================================================================
// input : char* input_url -> input url
//         char* hashed_url -> empty, or else char* pointer
// -----------------------------------------------------------------
// output : char* hashed_url -> hashed input url in hexadecimal
// -----------------------------------------------------------------
// purpose : get hashed url
///////////////////////////////////////////////////////////////////////
char* sha1_hash(char* input_url, char* hashed_url)
{
  unsigned char hashed_160bits[20];
  char hashed_hex[41];
  int i;

  SHA1((unsigned char*)input_url,strlen(input_url),hashed_160bits); // hash
  
  // SHA1 함수의 결과 각 byte는 bit단위의 결과가 저장되므로 0x00~0xff의 data가 있을 수 있음
  // 이를 순수히 16진수로 나타내기 위해 두 바이트에 0x00~0xff의 값을 들어가게 함
  for(i=0;i<sizeof(hashed_160bits);i++)
    sprintf(hashed_hex + i*2, "%02x", hashed_160bits[i]);
  
  // copy hashed hexa url
  strcpy(hashed_url,hashed_hex);
  return hashed_url;
}

///////////////////////////////////////////////////////////////////////
// handler
// =================================================================
// input : interrupt signal - SIGCHLD
// -----------------------------------------------------------------
// output : None
// -----------------------------------------------------------------
// purpose : Verify that client connected with the sub server process is terminated
///////////////////////////////////////////////////////////////////////
static void handler()
{
    pid_t pid;
    int status;
    while((pid = waitpid(-1, &status, WNOHANG)) > 0);
}

///////////////////////////////////////////////////////////////////////
// alrm_handler
// =================================================================
// input : interrupt signal - SIGARLM
// -----------------------------------------------------------------
// output : None
// -----------------------------------------------------------------
// purpose : Print no response on stdout & terminate process when alarm on
///////////////////////////////////////////////////////////////////////
static void alrm_handler()
{
    write(STDOUT_FILENO, "======= NO RESPONSE =======\nSome requests may not be written to the log.\n", 73);
    exit(0);
}

time_t start;           // Main server start time
int sub = 0, semid, therr;
pid_t pid;              // PID variable for fork()
union semun{int val; struct semid_ds *buf; unsigned short* array;} arg;
pthread_t tid;

void* LOG(void* msg)
{
    printf("*PID# %d is waiting for the semaphore.\n", getpid());
    p(semid);
    sleep(1);
    printf("*PID# %d is in the critical zone.\n", getpid());

    char home[80], temp[BUFFSIZE];
    printf("*PID# %d create the *TID# %u.\n", getpid(), (unsigned int)pthread_self());

    // Make a log directory & file with all permissions
    getHomeDir(home);
    strcpy(temp,home);
    mkdir(strcat(temp,"/logfile/"),0777);
    strcat(temp,"logfile.txt");
    FILE* log = fopen(temp,"a");
    chmod(temp,0777);

    fprintf(log, "%s", (char*)msg);
    fflush(log);
    fclose(log);
    printf("*TID# %u is exited.\n", (unsigned int)pthread_self());
    printf("*PID# %d exited the critical zone.\n", getpid());
    v(semid);
    pthread_exit(NULL);
}

///////////////////////////////////////////////////////////////////////
// int_handler
// =================================================================
// input : interrupt signal - SIGINT
// -----------------------------------------------------------------
// output : None
// -----------------------------------------------------------------
// purpose : Print no response on stdout & terminate process when alarm on
///////////////////////////////////////////////////////////////////////
static void int_handler()
{
    if(pid)		// MAIN SERVER
    {
        char msg[300] = "";
        
        // Records server run time and number of processes(# of request) in log file and terminate
	    // Use Semaphore & thread
        sprintf(msg, "**SERVER** [Terminated] run time: %ld sec. #sub process: %d\n", time(NULL) - start, sub);
        if(therr = pthread_create(&tid, NULL, LOG, (void*)msg))
        {
            printf("pthread_create() ERROR\n");
            return;
        }
	pthread_join(tid, NULL);

        // Remove Semaphore
        if((semctl(semid, 0, IPC_RMID, arg)) == -1)
        {
            perror("semctl(REMOVE) failed\n");
            exit(1);
        }
    }
    exit(0);
}

int main()
{
    struct sockaddr_in server_addr, client_addr, web_addr;  // Server & Client sockaddr_in struct
    int socket_fd, web_fd, client_fd, len;                  // file descriptor no. for socket : network socket / browser-proxy / proxy-server

    // Make & set semaphore
    if((semid = semget((key_t)PORTNO, 50, IPC_CREAT|0666)) == -1)
    {
        perror("semget failed");
        exit(1);
    }
    arg.val = 1;
    if((semctl(semid, 0, SETVAL, arg)) == -1)
    {
        perror("semctl failed");
        exit(1);
    }

    // Make a socket for client to server connect
    if((socket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("SERVER : SOCKET CREAT ERROR\n");
        return -1;    // SOCKET CREAT ERROR
    }

    // Initialize start time & variables
    time(&start);
    pid = getpid();
    bzero((char*)&server_addr, sizeof(server_addr));  // Initialize to 0
    server_addr.sin_family = AF_INET;                 // Address system : AF_INET
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);  // Set server address for ALLADDRESS(0x0)
    server_addr.sin_port = htons(PORTNO);             // Change Server's port # to network byte order

    // Make a 'bind' for socket connection
    if(bind(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        printf("SERVER : Socket bind error\n");
        close(socket_fd);
        return -1;      // SOCKET BIND ERROR
    }

    listen(socket_fd, 25);             // Socket capacity : 25
    signal(SIGCHLD, (void*)handler);    // Signal handling for client disconnection
    signal(SIGALRM, (void*)alrm_handler);   // Signal handling for alarm - timeout
    signal(SIGINT, (void*)int_handler); // Signal handling for interrupt signal

    while(1)                            // START
    {
        struct in_addr inet_client_address;

        // Get all client information, when new client has came
        bzero((char*)&client_addr, sizeof(client_addr));
        len = sizeof(client_addr);
        client_fd = accept(socket_fd, (struct sockaddr*)&client_addr, &len);

        if(client_fd < 0)
        {
            // CLIENT ACCEPT ERROR
            printf("SERVER %d : Client Accept Failed\n", getpid());
            close(socket_fd);
            return -1;
        }

        inet_client_address.s_addr = client_addr.sin_addr.s_addr;

        if((pid = fork()) == -1)       // Call fork function for make sub server process
        {
            // FORK ERROR
            close(client_fd);
            close(socket_fd);
            return -1;
        }
        else if(pid == 0)                    // proxy 1-2 : Server part (Sub server process)
        {
            char input_url[BUFFSIZE], buf[BUFFSIZE], method[20] = {0,}, tok[BUFFSIZE] = {0,};

            int client_len = read(client_fd, buf, BUFFSIZE);  // Get request message from client
            strcpy(tok, buf);			    // Temporary same message for strtok
            strcpy(method, strtok(tok, " "));       // Method(GET,POST...)
            strcpy(input_url, strtok(NULL," ")+7);  // Input URL

            if (!strcmp(method, "GET"))
            {
                // temp = temporary string, tmstr = time string
                char host[BUFFSIZE], hashed_url[41], home[80], temp[MSGBUFF], tmstr[50], hostIP[50], serverbuf[MSGBUFF], log[300] = "";
                int cache_len, web_len;                    // Length of response msg
                time_t tcheck;
                struct tm* bd_time;
                FILE* cache;                         // Cache file pointer
                mode_t all = 0777;
                struct hostent* hent;

                memset(serverbuf, EOF, sizeof(serverbuf));  // Initialize
                umask(000);                               // Set mask to zero (for set all permission)
                
                // Make a cache directory
                getHomeDir(home);
                strcpy(temp,home);
                mkdir(strcat(temp,"/cache"),all);

                sha1_hash(input_url,hashed_url);    // Get hashed url
		        /*
                // For debug
                printf("input url : %s, hashed url : %s\n", input_url, hashed_url);
                fflush(NULL);
                */

                // Make a cache's child directory using hashed url
                strcpy(temp,home);
                strcat(temp,"/cache/");
                strncat(temp,hashed_url,3);
                if(mkdir(temp,all) == -1) // Directory is already exist?
                {
                    // If then, there is a possibility it will be 'Hit'
                    DIR* dir = opendir(temp);
                    struct dirent* dp;
                    
                    // File(URL) is already exist?
                    while(dp = readdir(dir))
                        if(!strcmp(dp->d_name,hashed_url+3))
                            break;

                    if(dp)  // update the log : Hit
                    {
                        // logfile에 기록 후 Process를 종료
                        strncpy(tok,hashed_url,3);
                        tok[3] = 0;                        // "tok\0"

                        // Get broken-down time & formatted time string
                        tcheck = time(NULL);
                        bd_time = localtime(&tcheck);
                        strftime(tmstr,sizeof(tmstr),"%Y/%m/%d, %X",bd_time);

			// Document on log(use semaphore & thread)
                        sprintf(log,"[HIT]%s/%s-[%s]\n[HIT]%s\n",tok,hashed_url+3,tmstr,input_url);
                        if(therr = pthread_create(&tid, NULL, LOG, (void*)log))
                        {
                            printf("pthread_create() ERROR\n");
                            return 0;
                        }
                        pthread_detach(tid);

                        // Hashed URL is already exist! -> 'Hit' : write cache contents to browser
                        strcat(temp,"/");
                        strcat(temp,dp->d_name);
                        for(cache = fopen(temp,"r"); (cache_len = fread(temp,sizeof(char),sizeof(temp),cache)) > 0; memset(serverbuf,EOF,sizeof(serverbuf)))
                            write(client_fd,temp,cache_len);
                        fclose(cache);

                        // socket clear
                        close(web_fd);
                        close(client_fd);
                        pthread_exit(NULL);                // Sub server process end
                    }
                }

                // Get broken-down time & formatted time string
                tcheck = time(NULL);
                bd_time = localtime(&tcheck);
                strftime(tmstr,sizeof(tmstr),"%Y/%m/%d, %X",bd_time);
                
		// Document on log(use semaphore & thread)
                sprintf(log,"[MISS]%s-[%s]\n",input_url,tmstr);
                if(therr = pthread_create(&tid, NULL, LOG, (void*)log))
                {
                    printf("pthread_create() ERROR\n");
                    return 0;
                }
		pthread_detach(tid);

                // It will be 'MISS' : request to web server
                // Get real host name for gethostbyname()
                strcpy(host, strstr(buf, "Host: ")+6);
                strtok(host, "\r");

                // Make a socket for client to server connect
                if((web_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
                {
                    printf("SERVER : SOCKET CREAT ERROR\n");
                    return -1;    // SOCKET CREAT ERROR
                }
                bzero((char*)&web_addr, sizeof(web_addr));     // Initialize to 0

                // Ready to web server connection
                if(hent = (struct hostent*)gethostbyname(host))
                    strcpy(hostIP,inet_ntoa(*((struct in_addr*)hent->h_addr_list[0])));
                web_addr.sin_family = AF_INET;                 // Address system : AF_INET
                web_addr.sin_addr.s_addr = inet_addr(hostIP);  // Set web server address (hostaddr in dotted address)
                web_addr.sin_port = htons(HTTPPORT);           // Link to web server using HTTP port (80)

                if(connect(web_fd, (struct sockaddr*)&web_addr, sizeof(web_addr)) < 0)
                {
                    printf("WEB SERVER IS NOT READY\n");
                    return -1;              // SERVER IS NOT READY
                }
                
                // make a directory & cache file
                strcat(temp,"/");
                strcat(temp,hashed_url+3);
                cache = fopen(temp,"w");
                chmod(temp,all);

                if(write(web_fd, buf, client_len) > 0)  // Send request msg to web server
                {
                    alarm(30);                          // keep-alive : 30
                    while((web_len = read(web_fd, serverbuf, sizeof(serverbuf))) > 0)   // Receive response msg from web server
                    {
                        // Send response msg to browser & record in cache file
                        write(client_fd, serverbuf, web_len);
                        fwrite(serverbuf,sizeof(char),web_len,cache);
                        fflush(cache);
                        memset(serverbuf,EOF,sizeof(serverbuf));            // Initialize
                    }
                    alarm(0);                           // Alarm off, when all response msg has received
                }
                fclose(cache);
                close(web_fd);
            }
            close(client_fd);       // Close client socket file descriptor in sub server process
            pthread_exit(NULL);                // Sub server process end
        }
        close(client_fd);           // Close client socket file descriptor in main server process
        sub++;                      // Sub process count up
    }
    close(socket_fd);               // Close socket file descriptor
    return 0;
}
