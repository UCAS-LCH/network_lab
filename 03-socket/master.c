#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

struct master_message{
    int total_length; //消息总长度
    char pos[100];    //文件所在位置
    int begin_pos;    //进行字符统计的初始位置
    int end_pos;      //进行字符统计的结束位置
};
struct para{
    int sock;
    struct master_message msg;
    int *reply;
};
void thread(struct para *p)
{
    if (send(p->sock, &(p->msg), sizeof(struct master_message), 0) < 0) {
        printf("Send failed");
        return 1;
    }
    if (recv(p->sock, (p->reply), 2000, 0) < 0){ 
        printf("recv failed");
        return 1;
    }
}
int main(int argc,const char *argv[])
{
    int sock_1,sock_2;
    struct sockaddr_in worker_1,worker_2;
    int server_reply_1[26],server_reply_2[26];
    int total_char_num[26];
    char file_name[100];
    strcpy(file_name, argv[1]);
    int i;
    for(i = 0;i < 26;i++)
        total_char_num[i] = 0;
    sock_1 = socket(AF_INET, SOCK_STREAM, 0);
    sock_2 = socket(AF_INET, SOCK_STREAM, 0);
    if(sock_1 == -1 || sock_2 == -1){
	    printf("Could not create socket");
    }
    printf("Socket created");
    
    FILE *fp;
    char *strLine;
    char *ip_1,*ip_2;
    strLine = (char *)malloc(100);
    ip_1 = (char *)malloc(10);
    ip_2 = (char *)malloc(10);
    if((fp = fopen("workers.conf","r")) == NULL){
        printf("Open Failed\n");
        return -1;
    }
    fgets(strLine,100,fp);
    strLine[(int)(strrchr(strLine,'\n') - strLine)] = '\0';
    strcpy(ip_1,strLine);
    fgets(strLine,100,fp);
    strLine[(int)(strrchr(strLine,'\n') - strLine)] = '\0';
    strcpy(ip_2,strLine);
    


    worker_1.sin_addr.s_addr = inet_addr(ip_1);
    worker_1.sin_family = AF_INET;
    worker_1.sin_port = htons(8888);
    
    worker_2.sin_addr.s_addr = inet_addr(ip_2);
    worker_2.sin_family = AF_INET;
    worker_2.sin_port = htons(8888);

    if(connect(sock_1,(struct sockaddr *)&worker_1, sizeof(worker_1)) < 0){
    	perror("connect failed. Error");
    	return 1;
    }
    printf("Connected_1!\n");

    if(connect(sock_2,(struct sockaddr *)&worker_2, sizeof(worker_2)) < 0){
    	perror("connect failed. Error");
    	return 1;
    }
    printf("Connected_2!\n");
    int fd;
    if((fd = open(file_name,O_RDONLY)) < 0){
        printf("Open failed\n");
        return -1;
    }
    struct stat buf;
    stat(file_name,&buf);
    int text_size;
    text_size = buf.st_size;
    struct master_message worker1_message,worker2_message;
    worker1_message.total_length = worker2_message.total_length = htonl(sizeof(struct master_message));
    strcpy(worker1_message.pos, file_name);
    strcpy(worker2_message.pos, file_name);
    worker1_message.begin_pos = htonl(0);
    worker1_message.end_pos = htonl(text_size / 2);
    worker2_message.begin_pos = htonl(text_size / 2 + 1);  
    worker2_message.end_pos = htonl(text_size);
    pthread_t id_1,id_2;
    struct para worker1_para,worker2_para;
    worker1_para.sock = sock_1;
    worker1_para.msg = worker1_message;
    worker1_para.reply = server_reply_1;
    worker2_para.sock = sock_2;
    worker2_para.msg = worker2_message;
    worker2_para.reply = server_reply_2;
    int ret;
    ret = pthread_create(&id_1,NULL,(void *)thread,&worker1_para);
    if(ret != 0){
        printf("create thread_1 failed\n");
        return -1;
    }
    ret = pthread_create(&id_2,NULL,(void *)thread,&worker2_para);
    if(ret != 0){
        printf("create thread_2 failed\n");
        return -1;
    }
    pthread_join(id_1,NULL);
    pthread_join(id_2,NULL);
    int j;
    for(j = 0;j < 26;j++){
        total_char_num[j] += (ntohl(server_reply_1[j]) + ntohl(server_reply_2[j]));
        printf("%d\n", total_char_num[j]);
    }
    close(sock_1);
    close(sock_2);
    return 0;
}
