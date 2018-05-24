#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

struct master_message{
    int total_length;
    char pos[100];
    int begin_pos;
    int end_pos;
};

int main(int argc,const char *argv[])
{
    int s,cs;
    struct sockaddr_in worker;
    int char_num[260];
    char text_content[2000];
    if((s = socket(AF_INET,SOCK_STREAM,0)) < 0){
	perror("Could not create socket");
	return -1;
    }
    printf("Socket created");
    
    worker.sin_family = AF_INET;
    worker.sin_addr.s_addr = INADDR_ANY;
    worker.sin_port = htons(8888);

    if(bind(s,(struct sockaddr *)&worker,sizeof(worker)) < 0){
    	perror("bind failed.Error");
    	return -1;
    }
    printf("bind done");

    listen(s,3);
    printf("Waiting for incoming connections...");

    int c = sizeof(struct sockaddr_in);
    if ((cs = accept(s, (struct sockaddr *)&worker, (socklen_t *)&c)) < 0) {
        perror("accept failed");
        return 1;
    }
    printf("Connection accepted");
    struct master_message msg;
    int msg_len = 0;
    int fd;
    int i,j;
    int actual_length;
    int read_length = 1024;
    while((msg_len = recv(cs,&msg,1024,0)) > 0){
        if((fd = open(msg.pos,O_RDONLY)) < 0){
            printf("Open failed\n");
            return -1;
        }
        lseek(fd,ntohl(msg.begin_pos),SEEK_SET);
        actual_length = ntohl(msg.end_pos) - ntohl(msg.begin_pos) + 1;
        while(1){
            if(actual_length > 1024){
                read_length = 1024;
                actual_length -= 1024;
            }
            else
                read_length = actual_length;
            read(fd,text_content,read_length);
            for(j = 0;j < read_length;j++){
                if(text_content[j] > 96 && text_content[j] < 123)
                    char_num[text_content[j] - 97] ++;
                else if(text_content[j] > 64 && text_content[j] < 91)
                    char_num[text_content[j] - 65] ++;
            }
            if(read_length < 1024)
                break;
        }
        for(i = 0;i < 26;i++)
            char_num[i] = htonl(char_num[i]);
        write(cs, char_num, 104);
    }

    if (msg_len == 0) {
        printf("Client disconnected");
    }
    else { 
        perror("recv failed");
        return -1;
    }
     
    return 0;
}
