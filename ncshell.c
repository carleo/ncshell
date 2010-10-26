/****************************************************************************
 * ncshell: similar to nc, can run in server and client mode, moreover it can
 * fork a pty to start a shell, can be used as a remote shell tool
 *
 * author:  Calreo Lee (carleo21@gmail.com)
 * date:    Wed Oct 14 11:50:34 2009
 * version: 0.2
 ****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <malloc.h>
#include <fcntl.h>
#include <pthread.h>
#include <pty.h>
#include <poll.h>
#include <termios.h>
#include <signal.h>
#include <pwd.h>

#define BUFLEN 1024

struct _threadarg {
  int from_fd;
  int to_fd;
};

struct _settings {
  int listen;  /* listen a port */
  int port;  /* port to listen or connect */
  int shell;  /* start shell or not */
  int wait;  /* non-deamon */
  char *target;  /* target host */
  char *username; /* username */
};

extern int errno;
extern char *optarg;
extern int h_errno;
struct _settings settings;
struct termios oldterm;
volatile int peer_closed = 0;

void showusage(void);
void setting_init(void);
void loop(int work_fd, int read_fd, int write_fd);
void handler(int signum)
{
  exit(0);
}

void * recv_thread(void*args);

int main(int argc, char **argv)
{
  int c;
  struct sockaddr_in sock_addr, cli_addr;
  int sock_fd, work_fd;
  int read_fd, write_fd;
  struct passwd *pw;

  while (-1 != (c = getopt(argc, argv, "hlp:st:u:w"))) {
    switch (c) {
    case 'h':
      showusage();
      exit(0);
      break;
    case 'l':
      settings.listen = 1;
      break;
    case 'p':
      settings.port = atoi(optarg);
      break;
    case 's':
      settings.shell = 1;
      break;
    case 't':
      settings.target = strdup(optarg);
      break;
    case 'u':
      settings.username = strdup(optarg);
    case 'w':
        settings.wait = 1;
    break;
    default:
      /* error */
      exit(1);
    }
  }

  /* check options */
  if (settings.port < 1) {
    fprintf(stderr, "%s\n", "please specified a valid port via '-p' option");
    exit(1);
  }
  if (settings.listen == 0 && settings.target == NULL) {
    fprintf(stderr, "one of '-t' and '-l' must be provided\n");
    exit(1);
  }
  if (settings.listen && settings.target) {
    fprintf(stderr, "only one of '-t' and '-l' can be provided\n");
    exit(1);
  }

  if (settings.username) {
    if (geteuid() != 0) {
      fprintf(stderr, "can not switch to other user without root privilege\n");
      exit(1);
    }
    if (*settings.username == '\0') {
      fprintf(stderr, "username can not be empty\n");
      exit(1);
    }
    if ((pw = getpwnam(settings.username)) == NULL) {
      fprintf(stderr, "no such username %s\n", settings.username);
      exit(1);
    }
  }
  
  sock_fd = -1;
  work_fd = -1;
  memset((void *)&sock_addr, 0, sizeof(struct sockaddr_in));
  sock_addr.sin_family = AF_INET;
  sock_addr.sin_port = htons(settings.port);

  if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    fprintf(stderr, "can not create socket: %s\n", strerror(errno));
    exit(1);
  }

  if (settings.listen) {
    int opt = 1;

    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) {
      perror("setsockopt error");
      close(sock_fd);
      return -1;
    }

    sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock_fd, (struct sockaddr*)&sock_addr,
             sizeof(struct sockaddr_in)) == -1) {
      fprintf(stderr, "can not bind to port %d: %s\n", settings.port,
              strerror(errno));
      exit(1);
    }
  }

  /* drop root privilege after bind */
  if (settings.username) {
    if (setgid(pw->pw_gid)) {
      perror("failed to setgid");
      exit(1);
    }
    /* reinit groups or supplementary groups retains root privilegs */
    if (initgroups(settings.username, pw->pw_gid)) {
      perror("failed to init group");
      exit(1);
    }
    if (setuid(pw->pw_uid)) {
      perror("failed to set uid");
      exit(1);
    }

    /* reset some environment variables */
    if (getenv("HOME") != NULL) {
      setenv("HOME", pw->pw_dir, 1);
    }

  }

  if (settings.listen) {
    char clientip[20];
    socklen_t al;
    if (listen(sock_fd, SOMAXCONN) == -1) {
      fprintf(stderr, "can not listen :\n", errno);
      exit(1);
    }
    al = sizeof(cli_addr);
    printf("waiting for connection\n");
    if ((work_fd = accept(sock_fd, (struct sockaddr *)&cli_addr,
                         (socklen_t *)&al)) == -1) {
      fprintf(stderr, "can not accept: %s\n", strerror(errno));
      exit(1);
    }
    memset(clientip, 0, 20);
    inet_ntop(AF_INET, &(cli_addr.sin_addr), clientip, 20);
    printf("get a peer from %s port %u\n", clientip,
            (unsigned int)ntohs(cli_addr.sin_port));
  } else {
    printf("trying to connect %s port %d\n", settings.target, settings.port);
    struct hostent *hp = gethostbyname(settings.target);
    if (hp == NULL || *(hp->h_addr_list) == NULL) {
      fprintf(stderr, "can not resolve given target '%s': %s\n",
              settings.target, hstrerror(h_errno));
      exit(1);
    }
    memcpy(*(hp->h_addr_list), &sock_addr.sin_addr, sizeof(struct in_addr));
    if (connect(sock_fd, (struct sockaddr*)&sock_addr,
                sizeof(struct sockaddr_in)) == -1) {
      fprintf(stderr, "can not connect to target: %s\n",
              strerror(errno));
      exit(1);
    }
    printf("connected\n");
    work_fd = sock_fd;
  }

  /* run as daemon by default if we are going to start shell */
  if (settings.shell && !settings.wait) {
    int fd;
    pid_t pid = fork();
    if (pid < 0) {
      fprintf(stderr, "can not fork child: %s\n", strerror(errno));
      exit(1);
    } else if (pid > 0) {
      exit(0);
    }
    /* child */
    if (chdir("/") == -1) {
      fprintf(stderr, "can not chdir to '/': %s\n", strerror(errno));
      exit(1);
    }
    if (setsid() == -1) {
      fprintf(stderr, "can not setsid: %s\n", strerror(errno));
      exit(1);
    }

    /* close stdio */
    if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
      if (dup2(fd, STDIN_FILENO) < 0 || dup2(fd, STDOUT_FILENO) < 0 ||
          dup2(fd, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
      }
    } else {
      close(STDIN_FILENO);
      close(STDOUT_FILENO);
      close(STDERR_FILENO);
    }
  }

  if (settings.shell) {
    pid_t pid_sh;
    struct termios term;
    struct winsize win;
    int fdm;

    signal(SIGCHLD, handler);

    /* start shell */
    pid_sh = forkpty(&fdm, NULL, NULL, NULL);
    if (pid_sh == 0) {
      char* args[] = { "bash", NULL};
      printf("Welcome to ncshell (pid: %d)\n", getpid());
      if (execv("/bin/bash", args) == -1) {
        fprintf(stderr, "execv failed: %s\n", strerror(errno));
        exit(1);
      }
    } else if (pid_sh < 0) {
      fprintf(stderr, "can not forkpty: %s\n", strerror(errno));
      exit(1);
    }

    read_fd = fdm;
    write_fd = fdm;
  } else {
    /* save term attrs and set to raw mode */
    if (isatty(0)) {
      struct termios newterm;
      if (tcgetattr(0, &oldterm) == -1) {
        fprintf(stderr, "can not get terminal attrbutes: %s\n", strerror(errno));
        exit(1);
      }
      newterm = oldterm;
      /* cfmakeraw(newterm); */
      newterm.c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP
                           | INLCR | IGNCR | ICRNL | IXON);
      newterm.c_oflag &= ~OPOST;
      newterm.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
      newterm.c_cflag &= ~(CSIZE | PARENB);
      newterm.c_cflag |= CS8;

      if (tcsetattr(0, TCSAFLUSH, &newterm) == -1) {
        fprintf(stderr, "can not set terminal attrbutes: %s\n", strerror(errno));
        exit(1);
      }
    }
    
    read_fd = STDIN_FILENO;
    write_fd = STDOUT_FILENO;
  }

  signal(SIGPIPE, SIG_IGN);
  loop(work_fd, read_fd, write_fd);

  shutdown(work_fd, SHUT_RDWR);
  close(work_fd);
  if (sock_fd != work_fd) {
    shutdown(sock_fd, SHUT_RDWR);
    close(sock_fd);
  }

  /* reset terminal */
  if (!settings.shell && isatty(0)) {
    tcsetattr(0, TCSANOW, &oldterm);
  }
  printf("Connection closed\n");

  return 0;
}


ssize_t writen(int fd, void *buf, size_t size)
{
  ssize_t n, offset;
  offset = 0;
  while (size > 0) {
    n = write(fd, buf + offset, size);
    if (n >= 0) {
      size -= n;
      offset += n;
    } else {
      if (errno != EAGAIN && errno != EINTR) {
        return -1;
      }
    }
  }
  return 0;
}
  
void loop(int work_fd, int read_fd, int write_fd)
{
  struct pollfd fds[2];
  char buf[BUFLEN];
  ssize_t size;

  fds[0].fd = work_fd;
  fds[0].events = POLLIN;
  fds[1].fd = read_fd;
  fds[1].events = POLLIN;
  while (poll(fds, 2, -1) > 0) {
    if (fds[0].revents & POLLIN) {
      size = read(work_fd, buf, BUFLEN);
      if (size <= 0)
        break;
      else if (writen(write_fd, buf, size))
        break;
    }
    if (fds[1].revents & POLLIN) {
      size = read(read_fd, buf, BUFLEN);
      if (size <= 0)
        break;
      else if (writen(work_fd, buf, size))
        break;
    }
  }
}


void showusage(void)
{
  printf("%s",
         "-h         print this help and exit\n"
         "-l         listen to port (server mode), default: off\n"
         "-p <port>   TCP port to connect or listen to\n"
         "-t <host>  target host to connect\n"
         "-s         start a shell, default: off\n"
         "-u <user>  run as user"
         "-w         waiting for connection, default: off\n"
         );
}

void setting_init(void)
{
  settings.listen = 0;
  settings.port = 0;
  settings.wait = 0;
  settings.target = NULL;
  settings.shell = 0;
}
