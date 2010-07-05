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

struct _threadarg {
  int from_fd;
  int to_fd;
};

struct _settings {
  int listen;  /* listen a port */
  int port;  /* port to listen or connect */
  int shell;  /* start shell or not */
  char *target;  /* target host */
  int wait;  /* non-deamon */
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
void * recv_thread(void*args);

void handler(int signum)
{
  if (signum == SIGCHLD) {
    fprintf(stderr, "caught SIGCHLD, raise SIGTERM\n");
    raise(SIGTERM);
  }
}

int main(int argc, char **argv)
{
  int c;
  struct sockaddr_in sock_addr, cli_addr;
  int sock_fd, work_fd;
  int read_fd, write_fd;

  while (-1 != (c = getopt(argc, argv, "hlp:st:w"))) {
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

  if (settings.shell && !settings.wait) {
    pid_t pid = fork();
    if (pid < 0) {
      fprintf(stderr, "can not fork child: %s\n", strerror(errno));
      exit(1);
    } else if (pid > 0) {
      /* parent exit */
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
  }
  
  sock_fd = -1;
  work_fd = -1;
  memset((void *)&sock_addr, 0, sizeof(struct sockaddr_in));
  sock_addr.sin_family = AF_INET;
  sock_addr.sin_port = htons(settings.port);
  if (settings.target) {
    char *p = NULL;
    struct hostent *hp = gethostbyname(settings.target);
    if (hp == NULL) {
      fprintf(stderr, "can not resolve given target '%s': %s\n",
              settings.target, hstrerror(h_errno));
      exit(1);
    }
    if (inet_aton(inet_ntoa(*((struct in_addr *)hp->h_addr)),
                  (struct in_addr *)&sock_addr.sin_addr) == -1) {
      fprintf(stderr, "invalid target\n");
      exit(1);
    }
  } else {
    sock_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  }

  if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    fprintf(stderr, "can not create socket: %s\n", strerror(errno));
    exit(1);
  }

  if (settings.listen) {
    char clientip[20];
    socklen_t al;
    if (bind(sock_fd, (struct sockaddr*)&sock_addr,
             sizeof(struct sockaddr_in)) == -1) {
      fprintf(stderr, "can not bind to port %d: %s\n", settings.port,
              strerror(errno));
      exit(1);
    }
    if (listen(sock_fd, SOMAXCONN) == -1) {
      fprintf(stderr, "can not listen :\n", errno);
      exit(1);
    }
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
    if (connect(sock_fd, (struct sockaddr*)&sock_addr,
                sizeof(struct sockaddr_in)) == -1) {
      fprintf(stderr, "can not connect to target: %s\n",
              strerror(errno));
      exit(1);
    }
    printf("connected\n");
    work_fd = sock_fd;
  }
  
  if (settings.shell) {
    pid_t pid_sh;
    struct termios term;
    struct winsize win;
    int fdm;
    
    signal(SIGCHLD, handler);
    /* start shell */
    printf("try to forkpty\n");
    pid_sh = forkpty(&fdm, NULL, NULL, NULL);
    if (pid_sh == 0) {
      char* args[] = { "bash", NULL};
      sleep(1);
      printf("Welcome to ncshell (pid: %d)\n", getpid());
      if (execv("/bin/bash", args) == -1) {
        fprintf(stderr, "execv failed: %s\n", strerror(errno));
        exit(1);
      }
    } else if (pid_sh < 0) {
      fprintf(stderr, "can not forkpty: %s\n", strerror(errno));
      exit(1);
    }

    /* here is the main process */
    if (!settings.wait) {
      printf("close stdio fds\n");
      close(0);
      close(1);
      close(2);
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
/*       signal(SIGTERM, handler); */
    }
    
    read_fd = 0;
    write_fd = 1;
  }

  /* ignore SIGPIPE */
  signal(SIGPIPE, SIG_IGN);
  loop(work_fd, read_fd, write_fd);

  shutdown(work_fd, SHUT_RDWR);
  close(work_fd);
  shutdown(sock_fd, SHUT_RDWR);
  close(sock_fd);

  /* reset terminal */
  if (!settings.shell && isatty(0)) {
    tcsetattr(0, TCSANOW, &oldterm);
  }
  printf("Connection closed\n");

  return 0;
}

/**
 * piping loop
 * \param work_fd  the socket fd
 * \param read_fd  fd for reading
 * \param write_fd fd for writing
 */
void loop(int work_fd, int read_fd, int write_fd)
{
  int size, n;
  char buffer[1024];

  pthread_t t;
  pthread_attr_t attr;
  struct _threadarg args;

  args.from_fd = work_fd;
  args.to_fd = write_fd;
  pthread_attr_init(&attr);

  /* sub thread read socket */
  if (pthread_create(&t, &attr, recv_thread, &args) != 0) {
    fprintf(stderr, "can not create thread: %s\n", strerror(errno));
    return;
  }
  /* main thread write socket */
  while (1) {
    size = read(read_fd, buffer, 1024);
    if (peer_closed)
      break;
    
    if (size <= 0)
      break;
    n = write(work_fd, buffer, size);
    if (n != size) {
      shutdown(work_fd, SHUT_RDWR);
      close(work_fd);
      break;
    }
  }
  printf("peer stop receive\n");

  pthread_join(t, NULL);
}

/**
 * thread route to read socket
 */
void * recv_thread(void*args)
{
  int size, n;
  char buffer[1024];
  struct _threadarg *ap;
  int from_fd, to_fd;
  
  ap = (struct _threadarg*)args;
  from_fd = ap->from_fd;
  to_fd = ap->to_fd;
  while (1) {
    size = read(from_fd, buffer, 1024);
    if (size <= 0) {
      shutdown(from_fd, SHUT_RDWR);
      close(from_fd);
      if (!settings.shell && isatty(0)) {
        tcsetattr(0, TCSAFLUSH, &oldterm);
        raise(SIGTERM);
      }
      break;
    }
    
    n = write(to_fd, buffer, size);
    if (n != size) {
      shutdown(from_fd, SHUT_RDWR);
      close(from_fd);
      if (!settings.shell && isatty(0)) {
        tcsetattr(0, TCSAFLUSH, &oldterm);
        raise(SIGTERM);
      }
      break;
    }
  }
  printf ("peer stop send\n");
  return NULL;
}

/* to use non-blocking io
{
    fflags = fcntl(fd, F_GETFL);
    fflags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, fflags);
    
    fds[0].fd = 0;
    fds[1].fd = 1;
    fds[2].fd = fd;
    fds[0].events = POLLIN;
    fds[1].events = POLLOUT;
    fds[0].events = POLLIN | POLLOUT;
    while (1) {
      poll(fds, 3, 10000);
      if (recv_size > 0) {
        n = write(1, recv_buf + recv_offset, recv_size);
        if (n >= 0) {
          recv_size -= n;
          recv_offset += n;
        } else {
          if (errno != EAGAIN && errno != EINTR) {
            perror("write error: ", errno);
            break;
          }
        }
      }
      if (recv_size == 0) {
        n = read(fd, recv_buf, 1024);
        if (
    }
}
*/


void showusage(void)
{
  printf("%s",
         "-h         print this help and exit\n"
         "-l         listen to port (server mode), default: off\n"
         "-p <port>   TCP port to connect or listen to\n"
         "-t <host>  target host to connect\n"
         "-s         start a shell, default: off\n"
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
