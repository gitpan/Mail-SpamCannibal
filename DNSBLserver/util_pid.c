/* util_pid.c
 *
 * Copyright 2003, Michael Robinton <michael@bizsystems.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

/*	int kill(pid_t pid, int sig)
 *	pid_t getpid(void)
 */

extern char mybuffer[], * dbhome;
extern pid_t pidrun;
static char pidfile[] = "dnsbls.pid";

void
savpid(char * fpath)
{
  FILE *fd;
  if ((fd = fopen(fpath, "w")) != NULL) {
    fprintf(fd, "%u\n", getpid());
    (void)fclose(fd);
  }
}

char *
pidpath()
{
  strcpy(mybuffer, dbhome);
  strcat(mybuffer, "/");
  strcat(mybuffer, pidfile);
  return(mybuffer);
}

/* return address of pidfile path name
 * if no other process is running
 * Otherwise return NULL and place
 * the pid of running process in
 * EXTERN pidrun
 */

char *
chk4pid(char * fpath)
{
  FILE *fd;

  pidrun = 0;
  if (fpath == NULL)
    fpath = pidpath();

  if ((fd = fopen(fpath, "r")) == NULL)
    return(fpath);

  fscanf(fd,"%d",&pidrun);
  (void)fclose(fd);

/* return '0' = running */
  if (kill(pidrun,0))
    return(fpath);

  return(NULL);
}
 