/* CText.xs
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

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
/* #include <sys/vfs.h>
*/
#include <stdio.h>

/* for BerkeleyDB interface - bdbtarpit.c	*/
#include "bdbtarpit.h"
#include "defines.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* for util_pid.c		*/
#include "util_pid_func.h"

/* for t_cmdline.c		*/
#include "host_info_func.h"

/* for size of string buffer below	*/
#include <resolv.h>

/* for t_short	*/
#include <unistd.h>

/* Global Variables from main.c */
  extern DBTPD dbtp;
  extern int oflag, logopen, bflag, zflag;
  extern pid_t pidrun;
  extern char * zone_name, * local_name, * contact, * errormsg;
  extern int zone_name_len, zoneEQlocal;
  extern int h_name_ctr;        /* name service buffer ring pointer     */
  extern u_int32_t * Astart, * Aptr, localip[];
  extern int mxmark[];
  extern struct in_addr stdResp, stdRespBeg, serial_rec;

/* Globals from ns.c		*/
  extern unsigned char ns_msgbuf[];
  char * name_skip(char * buf);

/* Globals used within CTest	*/

char strbuf[MAXDNAME];
char c, * nsname = NULL;
int nstore = 0, Mptr = 0, mxsave = 0, aflag = 0;

/* ****************************	*
 * 	dump database		*
 * 	used only for test	*
 * ****************************	*

Dumps database contents as ascii strings of the form
	  key	=> data (time secs)
	1.2.3.4	=> 1234567890

Returns:	0 on success, else error code
 */

void
my_helpinit(DBTPD * dbtp, int ai, char * addr)
{
  dbtp->dbfile[ai] = addr;
}

int
mydb_dump(int secondary)
{
  DB * dbp;
  DBT key, data;
  int status;
  u_int32_t cursor = 1;
  DBC * dbcp;
  struct in_addr inadr;
  int i, c; 
  char * cp;

  if (secondary)
    dbp = dbtp.dbaddr[DBcontrib];
  else
    dbp = dbtp.dbaddr[DBtarpit];

  memset(&key, 0, sizeof(DBT));
  memset(&data, 0, sizeof(DBT));
  key.data = &cursor;
  key.size = sizeof(cursor);
  while((status = dbp->get(dbp, NULL, &key, &data, DB_SET_RECNO)) == 0) {
    inadr.s_addr = *(in_addr_t *)(key.data);
    if (secondary) {
      printf("%16s => ", inet_ntoa(inadr));
      cp = (char *)data.data;
      for(i=0;i<data.size;i++) {
	putchar((int)(*cp++));
      }
      printf("\n");
    }
    else
      printf("%16s => %10ld\n", inet_ntoa(inadr), *(u_int32_t *)data.data);
    key.data = &cursor;
    key.size = sizeof(cursor);
    cursor++;
  }
  if (status == DB_NOTFOUND)
	status = 0;
  return status;   
}


void *
myct_getsec(void * addr, size_t size)
{
  extern char strbuf[];
  extern DBTPD dbtp;

  u_int32_t i;
  if (dbtp_get(&dbtp,DBcontrib,addr,size))
	return(NULL);
  i = (u_int32_t)(dbtp.mgdbt.size);
  if (i > MAXDNAME -1)
	i = MAXDNAME -1;
  memcpy(strbuf,(char *)(dbtp.mgdbt.data),i);
  *((char *)(strbuf + i)) = '\0';
  return((void *)strbuf);
}

void *
myct_getpri(void * addr, size_t size)
{
  extern DBTPD dbtp;

  if (dbtp_get(&dbtp,DBtarpit,addr,size))
	return(0);
  return(dbtp.mgdbt.data);
}

int
my_cmdline(char c,char * stuff)
{
    struct in_addr in;
  /* parse the command line */
    switch(c) {
	case 'n':
	    if (nsname != NULL && !aflag) {
		if(add_ns_info(nsname,aflag))
		    return(0);
	    }
	    mxmark[Mptr] = mxsave;	/* stash any mx mark	*/

/*	must retrieve Aptrs for next entry before h_name_ctr is incremented	*/
	    Aptr = Astart = current_Astart(h_name_ctr);
	    Mptr = h_name_ctr;
	    nsname = stuff;
	    aflag = 0;
	    mxsave = 0;
	    nstore = 0;
	    break;

	case 'a':
	    if (nsname == NULL)
		return(0);
	    aflag = 1;
	    if (!nstore) {
		if(add_ns_info(nsname,aflag))
		    return(0);
		mxmark[Mptr] = mxsave;
	  	nstore = 1;
	    }
	    if((inet_aton(stuff, &in)) == 0)
		return(0);
	    Aptr = insert_A_record(Astart, Aptr, in.s_addr);
	    break;

	case 'b':
	    bflag = atoi(stuff);
	    break;

	case 'e':
	    errormsg = stuff;
	    break;

	case 'm':
	    if (nsname == NULL)
		return(0);
		mxmark[Mptr] = mxsave = atoi(stuff);
		break;

	case 'L':
	    strcpy(local_name,stuff);
	    if (zone_name != NULL) {
		if (strcasecmp(zone_name, local_name) == 0)
		    zoneEQlocal = 1;
		else
		    zoneEQlocal = 0;
	    }
	    break;

	case 'I':
	    if(inet_aton(stuff, &in) == 0)
		return(0);
	    localip[0] = in.s_addr;
	    break;

	case 'z':
	    zone_name = stuff;
	    zone_name_len = strlen(zone_name);
	    if (local_name != NULL) {
		if (strcasecmp(zone_name, local_name) == 0)
		    zoneEQlocal = 1;
		else
		    zoneEQlocal = 0;
	    }
	    break;

	case 'c':
	    contact = stuff;
	    break;

	case 'P':
	    zflag = atoi(stuff);
	    break;

	default:
	    return(0);
    } /* end case */
    return(1);
}

u_int32_t
my_u32(void * data)
{
  return(*(u_int32_t *)data);
}

int
my_cmp_serial(u_long s1, u_long s2)
{
  return(cmp_serial((u_int32_t)s1, (u_int32_t)s2));
}

MODULE = Mail::SpamCannibal::DNSBLserver::CTest	PACKAGE = Mail::SpamCannibal::DNSBLserver::CTest

PROTOTYPES: DISABLE

 # first item in list is the program name

int
t_main(...)
    PREINIT:
	STRLEN	len;
	unsigned char * ptr[20];
	int i;
	extern int opterr;
    CODE:
	if (items > 20) {
	    RETVAL = 0;
	} else {
	    for (i=0; i < items; i++)
	    {
		ptr[i] = (unsigned char *)(SvPV(ST(i), len));
	    }
	opterr = 0;
	realMain(items, (char **)ptr);
	}
	RETVAL = i;
    OUTPUT:
	RETVAL

void
t_setsig()
    CODE:
	logopen = 0;	/* skip branch in Code	*/
	oflag = 1;	/* print to stdout	*/
	set_signals();

int
t_pidrun()
    CODE:
	RETVAL = (int)pidrun;

void
t_savpid(path)
	unsigned char * path
    CODE:
	savpid(path);

void
t_chk4pid(path)
	unsigned char * path
    PREINIT:
	SV * out;
    PPCODE:
	path = chk4pid(path);
	if (path == NULL) {
	  ST(0) = &PL_sv_undef;
	}
	else {
	  out = sv_newmortal();
	  out = newSVpv(path,0);
	  ST(0) = out;
	  XSRETURN(1);
	}

void
t_pidpath()
    PREINIT:
	SV * out;
    PPCODE:
	out = sv_newmortal();
	out = newSVpv(pidpath(),0);
	ST(0) = out;
	XSRETURN(1);

int
t_init(home,...)
	unsigned char * home
    PREINIT:
	STRLEN len;
    CODE:
	my_helpinit(&dbtp,DBtarpit,NULL);
	my_helpinit(&dbtp,DBcontrib,NULL);

	if (items > 1)
	    my_helpinit(&dbtp,DBtarpit,(char *)(SvPV(ST(1), len)));
	if (items > 2)
	    my_helpinit(&dbtp,DBcontrib,(char *)(SvPV(ST(2), len)));

	RETVAL = dbtp_init(&dbtp,home, -1);
    OUTPUT:
	RETVAL

int
t_dump(which)
	int which
    CODE:
	RETVAL = mydb_dump(which);
    OUTPUT:
	RETVAL

void
t_close()
    CODE:
	dbtp_close(&dbtp);

void
t_get(which, addr);
	int which
	SV * addr
    PREINIT:
	SV * out;
	STRLEN len;
	void * data;
    PPCODE:
	data = (void *)(SvPV(addr,len));
	if (which)
	  data = myct_getsec(data,len);
	else
	  data = myct_getpri(data,len);

	if (data == NULL) {
	  ST(0) = &PL_sv_undef;
	}
	else {
	  out = sv_newmortal();
	  if(which) {
	    out = newSVpv((char *)data,0);
	  } 
	  else {
	    out = newSViv(*(I32 *)data);
	  }
	  ST(0) = out;
	}
	XSRETURN(1);

void
t_getrecno(which, cursor)
	int which
	U32 cursor
    PREINIT:
	SV * netaddr, * tmp;		/* older perl does not know about newSVuv */
	U32 datasize;
	int ai;
    PPCODE:
	if (which)
	    ai = DBcontrib;
	else
	    ai = DBtarpit;

	if (dbtp_getrecno(&dbtp,ai,cursor)) {
	    if(GIMME == G_ARRAY)
		XSRETURN_EMPTY;
	    else
		XSRETURN_UNDEF;
	}
	netaddr = sv_newmortal();
	sv_setpvn(netaddr, (char *)dbtp.keydbt.data, (size_t)dbtp.keydbt.size);
	XPUSHs(netaddr);
	if(GIMME == G_ARRAY) {
	    if (which)
		XPUSHs(sv_2mortal(newSVpv((char *)dbtp.mgdbt.data, (size_t)dbtp.mgdbt.size)));
	    else {
		cursor = my_u32(dbtp.mgdbt.data);	/* temp variable	*/
		tmp = newSViv(cursor);
		sv_setuv(tmp,cursor);
		XPUSHs(sv_2mortal(tmp));
	    }
	    XSRETURN(2);
	}
	XSRETURN(1);

void
t_short()
    PPCODE:
	gethostname(strbuf,MAXDNAME);
	ST(0) = sv_2mortal(newSVpv(strbuf,0));
	XSRETURN(1);

int
t_not_numeric(cp)
	char * cp
    CODE:
	RETVAL = not_numericIP(cp);
    OUTPUT:
	RETVAL

int
t_munge(fd,bp,msglen,is_tcp)
 	int	fd
	unsigned char * bp
	size_t	msglen
	int	is_tcp
    CODE:
	memcpy(ns_msgbuf,bp,msglen);
	RETVAL = munge_msg(fd,msglen,is_tcp);
    OUTPUT:
	RETVAL

int
t_cmdline(cmd,stuff)
	char * cmd
	char * stuff
    PREINIT:
	char c = *cmd;
    CODE:
	RETVAL = my_cmdline(c,stuff);
    OUTPUT:
	RETVAL

int
t_set_resp(serial_ip,stdip,stdbip)
	char * serial_ip
	char * stdip
	char * stdbip
    CODE:
	if ((inet_aton(serial_ip,&serial_rec) == 0) || 
	    (inet_aton(stdip,&stdResp) == 0) ||
	    (inet_aton(stdbip,&stdRespBeg) == 0))
	    XSRETURN_UNDEF;
	RETVAL = 1;
    OUTPUT:
	RETVAL

int
t_cmp_serial(s1,s2)
	unsigned long s1
	unsigned long s2
    CODE:
	RETVAL = my_cmp_serial(s1,s2);
    OUTPUT:
	RETVAL

int
t_name_skip(buf)
	unsigned char * buf
    PREINIT:
	unsigned char * out;
    CODE:
	out = name_skip(buf);
	RETVAL = (int)(out - buf);
    OUTPUT:
	RETVAL
