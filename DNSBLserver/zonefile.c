/* zonefile.c
 *
 * Copyright 2004, Michael Robinton <michael@bizsystems.com>
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
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <bdbtarpit.h>
#include "ns_func.h"
#include "defines.h"
#include "host_info_func.h"

u_char ah,am,al,az,bh,bm,bl,bz,ch,cm,cl,cz,dh,dm,dl,dz,org;
char txa[512], txb[512], txc[512], txd[512], pbuf[24], fbuf[24];
u_int32_t aa, ab, ac, ad, A_rec;
struct in_addr in;

void
initlb()
{
  extern u_char ah,am,al,az,bh,bm,bl,bz,ch,cm,cl,cz,dh,dm,dl,dz,org;
  extern char txa[],txb[],txc[],txd[];
  ah = am = al = az = bh = bm = bl = bz = ch = cm = cl = cz = dh = dm = dl = dz = org = 0;
  aa = ab = ac = ad = 0;
  memset(txa,0,512);
  memset(txb,0,512);
  memset(txc,0,512);
  memset(txd,0,512);
}

void
tabout(char * bp, char * name, char * type)
{
  size_t len = strlen(name);
  char * tp;
  if (len < 8)
    tp = "\t\t\t";
  else if (len < 16)
    tp = "\t\t";
  else if (len < 24)
    tp = "\t";
  else
    tp = " ";
  sprintf(bp,"%s%s%s\t",name,tp,type);
}

void
add_A_rec(char * bp, char * name, u_int32_t * ip)
{
  extern struct in_addr in;
  tabout(bp,name,"A");
  in.s_addr = *ip;
  strcat(bp,inet_ntoa(in));
}

void
ishift()
{
  extern u_char ah,am,al,az,bh,bm,bl,bz,ch,cm,cl,cz,dh,dm,dl,dz;
  extern char txa[], txb[], txc[], txd[];
  extern u_int32_t aa,ab,ac,ad;

  dh = ch; dm = cm; dl = cl; dz = cz;
  ch = bh; cm = bm; cl = bl; cz = bz;
  bh = ah; bm = am; bl = al; bz = az;
  ad = ac; ac = ab; ab = aa;
  strncpy(txd,txc,512);
  strncpy(txc,txb,512);
  strncpy(txb,txa,512);
}

void
precrd(FILE * fd, char * bp, char * name, u_int32_t resp, char * txt)
{
  extern struct in_addr in;
  extern int Zflag;

  tabout(bp,name,"A");
  in.s_addr = resp;
  fprintf(fd,"%s%s\n",bp,inet_ntoa(in));
  if (Zflag == 0)
    fprintf(fd,"\t\t\tTXT\t\"%s\"\n",txt);
}

void
oflush(FILE * fd, char * bp)
{
  extern u_char bh,bm,bl,bz,ch,cm,cl,cz,dh,dm,dl,dz;
  extern char txb[], txc[], txd[], fbuf[]; 
  extern u_int32_t ab, ac, ad;
  extern u_char org;
  
  char * rif = fbuf;

  if (org == 1) {
    if (bh) {
      sprintf(rif,"%u.%u.%u.%u",bz,bl,bm,bh);
      precrd(fd,bp,rif,ab,txb);
    }
  } 
  else if (org == 2) {
    if (ch) {
      sprintf(rif,"%u.%u.%u",cz,cl,cm);
      precrd(fd,bp,rif,ac,txc);
    }
    if (bh) {
      sprintf(rif,"%u.%u.%u",bz,bl,bm);
      precrd(fd,bp,rif,ab,txb);
    }
  }
  else if (org == 3) {
    if (dh) {
      sprintf(rif,"%u.%u",dz,dl);
      precrd(fd,bp,rif,ad,txd);
    }
    if (ch) {
      sprintf(rif,"%u.%u",cz,cl);
      precrd(fd,bp,rif,ac,txc);
    }
    if (bh) {
      sprintf(rif,"%u.%u",bz,bl);
      precrd(fd,bp,rif,ab,txb);
    }
  }
  else if (org == 4) {
    if (dh) {
      sprintf(rif,"%u",dz);
      precrd(fd,bp,rif,ad,txd);
    }
    if (ch) {
      sprintf(rif,"%u",cz);
      precrd(fd,bp,rif,ac,txc);
    }
    if (bh) {
      sprintf(rif,"%u",bz);
      precrd(fd,bp,rif,ab,txb);
    }
  }
  bh = ch = dh = 0;
}

void
oprint(FILE * fd, char * bp, u_char new, char * pre)
{
  extern u_char org;
  extern char * zone_name;

  if (new <= org)
	oflush(fd,bp);
  if (new != org)
    fprintf(fd,"$ORIGIN %s%s.\n",pre,zone_name);

  org = new;
}

void
iload(u_char * iptr, u_int32_t * A_resp, char * txt)
{
  extern u_char ah,am,al,az;
  extern char txa[];

  ishift();							/* shift lookback stack */
  ah = *iptr;
  am = *(iptr +1);
  al = *(iptr +2);
  az = *(iptr +3);
  aa = *A_resp;
  strncpy(txa,txt,512);
}


void
iprint(FILE * fd, char * bp)
{
  extern u_char ah,am,al,az,bh,bm,bl,bz,ch,cm,cl,cz,dh,dm,dl,dz,org;
  extern struct in_addr in;
  extern char pbuf[], txd[];
  extern u_int32_t ad;

  char * rif = pbuf;

  *rif = 0;

  if (ah != bh || (ch && bh != ch) || (dh && ch != dh)) {
    oprint(fd,bp,1,"");
    return;
  }
  if (am != bm || (ch && bm != cm) || (dh && cm != dm)) {
    sprintf(rif,"%u.",ah);
    oprint(fd,bp,2,rif);
    return;
  }
  if (al != bl || (ch && bl != cl) || (dh && cl != dl)) {
    sprintf(rif,"%u.%u.",am,ah);
    oprint(fd,bp,3,rif);
    return;
  }
  if (org < 4) {
    sprintf(rif,"%u.%u.%u.",al,am,ah);
    oprint(fd,bp,4,rif);
  }
/*  if (dh) {
    tabout(bp,rif,"A");
    in.s_addr = aa;
    fprintf(fd,"%u %s%s\n",bp,inet_ntoa(in));
  }
*/
  if (dh) {
    sprintf(rif,"%u",dz);
    precrd(fd,bp,rif,ad,txd);
  }
}

/*  re	turns 0 on success
 *  1 if serial number missing
 * -1 if start/end serial numbers do not match
 */

int
zonefile(FILE * fd)
{
  extern char * dbhome;
  extern char * errormsg;
  extern char * local_name;
  extern char * contact;
  extern char * zone_name;
  extern int zone_name_len;
  extern int zoneEQlocal;
  extern DBTPD dbtp;
  extern struct in_addr stdResp, stdRespBeg, stdRespEnd, serial_rec, in;
  extern u_int32_t refresh, retry, expire, minimum, soa_ttl, localip[], A_rec;
  extern int h_name_ctr, mxmark[], visibleMAXeth;
  extern int zflag, run, dflag;
  extern char mybuffer[], * stdErr_response, version[];
  extern pid_t parent;
  extern u_char ah,am,al,az,bh,bm,bl,bz,ch,cm,cl,cz,dh,dm,dl,dz,org;
  
  int type, class, n, i;
  char * Hptr, * bp;
  u_int32_t serial, lserial, * Aptr, * Astart, * A_resp, numrecs;
  u_short len;
  u_int32_t recno = 1;
  int serial_missing = 1;
  time_t current = time(NULL);

/* fetch the number of records 
   (including overhead records that are not printed out) 
   in that will be sent to zonefile
 */
  if (zflag != 0)			/* if promiscous reporting	*/
    numrecs = dbtp_stati(&dbtp,DBtarpit);
  else
    numrecs = dbtp_stati(&dbtp,DBevidence);

/* version, number of records (more or less), date, ORIGIN, and TTL for SOA	*/
  fprintf(fd,"; Version: %s\n; %u A records\n; zone dump on %s\n$ORIGIN .\n$TTL %u\n",version,numrecs,ctime(&current),soa_ttl);
  bp = mybuffer;
  tabout(bp,zone_name,"IN SOA");				/* zonename IN SOA		*/
  fprintf(fd,"%s%s. %s. (\n",bp,local_name,contact);		/* name contact (		*/
  if (dbtp_get(&dbtp,DBtarpit,(void *)&serial_rec.s_addr,sizeof(serial_rec.s_addr))) {
    serial = (u_int32_t)(time(NULL));
  } else {
    serial = *(u_int32_t *)(dbtp.mgdbt.data);
    serial_missing = 0;
  }								/* serial, refresh, retry, expire, minimum	*/
  fprintf(fd,"\t\t\t\t%u\n\t\t\t\t%u\n\t\t\t\t%u\n\t\t\t\t%u\n\t\t\t\t%u\n\t\t\t\t)\n",serial,refresh,retry,expire,minimum);
  fprintf(fd,"$TTL %d\n",minimum);				/* TTL for all other records		*/
  if (zoneEQlocal) {						/* add local name if zone is local	*/
    for(i=0;i<visibleMAXeth;i++) {
      if (localip[i] == 0)
	break;
      add_A_rec(bp,"",&(localip[i]));
      fprintf(fd,"%s\n",bp);
    }
  }

  for(i=0;i<h_name_ctr;i++) {
    if (mxmark[i])
	continue;
    Hptr = current_name(i);
    fprintf(fd,"\t\t\tNS\t%s.\n",Hptr);
  }

  for(i=0;i<h_name_ctr;i++) {
    if (mxmark[i] == 0)
	continue;
    Hptr = current_name(i);
    fprintf(fd,"\t\t\tMX %d\t%s.\n",mxmark[i],Hptr);
  }

  if (h_name_ctr)
	fprintf(fd,"$ORIGIN %s.\n",zone_name);

  for(i=0;i<h_name_ctr;i++) {
    Hptr = current_name(i);
/*	name ends in zone name and is not local name	*/
    if (((len = strlen(Hptr)) >= zone_name_len) &&
	(strcasecmp((u_char *)(Hptr - zone_name_len + len), zone_name) == 0) &&
	 strcasecmp((u_char *)Hptr,local_name)) {
      Aptr = Astart = current_Astart(i);
      memset(txa,0,512);
      if ((len = len - zone_name_len -1) > 0)
	strncpy(txa,Hptr,len);
      Hptr = txa;
      do {
	add_A_rec(bp,Hptr,Aptr);
	fprintf(fd,"%s\n",bp);
	*Hptr = 0;
      } while((Aptr = next_A_record(Astart,Aptr)) != NULL);
    }
  }

/* init lookback	*/
  initlb();

/* **************************************************** *
 *	overhead records complete, add numeric records	*
 * ****************************************************	*
 */

  while (1) {
  NEXT_RECORD:
    if (dbtp_getrecno(&dbtp,DBtarpit, recno++))
	break;

/*	suppress numeric record for 127.0.0.0, it is used internally	*/
    if (*(u_char *)dbtp.keydbt.data == 0x7F &&
      *(u_char *)(dbtp.keydbt.data +1) == 0 &&
      *(u_char *)(dbtp.keydbt.data +2) == 0 &&
      *(u_char *)(dbtp.keydbt.data +3) == 0)
	goto NEXT_RECORD;					/* skip serial number	*/

    A_rec = *(u_int32_t *)dbtp.keydbt.data;
    in.s_addr = A_rec;						/* propagate IP for errIP() use	*/

    if ((A_resp = ns_response()) == NULL)
	goto NEXT_RECORD;				/* do not report promiscious contributions	*/

    iload((u_char *)&A_rec,A_resp,stdErr_response);
    iprint(fd,bp);

  }	/* end while(1)		*/

  ishift();
  oflush(fd,bp);

  fclose(fd);
  
  if (serial_missing)
	return 1;

/* check if serial numbers match, and return result. 
   a change means the record has been modified and no record update will occur
 */
  dbtp_get(&dbtp,DBtarpit,(void *)&serial_rec.s_addr,sizeof(serial_rec.s_addr));
  if (serial == *(u_int32_t *)(dbtp.mgdbt.data))
	return 0;		/* SUCCESS, return 0			*/
  return -1;			/* :-( serial numbers do not match	*/
}  
