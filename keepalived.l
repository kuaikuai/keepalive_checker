/********************************************************
 * keepalived.l 
 * 
 * 
 * part         Section                         Comment
 * gd           global  section
 * vs		virtual server section
 * vsg          virtual sync group section
 * vi           virtual instance section
 * vrsg		vrrp sync group
 * 
 * bison -d keepalived.y
 * flex keepalived.l
 * gcc -g -c lex.yy.c -o parser.lex.o
 * gcc -g -c keepalived.tab.c -o parser.bison.o
 * gcc -g -o parser parser.bison.o parser.lex.o
 *
 * ./parser keepalves.conf 
 *
 ********************************************************/

%{
#include <stdlib.h>
#include <string.h>
#include "keepalived.tab.h"

//#define TEST_LEX 1
#undef TEST_LEX


#ifdef TEST_LEX

YYSTYPE yylval;

// YYLTYPE yylloc;
#else


extern YYSTYPE yylval;
// extern YYLTYPE yylloc;
#endif

static void yy_push_state(int);
static int yy_top_state(void);
int cond;

int line_no = 1;
int debug   = 0;
int brac_lev = 0;



#define  LEX_NUMBER_TOKEN(s,r)      if(debug) { printf("%s -> %i ",s,r); } yylval.integer = atoi(yytext); return r
#define  LEX_STRING_TOKEN(s,r)      if(debug) { printf("%s -> %i ",s,r); } yylval.sym = strdup(yytext);   return r
#define  LEX_IDENTIFIER_TOKEN(s,r)  if(debug) { printf("%s -> %i ",s,r); } yylval.sym = strdup(yytext);   return r
#define  LEX_KEYWORD_TOKEN(s,r)     if(debug) { printf("line:%d %s -> %i\n",line_no,s,r); } yylval.integer = r;            return r
#define  LEX_ESCAPED_TOKEN(s,r)     if(debug) { printf("%s ->%i ",s,r); } yylval.sym = strdup(yytext);   return r
#define  LEX_ERRMSG(s,r)            if(debug) { printf("%s ->%i ",s,r); }                                return r
%}

%option stack

%option nounput

%option full

%option never-interactive


newline			"\n"
dot			"\."
not_newline             "."
backslash		"\\"
quote			[\"]
tick			"\'"
strchr			[^\"\n\\]
any			[{newline}|{not_newline}]
ws			[ \f\v\t]
digit			[0-9]
oct                     ({digit}|([1-9]{digit})|(1{digit}{digit})|(2[0-4]{digit})|(25[0-5]))
digits			{digit}+
hex                     ({digit}|[A-Fa-f])
letter			[a-z_A-Z]
escape			({backslash}{any})
comment                 "/""*"([^*]|"*"*[^*/])*"*"+"/"
ip4			{oct}{dot}{oct}{dot}{oct}{dot}{oct}
ip4slash		({ip4})+"/"+(({digit}){1,2})
hex4			([0-9a-fA-F]{4})
hex32			([0-9a-fA-F]{32})
h4			([0-9a-fA-F]{1,4})
ip6			(({h4}:){7}{h4}|({h4}:){1,7}:|({h4}:){1,6}:{h4}|({h4}:){1,5}(:{h4}){1,2}|({h4}:){1,4}(:{h4}){1,3}|({h4}:){1,3}(:{h4}){1,4}|({h4}:){1,2}(:{h4}){1,5}|{h4}:((:{h4}){1,6})|:((:{h4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}({oct}\.){3}({oct})|({h4}:){1,4}:({oct}\.){3}({oct}))
identifier              ({letter}({letter}|{digit})*)
email                   ([a-zA-Z0-9\-\.]+@[a-zA-Z0-9\-\.]*)
hostname                (({letter}|{digit})+({dot}({letter}|{digit}|_|-)*)*)
string                  {quote}.*+{quote}
pathstr			(\/([a-zA-Z0-9\.\/\-_])*)
label			([a-zA-Z0-9]+:[a-zA-Z0-9]+)
interface		([a-zA-Z0-9\.\:]+)

%s			gd vs vi vsg vrsg smtpc vrrps

%%

{ip6}				{ LEX_STRING_TOKEN(yytext, IP6); }
{ip4}                  		{ LEX_STRING_TOKEN(yytext, IP4); }
{ip4slash}                      { LEX_STRING_TOKEN(yytext, IP4SLASH); }
{hex32}      	          	{ LEX_STRING_TOKEN(yytext, HEX32); }
{digits}        		{ LEX_NUMBER_TOKEN(yytext, NUM); }
{pathstr}			{ LEX_STRING_TOKEN(yytext, PATHSTR); }
"{"				{ ++brac_lev; LEX_KEYWORD_TOKEN(yytext, LB); }
"}"				{ --brac_lev; if (!brac_lev) BEGIN(INITIAL);  LEX_KEYWORD_TOKEN(yytext,  RB); }
include                         { LEX_KEYWORD_TOKEN(yytext, INCLUDE); }
static_ipaddress		{ LEX_KEYWORD_TOKEN(yytext, STATIC_IPA); }
src  		                { LEX_KEYWORD_TOKEN(yytext, SRC); }
or				{ LEX_KEYWORD_TOKEN(yytext, OR); }
brd				{ LEX_KEYWORD_TOKEN(yytext, BRD); }
scope				{ LEX_KEYWORD_TOKEN(yytext, SCOPE); }
blackhole			{ LEX_KEYWORD_TOKEN(yytext, BLACKHOLE); }
global_defs			{ BEGIN(gd);    LEX_KEYWORD_TOKEN(yytext, GLOBALDEFS); }
vrrp_instance			{ BEGIN(vi);    LEX_KEYWORD_TOKEN(yytext, VRRPINSTANCE); }
virtual_server			{ BEGIN(vs);    LEX_KEYWORD_TOKEN(yytext, VIRTUALSERVER); }
virtual_server_group		{ BEGIN(vsg);   LEX_KEYWORD_TOKEN(yytext, VIRTUALSERVERGROUP); }
virtual_sync_group		{ BEGIN(vrsg);  LEX_KEYWORD_TOKEN(yytext, VIRTUALSYNCGROUP); }
vrrp_sync_group                 { BEGIN(vrrps); LEX_KEYWORD_TOKEN(yytext, VRRP_SYNC_GROUP); }
vrrp_script			{ BEGIN(vrrps);	LEX_KEYWORD_TOKEN(yytext, VRRPSCRIPT); }
"-"				{ LEX_KEYWORD_TOKEN(yytext, MINUS); }
<*>host 	               	{ LEX_KEYWORD_TOKEN(yytext, HOST); }
<*>connect_ip 	       		{ LEX_KEYWORD_TOKEN(yytext, CONNECT_IP); }
<*>connect_port 	      	{ LEX_KEYWORD_TOKEN(yytext, CONNECT_PORT); }
<*>bindto     	       		{ LEX_KEYWORD_TOKEN(yytext, BINDTO); }
<*>bindto_port			{ LEX_KEYWORD_TOKEN(yytext, BINDTO_PORT); }
SMTP_CHECK             		{ LEX_KEYWORD_TOKEN(yytext, SMTP_CHECK); }
<gd>notification_email		{ LEX_KEYWORD_TOKEN(yytext, NOTIFICATION_EMAIL); }
<gd>smtp_server			{ LEX_KEYWORD_TOKEN(yytext, SMTPSERVER); }
<gd>smtp_connect_timeout	{ LEX_KEYWORD_TOKEN(yytext, SMTPCONNECTTIMEOUT); }
<gd>lvs_id			{ LEX_KEYWORD_TOKEN(yytext, ROUTER_ID); }
<gd>router_id			{ LEX_KEYWORD_TOKEN(yytext, ROUTER_ID); }
<gd>{email}			{ LEX_STRING_TOKEN(yytext, EMAIL); }
<gd>notification_email_from	{ LEX_STRING_TOKEN(yytext, NOTIFICATION_EMAIL_FROM); }
<vrrps>script			{ LEX_KEYWORD_TOKEN(yytext, SCRIPT); }
<vrrps>fall			{ LEX_KEYWORD_TOKEN(yytext, FALL); }
<vrrps>rise			{ LEX_KEYWORD_TOKEN(yytext, RISE); }
<vrrps>interval			{ LEX_KEYWORD_TOKEN(yytext, INTERVAL); }
<vrrps>weight			{ LEX_KEYWORD_TOKEN(yytext, SCRIPT_WEIGHT); }
<vi,vrrps>track_interface	{ LEX_KEYWORD_TOKEN(yytext, TRACK_INTERFACE); }
<vi,vrrps>track_script		{ LEX_KEYWORD_TOKEN(yytext, TRACK_SCRIPT); }
<vi>virtual_router_id		{ LEX_KEYWORD_TOKEN(yytext, VIRTUAL_ROUTER_ID); }
<vi>state			{ LEX_KEYWORD_TOKEN(yytext, STATE); }
<vi>MASTER			{ LEX_KEYWORD_TOKEN(yytext, MASTER); }
<vi>SLAVE			{ LEX_KEYWORD_TOKEN(yytext, SLAVE); }
<vi>BACKUP                       { LEX_KEYWORD_TOKEN(yytext, BACKUP); }
<vi>interface			{ LEX_KEYWORD_TOKEN(yytext, INTERFACE); }
<vi>priority			{ LEX_KEYWORD_TOKEN(yytext, PRIORITY); }
<vi>advert_int			{ LEX_KEYWORD_TOKEN(yytext, ADVERT_INT); }
<vi>authentication		{ LEX_KEYWORD_TOKEN(yytext, AUTHENTICATION); }
<vi>auth_type			{ LEX_KEYWORD_TOKEN(yytext, AUTH_TYPE); }
<vi>auth_pass			{ LEX_KEYWORD_TOKEN(yytext, AUTH_PASS); }
<vi>PASS			{ LEX_KEYWORD_TOKEN(yytext, PASS); }
<vi>AH				{ LEX_KEYWORD_TOKEN(yytext, AH); }
<vi>virtual_ipaddress		{ LEX_KEYWORD_TOKEN(yytext, VIRTUAL_IPADDRESS); }
<INITIAL,vi,gd>static_route	{ LEX_KEYWORD_TOKEN(yytext, STATIC_ROUTE); }
<INITIAL,vi,gd>static_routes	{ LEX_KEYWORD_TOKEN(yytext, STATIC_ROUTE); }
<INITIAL,vi,gd>dev		{ LEX_KEYWORD_TOKEN(yytext, DEV); }
<INITIAL,vi,gd>via		{ LEX_KEYWORD_TOKEN(yytext, VIA); }
<INITIAL,vi,gd>gw		{ LEX_KEYWORD_TOKEN(yytext, GW); }
<INITIAL,vi>site		{ LEX_KEYWORD_TOKEN(yytext, S_SITE); }
<INITIAL,vi>link		{ LEX_KEYWORD_TOKEN(yytext, S_LINK); }
<INITIAL>nowhere		{ LEX_KEYWORD_TOKEN(yytext, S_NOWHERE); }
<INITIAL>global			{ LEX_KEYWORD_TOKEN(yytext, S_GLOBAL); }
<vi>virtual_routes		{ LEX_KEYWORD_TOKEN(yytext, VIRTUAL_ROUTES); }
<vi>label			{ LEX_KEYWORD_TOKEN(yytext, LABEL); }
<vs>omega			{ LEX_KEYWORD_TOKEN(yytext, OMEGA); }
<vs>hysteresis			{ LEX_KEYWORD_TOKEN(yytext, HYSTERESIS); }
<vs>alpha			{ LEX_KEYWORD_TOKEN(yytext, ALPHA); }
<vs>quorum                      { LEX_KEYWORD_TOKEN(yytext, QUORUM); }
<vs>quorum_up			{ LEX_KEYWORD_TOKEN(yytext,QUORUM_UP); }
<vs>quorum_down			{ LEX_KEYWORD_TOKEN(yytext,QUORUM_DOWN); }
<vs>group			{ LEX_KEYWORD_TOKEN(yytext, VIRTUALGROUP); }
<vs>delay_loop                  { LEX_KEYWORD_TOKEN(yytext, DELAYLOOP); }
<vs>delay_lp			{ LEX_KEYWORD_TOKEN(yytext, DELAYLOOP); }
<vs>lb_algo			{ LEX_KEYWORD_TOKEN(yytext, LBALGO); }
<vs>lb_kind			{ LEX_KEYWORD_TOKEN(yytext, LBKIND); }
<vs>persistence_timeout		{ LEX_KEYWORD_TOKEN(yytext, PERSISTSTENCE_TIMEOUT); }
<vs>sorry_server		{ LEX_KEYWORD_TOKEN(yytext, SORRYSERVER); }
<vs>protocol			{ LEX_KEYWORD_TOKEN(yytext, PROTOCOL); }
<vs>TCP				{ LEX_KEYWORD_TOKEN(yytext, TCP); }
<vs>UDP				{ LEX_KEYWORD_TOKEN(yytext, UDP); }
<vs>NAT				{ LEX_KEYWORD_TOKEN(yytext, NAT); }
<vs>DR				{ LEX_KEYWORD_TOKEN(yytext, DR); }
<vs>TUN				{ LEX_KEYWORD_TOKEN(yytext, TUN); }
<vs>rr				{ LEX_KEYWORD_TOKEN(yytext, RR); }
<vs>wrr				{ LEX_KEYWORD_TOKEN(yytext, WRR); }
<vs>lc                          { LEX_KEYWORD_TOKEN(yytext, LC); }
<vs>wlc                         { LEX_KEYWORD_TOKEN(yytext, WLC); }
<vs>sh                          { LEX_KEYWORD_TOKEN(yytext, SH); }
<vs>dh                          { LEX_KEYWORD_TOKEN(yytext, DH); }
<vs>lblc                        { LEX_KEYWORD_TOKEN(yytext, LBLC); }
<vs>ops				{ LEX_KEYWORD_TOKEN(yytext, OPS); }
<vs>virtualhost			{ LEX_KEYWORD_TOKEN(yytext, VIRTUALHOST); }
<vs>inhibit_on_failure		{ LEX_KEYWORD_TOKEN(yytext, INHIBIT_ON_FAILURE); }
<vi>nopreempt			{ LEX_KEYWORD_TOKEN(yytext, NOPREEMPT); }
<vi>use_vmac			{ LEX_KEYWORD_TOKEN(yytext, USE_VMAC); }
<vi>vmac_xmit_base		{ LEX_KEYWORD_TOKEN(yytext, VMAC_XMIT_BASE); }
<vi>native_ipv6			{ LEX_KEYWORD_TOKEN(yytext, NATIVE_IPV6); }
<vi>dont_track_primary		{ LEX_KEYWORD_TOKEN(yytext, DONT_TRACK_PRIMARY); }
<vi>mcast_src_ip		{ LEX_KEYWORD_TOKEN(yytext, MCAST_SRC_IP); }
<vi>unicast_src_ip		{ LEX_KEYWORD_TOKEN(yytext, UNICAST_SRC_IP); }
<vi>unicast_peer		{ LEX_KEYWORD_TOKEN(yytext, UNICAST_PEER); }
<vi>lvs_sync_daemon_interface	{ LEX_KEYWORD_TOKEN(yytext, LVS_SYNC_DAEMON_INTERFACE); }
<vi>garp_master_delay		{ LEX_KEYWORD_TOKEN(yytext, GARP_MASTER_DELAY); }
<vi>garp_master_repeat		{ LEX_KEYWORD_TOKEN(yytext, GARP_MASTER_REPEAT); }
<vi>garp_master_refresh		{ LEX_KEYWORD_TOKEN(yytext, GARP_MASTER_REFRESH); }
<vi>garp_master_refresh_repeat	{ LEX_KEYWORD_TOKEN(yytext, GARP_MASTER_REFRESH_REPEAT); }
<vi>virtual_ipaddress_excluded	{ LEX_KEYWORD_TOKEN(yytext, VIRTUAL_IPADDRESS_EXCLUDED); }
<vs>nat_mask			{ LEX_KEYWORD_TOKEN(yytext, NAT_MASK); }
<vi>debug			{ LEX_KEYWORD_TOKEN(yytext, DEBUG); }
<vi>notify_master		{ LEX_KEYWORD_TOKEN(yytext, NOTIFY_MASTER); }
<vi>notify_backup		{ LEX_KEYWORD_TOKEN(yytext, NOTIFY_BACKUP); }
<vi>notify_fault		{ LEX_KEYWORD_TOKEN(yytext, NOTIFY_FAULT); }
<vi>notify_stop			{ LEX_KEYWORD_TOKEN(yytext, NOTIFY_STOP); }
<vi>notify			{ LEX_KEYWORD_TOKEN(yytext, NOTIFY); }
<vi>smtp_alert			{ LEX_KEYWORD_TOKEN(yytext, SMTP_ALERT); }
<vs,smtpc>real_server		{ LEX_KEYWORD_TOKEN(yytext, REALSERVER); }
<vi,vs,smtpc>weight		{ LEX_KEYWORD_TOKEN(yytext, WEIGHT); }
<vs>HTTP_GET			{ LEX_KEYWORD_TOKEN(yytext, HTTP_GET); }
<vs>SSL_GET			{ LEX_KEYWORD_TOKEN(yytext, SSL_GET); }
<vs>TCP_CHECK			{ LEX_KEYWORD_TOKEN(yytext, TCP_CHECK); }
<vs>MISC_CHECK			{ LEX_KEYWORD_TOKEN(yytext, MISC_CHECK); }
<vs>url				{ LEX_KEYWORD_TOKEN(yytext, URL); }
<vs>path			{ LEX_KEYWORD_TOKEN(yytext, PATH); }
<vs>digest			{ LEX_KEYWORD_TOKEN(yytext, DIGEST); }
<vs>hex32			{ LEX_KEYWORD_TOKEN(yytext, HEX32); }
<vs>status_code			{ LEX_KEYWORD_TOKEN(yytext, STATUS_CODE); }
<vs>connect_timeout		{ LEX_KEYWORD_TOKEN(yytext, CONNECT_TIMEOUT); }
<vs>nb_get_retry		{ LEX_KEYWORD_TOKEN(yytext, NB_GET_RETRY); }
<vs>delay_before_retry		{ LEX_KEYWORD_TOKEN(yytext, DELAY_BEFORE_RETRY); }
<vs,vsg>fwmark			{ LEX_KEYWORD_TOKEN(yytext, FWMARK); }
<vrsg,vrrps>group		{ LEX_KEYWORD_TOKEN(yytext, GROUP); }
<vrsg,vrrps>notify_backup	{ LEX_KEYWORD_TOKEN(yytext, NOTIFY_BACKUP); }
<vrsg,vrrps>notify_master	{ LEX_KEYWORD_TOKEN(yytext, NOTIFY_MASTER); }
<vrsg,vrrps>notify_fault	{ LEX_KEYWORD_TOKEN(yytext, NOTIFY_FAULT); }
<vs>retry			{ LEX_KEYWORD_TOKEN(yytext, RETRY); }
<vs>helo_name			{ LEX_KEYWORD_TOKEN(yytext, HELO_NAME); }
<vs>misc_path			{ LEX_KEYWORD_TOKEN(yytext, MISC_PATH); }
<vs>misc_timeout		{ LEX_KEYWORD_TOKEN(yytext, MISC_TIMEOUT); }
<vs>warmup			{ LEX_KEYWORD_TOKEN(yytext, MISC_TIMEOUT); }
<vs>misc_dynamic		{ LEX_KEYWORD_TOKEN(yytext, MISC_DYNAMIC); }
!.*\n				{ /* Throw away comment */ line_no++; }
#.*\n 				{ /* Throw away comment */ line_no++; }
{ws}+	 			{ /* Throw away whitespace */ }
<INITIAL,vi>{label}|{interface}	{ LEX_STRING_TOKEN(yytext, STRING_LITERAL); }
<vs>{hostname}			{ LEX_STRING_TOKEN(yytext, STRING_LITERAL); }
{string}  			{ LEX_STRING_TOKEN(yytext, STRING_LITERAL); }
<gd,vi,vsg,vrsg,vrrps>{identifier} { LEX_IDENTIFIER_TOKEN(yytext, ID); }
{newline}			{ /* Throw away newline */ line_no++;}
<*>.				{ printf("\nLex error at line: %d ->",line_no); ECHO ; printf("<-\n"); }
<<EOF>> 			{ BEGIN(INITIAL); return 0; }
%%



