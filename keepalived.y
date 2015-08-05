/********************************************************
 * keepalived.y 
 ********************************************************/
%{
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

//-- Lexer prototype required by bison, aka getNextToken()
extern FILE *yyin;
extern int  errno;
extern char *optarg;
extern int  optind, opterr, optopt;
extern int  line_no;

#define YYERROR_VERBOSE 1

#define YYDEBUG 1
char *include_files[256];
int include_total = 0;

int yydebug;
int yylex(); 
int yyerror(const char *p) { printf("Error line %d, %s\n",line_no,p); }
int yywrap() {
  printf("OK!\n");
  fclose(yyin);
  if(include_total) { 
    char *name = include_files[--include_total];
    yyin = fopen(name, "r");
    if(NULL == yyin) {
      printf("ERROR: can not found %s\n", name);
      exit(1);
    }
    printf("checking %s\n", name);
    return 0; 
  }
  else return 1; 
}
%}

//-- SYMBOL SEMANTIC VALUES -----------------------------
%union {
  int integer;
  char *sym;

};

%token <integer> NUM 
%token <sym>	 IP4
%token <sym>	 IP4SLASH
%token <sym>     IP6 
%token		 DEBUG
%token           OPA OPM LB RB LP RP
%token <sym>     STRING_LITERAL ID EMAIL HEX32
%token           GLOBALDEFS  VRRPINSTANCE VIRTUALSERVER VIRTUALSERVERGROUP VIRTUALSYNCGROUP 
%token           HOST CONNECT_IP CONNECT_PORT BINDTO BINDTO_PORT
%token <sym>     NOTIFICATION_EMAIL SMTPSERVER SMTPCONNECTTIMEOUT ROUTER_ID
%token           LVSID VRRP_MCAST_G4 VRRP_MCAST_G6
%token		 SRC TO OR DEV VIA GW SCOPE TABLE BLACKHOLE
%token           PROTOCOL TCP UDP WEIGHT SMTP_CHECK
%token           RETRY CONNECT_TIMEOUT DELAY_BEFORE_RETRY
%token           VIRTUAL_ROUTER_ID STATE INTERFACE PRIORITY AUTHENTICATION AUTH_TYPE AUTH_PASS
%token           VIRTUAL_IPADDRESS TRACK_INTERFACE STATIC_ROUTE VIRTUAL_ROUTES VIRTUALGROUP DELAYLOOP
%token           LBALGO LBKIND PTIMEOUT SORRYSERVER PERSISTSTENCE_GRANULARITY
%token           REALSERVER HTTP_GET SSL_GET URL PATH DIGEST STATUS_CODE NB_GET_RETRY OPS VIRTUALHOST
%token           FWMARK HELO_NAME NOTIFICATION_EMAIL_FROM
%token           NAT DR TUN
%token           MASTER SLAVE MINUS
%token <sym>     PATHSTR
%token           LABEL VRRPSCRIPT SCRIPT FALL RISE TRACK_SCRIPT INTERVAL SCRIPT_WEIGHT
%token           NOTIFY_BACKUP NOTIFY_FAULT NOTIFY_MASTER GROUP VRRP_SYNC_GROUP 
%token           RR WRR LC WLC SH DH LBLC
%token		 TCP_CHECK
%token		 NOPREMPT PASS AH
%token		 INHIBIT_ON_FAILURE NOTIFY_UP NOTIFY_DOWN
%token		 MISC_CHECK WARMUP MISC_TIMEOUT MISC_PATH MISC_DYNAMIC
%token		 NATIVE_IPV6 VIRTUAL_IPADDRESS_EXCLUDE
%token		 GARP_MASTER_DELAY GARP_MASTER_REPEAT GARP_MASTER_REFRESH GARP_MASTER_REFRESH_REPEAT
%token		 UNICAST_PEER UNICAST_SRC_IP ADVERT_INT MCAST_SRC_IP VIRTUALINSTANCE LINK BRD NOPREEMPT
%token		 LVS_SYNC_DAEMON_INTERFACE VMAC_XMIT_BASE
%token		 PREEMPT_DELAY NOTIFY_STOP SMTP_ALERT
%token		 SITE DONT_TRACK_PRIMARY STATIC_IPA
%token		 S_SITE S_LINK S_NOWHERE S_GLOBAL S_HOST
%token		 USE_VMAC BACKUP NOTIFY	NOWHERE PERSISTSTENCE_TIMEOUT METRIC 
%token		 VIRTUAL_IPADDRESS_EXCLUDED NAT_MASK
%token		 IPV4 IPV6
%token		 ALPHA OMEGA HYSTERESIS QUORUM QUORUM_UP QUORUM_DOWN 
%token		 STOP
%token           INCLUDE
//-- GRAMMAR RULES ---------------------------------------
%%

keepconf:	main_stmts | main_stmts keepconf		{ }
|STOP				{ exit(0); }
		;

main_stmts: STATIC_ROUTE static_route_stmt	{ }
|STATIC_ROUTE LB static_route_stmts RB          { }
|STATIC_IPA LB static_ipa_stmts RB 	        { }
|global_part					{ }
|virtual_server_part				{ }
|VIRTUALSERVERGROUP ID LB vsg_list RB		{ }
|VRRPSCRIPT ID LB vrps_stmts RB			{ }
|vrrp_sync_group_part				{ }
|vrrp_instance_part				{ }
|include_stmt                                   { }
		;

static_ipa_stmts:  static_ipa_stmt | static_ipa_stmt static_ipa_stmts { }
		;

static_ipa_stmt: vir_stmt			{ }
		;


vrps_stmts:	 vrps_stmt  | vrps_stmt vrps_stmts { }
		;

vrps_stmt: SCRIPT STRING_LITERAL		{ }
|INTERVAL NUM					{ }
|SCRIPT_WEIGHT num				{ }
|FALL num					{ }
|RISE num					{ }
		;

num: MINUS NUM					{ $<integer>$ = - $<integer>1; }
|NUM						{ $<integer>$ = $<integer>0; }
		;

static_route_stmts:	static_route_stmt | static_route_stmt static_route_stmts { }
		;

vsg_list:	vsg_stmt | vsg_stmt vsg_list { }
		;

vsg_stmt: ip46					{ }
|NUM						{ }
|MINUS NUM NUM				        { }
|MINUS NUM                                      { }
|FWMARK NUM				 	{ }
		;

static_route_stmt: SRC ip46			{ }
|IP4SLASH route_options				{ /* printf ( "%s",$<sym>1 ); */ } 	
|ip46 route_options			        { /* printf ( "%s",$<sym>1 ); */ } 
|BLACKHOLE ip46					{ /* printf ( "%s",$<sym>1 ); */ } 
|BLACKHOLE IP4SLASH				{ /* printf ( "%s",$<sym>1 ); */ } 
		;

route_options: route_option | route_option route_options { }
		;

route_option: TO				{ }
|SRC ip46					{ /* printf ( "%s",$<sym>1 ); */ } 
|VIA ip46					{ /* printf ( "%s",$<sym>1 ); */ } 
|DEV STRING_LITERAL				{ /* printf ( "%s",$<sym>1 ); */ } 
|GW ip46					{ /* printf ( "%s",$<sym>1 ); */ } 
|SCOPE scope					{ /* printf ( "%s",$<sym>1 ); */ } 
|TABLE STRING_LITERAL				{ /* printf ( "%s",$<sym>1 ); */ } 						
		;

scope:						{ }
|S_SITE						{ }
|S_LINK						{ }
|S_GLOBAL					{ }
|S_NOWHERE					{ }
|S_HOST						{ }	
		;

ip46: IP4|IP6 { $<sym>$ = $<sym>0; }
		;


global_part:	GLOBALDEFS LB global_stmt_list RB
		;

global_stmt_list:	global_stmt | global_stmt global_stmt_list
		;

global_stmt: NOTIFICATION_EMAIL LB mail_stmt_list RB 	{ } 
| NOTIFICATION_EMAIL any_literal		{ /* printf ( "%s",$<sym>1 ); */ } 
| NOTIFICATION_EMAIL_FROM any_literal           { /* printf ( "%s",$<sym>1 ); */ } 
| SMTPSERVER IP4				{ /* printf ( "%s",$1 ); */ } 
| SMTPSERVER STRING_LITERAL                     { /* printf ( "%s",$<sym>1 ); */ } 
| SMTPCONNECTTIMEOUT NUM                        { /* printf ( "%s",$<sym>1 ); */ }  
| ROUTER_ID ID					{ /* printf ( "%s",$<sym>1 ); */ } 
| VRRP_MCAST_G4                                 { /* printf ( "%s",$<sym>1 ); */ } 
| VRRP_MCAST_G4  IP4                            { /* printf ( "%s",$<sym>1 ); */ } 
| VRRP_MCAST_G6                                 { /* printf ( "%s",$<sym>1 ); */ } 
| VRRP_MCAST_G6  IP6                            { /* printf ( "%s",$<sym>1 ); */ } 
		;


mail_stmt_list:  mail_stmt |  mail_stmt mail_stmt_list { }
		;

mail_stmt:	 any_literal			{ /* printf ( "%s",$<sym>1 ); */ } 
		;


virtual_server_part: VIRTUALSERVER iporfw LB virtual_server_stmts RB { }
|VIRTUALSERVER VIRTUALGROUP STRING_LITERAL LB virtual_server_stmts RB { }
		;


virtual_server_stmts: virtual_server_stmt | virtual_server_stmt virtual_server_stmts { }
		;

iporfw:						{ }
|IP6						{ }
|IP6 NUM					{ }
|IP4 						{ /* printf ( "%s",$<sym>1 ); */ }
|IP4 NUM					{ /* printf ( "%s",$<sym>1 ); */ } 
|FWMARK NUM					{ /* printf ( "%s",$<sym>1 ); */ }
		;


virtual_server_stmt: DELAYLOOP NUM		{ /* printf ( "%s %s",$<sym>0,$<sym>1 ); */ } 
| LBALGO lbalgo					{ /* printf ( "%s %s",$<sym>0,$<sym>1 ); */ } 
| LBKIND lbkind 				{ /* printf ( "%s %s",$<sym>0,$<sym>1 ); */ } 
| PERSISTSTENCE_TIMEOUT NUM			{ /* printf ( "%s %s",$<sym>0,$<sym>1 ); */ } 
| PERSISTSTENCE_GRANULARITY IP4			{ /* printf ( "%s %s",$<sym>0,$<sym>1 ); */ } 
| VIRTUALHOST any_literal			{ /* printf ( "%s %s",$<sym>0,$<sym>1 ); */ } 
| ADVERT_INT NUM				{ /* printf ( "%s %s",$<sym>0,$<sym>1 ); */ } 
| SORRYSERVER ip46 NUM				{ /* printf ( "%s %s",$<sym>0,$<sym>1 ); */ } 
| PROTOCOL TCP					{ /* printf ( "%s %s",$<sym>0,$<sym>1 ); */ } 
| PROTOCOL UDP					{ /* printf ( "%s %s",$<sym>0,$<sym>1 ); */ } 
| OPS						{ /* printf ( "%s",$<sym>1 ); */ } 
| NAT_MASK ip46					{ }
| ALPHA                                         { }
| OMEGA                                         { }
| QUORUM num					{ }
| HYSTERESIS num                                { }
| QUORUM_UP PATHSTR	                        { }
| QUORUM_DOWN PATHSTR		                { }
| REALSERVER ip46 LB real_server_stmts RB 	{ }
| REALSERVER ip46 NUM LB real_server_stmts RB 	{ }

		;
lbalgo:						{ }
|RR						{ }
|WRR						{ }
|LC						{ }
|WLC						{ }
|SH						{ }
|DH						{ }
|LBLC						{ }
		;
lbkind:						{ }
|NAT						{ }	
|UDP						{ }
|TUN						{ }
		;

real_server_stmts:	real_server_stmt | real_server_stmt real_server_stmts { }
		;

real_server_stmt: WEIGHT NUM			{ /* printf ( "%s",$<sym>1 ); */ } 
|INHIBIT_ON_FAILURE                             { /* printf ( "%s",$<sym>1 ); */ } 
|NOTIFY_UP STRING_LITERAL                       { /* printf ( "%s",$<sym>1 ); */ } 
|NOTIFY_DOWN STRING_LITERAL                     { /* printf ( "%s",$<sym>1 ); */ } 
|CONNECT_TIMEOUT NUM                            { }
|TCP_CHECK LB tcp_check_stmts RB		{ }
|SMTP_CHECK LB smtp_check_stmts RB		{ }
|MISC_CHECK LB misc_check_stmts RB		{ }
|HTTP_GET LB http_common_stmts RB 		{ /* printf ( "%s",$<sym>1 ); */ } 
|SSL_GET LB http_common_stmts RB                { /* printf ( "%s",$<sym>1 ); */ } 
		;


tcp_check_stmts: tcp_check_stmt | tcp_check_stmt tcp_check_stmts { }
		;

http_common_stmts: http_common_stmt | http_common_stmt http_common_stmts { }
		;

http_common_stmt: URL LB url_stmts RB				{ }
|HOST LB host_stmts RB				{ }
|CONNECT_TIMEOUT NUM                            { }
|CONNECT_PORT NUM				{ }
|WARMUP NUM					{ /* printf ( "%s",$<sym>1 ); */ } 
|DELAY_BEFORE_RETRY NUM                         { /* printf ( "%s",$<sym>1 ); */ } 
|NB_GET_RETRY NUM				{ /* printf ( "%s",$<sym>1 ); */ } 
		;

url_stmts:	url_stmt | url_stmt url_stmts { }
		;

url_stmt: PATH STRING_LITERAL			{ /* printf ( "%s",$<sym>1 ); */ } 
|PATH PATHSTR					{ /* printf ( "%s",$<sym>1 ); */ } 
|DIGEST HEX32					{ /* printf ( "%s",$<sym>1 ); */ } 
|STATUS_CODE	NUM				{ /* printf ( "%s",$<sym>1 ); */ } 
		;

tcp_check_stmt: CONNECT_PORT NUM 		{ /* printf ( "%s",$<sym>1 ); */ } 
|CONNECT_TIMEOUT NUM				{ /* printf ( "%s",$<sym>1 ); */ } 

		;

host_stmts:	host_stmt | host_stmt host_stmts { }
		;

host_stmt:CONNECT_IP ip46			{ /* printf ( "%s",$<sym>1 ); */ } 
|CONNECT_PORT NUM				{ /* printf ( "%s",$<sym>1 ); */ } 
|BINDTO ip46					{ /* printf ( "%s",$<sym>1 ); */ } 
|BINDTO_PORT NUM				{ /* printf ( "%s",$<sym>1 ); */ } 
|CONNECT_TIMEOUT NUM				{ /* printf ( "%s",$<sym>1 ); */ } 	
|FWMARK NUM					{ /* printf ( "%s",$<sym>1 ); */ } 
		;


smtp_check_stmts: smtp_check_stmt | smtp_check_stmt smtp_check_stmts { } 
		;


smtp_check_stmt: CONNECT_TIMEOUT NUM            { /* printf ( "%s",$<sym>1 ); */ } 
|WARMUP NUM					{ /* printf ( "%s",$<sym>1 ); */ } 
|RETRY NUM					{ /* printf ( "%s",$<sym>1 ); */ } 
|DELAY_BEFORE_RETRY NUM				{ /* printf ( "%s",$<sym>1 ); */ } 
|HELO_NAME STRING_LITERAL			{ /* printf ( "%s",$<sym>1 ); */ } 
|HOST LB host_stmts RB				{ }
		;

vrrp_instance_part: VRRPINSTANCE ID LB virtualistmts RB { }
		;

virtualistmts: virtualistmt | virtualistmt virtualistmts { }
		;

virtualistmt: USE_VMAC				{ /* printf ( "%s",$<sym>1 ); */ } 
|VMAC_XMIT_BASE					{ /* printf ( "%s",$<sym>1 ); */ } 
|NATIVE_IPV6					{ /* printf ( "%s",$<sym>1 ); */ } 
|STATE MASTER|BACKUP				{ /* printf ( "%s",$<sym>1 ); */ } 
|TRACK_INTERFACE STRING_LITERAL			{ }
|TRACK_INTERFACE LB interface_list RB		{ }
|TRACK_SCRIPT LB track_stmts RB			{ }
|INTERFACE STRING_LITERAL			{ /* printf ( "%s",$<sym>1 ); */ } 
|DONT_TRACK_PRIMARY				{ /* printf ( "%s",$<sym>1 ); */ } 
|MCAST_SRC_IP IP4|IP6				{ /* printf ( "%s",$<sym>1 ); */ } 
|UNICAST_SRC_IP IP4				{ /* printf ( "%s",$<sym>1 ); */ } 
|UNICAST_SRC_IP IP6 	                        { /* printf ( "%s",$<sym>1 ); */ } 
|LVS_SYNC_DAEMON_INTERFACE STRING_LITERAL	{ /* printf ( "%s",$<sym>1 ); */ } 
|GARP_MASTER_DELAY NUM				{ /* printf ( "%s",$<sym>1 ); */ } 
|GARP_MASTER_REPEAT NUM				{ /* printf ( "%s",$<sym>1 ); */ } 
|GARP_MASTER_REFRESH NUM			{ /* printf ( "%s",$<sym>1 ); */ } 
|GARP_MASTER_REFRESH_REPEAT NUM			{ /* printf ( "%s",$<sym>1 ); */ } 
|VIRTUAL_ROUTER_ID NUM				{ /* printf ( "%s",$<sym>1 ); */ } 
|PRIORITY NUM					{ /* printf ( "%s",$<sym>1 ); */ } 
|ADVERT_INT NUM					{ /* printf ( "%s",$<sym>1 ); */ } 
|NOPREEMPT					{ /* printf ( "%s",$<sym>1 ); */ } 
|PREEMPT_DELAY NUM				{ /* printf ( "%s",$<sym>1 ); */ } 
|DEBUG						{ /* printf ( "%s",$<sym>1 ); */ } 
|NOTIFY_MASTER STRING_LITERAL			{ /* printf ( "%s",$<sym>1 ); */ } 
|NOTIFY_BACKUP STRING_LITERAL			{ /* printf ( "%s",$<sym>1 ); */ } 
|NOTIFY_FAULT STRING_LITERAL 			{ /* printf ( "%s",$<sym>1 ); */ } 
|NOTIFY_STOP STRING_LITERAL                	{ /* printf ( "%s",$<sym>1 ); */ } 
|NOTIFY STRING_LITERAL				{ /* printf ( "%s",$<sym>1 ); */ } 
|SMTP_ALERT					{ /* printf ( "%s",$<sym>1 ); */ } 
|AUTHENTICATION LB auth_stmts RB		{ }
|VIRTUAL_IPADDRESS LB vip_list RB		{ }
|VIRTUAL_IPADDRESS_EXCLUDED LB vip_list_ex RB	{ }
|VIRTUAL_ROUTES LB vir_list RB			{ }

		;
track_stmts:	track_stmt | track_stmt track_stmts { }

track_stmt:	ID				{ }
|WEIGHT num					{ }


interface_list:	interface_stmt | interface_stmt interface_list {}
		;

interface_stmt: STRING_LITERAL			{ }
|WEIGHT num					{ }

auth_stmts:	auth_stmt  | auth_stmt auth_stmts { }
		;	

auth_stmt: AUTH_TYPE	PASS			{ /* printf ( "%s",$<sym>1 ); */ } 
|AUTH_TYPE      AH				{ /* printf ( "%s",$<sym>1 ); */ } 
|AUTH_PASS	any_literal			{ /* printf ( "%s",$<sym>1 ); */ } 
		;

any_literal: EMAIL				{ }
|STRING_LITERAL					{ }
|ID						{ }
|NUM						{ }
|HEX32						{ }
		;
	
vip_list:	vipstmt | vipstmt vip_list	{ }
		;

vip_list_ex:	vipstmtex | vipstmtex vip_list_ex  { }
		;

vir_list:	vir_stmt | vir_stmt vir_list	{ }
		;

vir_stmt: SRC IP4				{ /* printf ( "%s",$<sym>1 ); */ } 
|TO  IP4 					{ /* printf ( "%s",$<sym>1 ); */ } 
|TO  IP4SLASH					{ /* printf ( "%s",$<sym>1 ); */ } 
|IP4						{ /* printf ( "%s",$<sym>1 ); */ } 
|IP4SLASH					{ /* printf ( "%s",$<sym>1 ); */ } 
|VIA IP4					{ /* printf ( "%s",$<sym>1 ); */ } 
|OR IP4						{ }
|DEV STRING_LITERAL				{ /* printf ( "%s",$<sym>1 ); */ } 
|SCOPE scope					{ /* printf ( "%s",$<sym>1 ); */ } 
|TABLE ID					{ /* printf ( "%s",$<sym>1 ); */ } 
|METRIC NUM					{ /* printf ( "%s",$<sym>1 ); */ } 
|BLACKHOLE					{ }
		;

vipstmt: IP4SLASH				{ }
|IP4 						{ /* printf ( "%s",$<sym>1 ); */ } 
|BRD IP4					{ /* printf ( "%s",$<sym>1 ); */ } 
|DEV STRING_LITERAL				{ /* printf ( "%s",$<sym>1 ); */ } 
|SCOPE scope 					{ /* printf ( "%s",$<sym>1 ); */ } 
|LABEL STRING_LITERAL				{ /* printf ( "%s",$<sym>1 ); */ } 
		;

vipstmtex: IP4					{ /* printf ( "%s",$<sym>1 ); */ } 
|BRD IP4                                        { /* printf ( "%s",$<sym>1 ); */ } 
|DEV STRING_LITERAL                             { /* printf ( "%s",$<sym>1 ); */ } 
|SCOPE scope                                    { /* printf ( "%s",$<sym>1 ); */ } 
                ;

vrrp_sync_group_part: VRRP_SYNC_GROUP ID LB vsgp_stmts RB { }
		;


vsgp_stmts:	vsgp_stmt | vsgp_stmt vsgp_stmts { }
		;

vsgp_stmt:ID					{ }
|GROUP LB vrrp_group_list RB			{ }
|NOTIFY_BACKUP	STRING_LITERAL			{ }
|NOTIFY_MASTER	STRING_LITERAL			{ }
|NOTIFY_FAULT	STRING_LITERAL			{ }

  		;			

vrrp_group_list: vrrp_group_id | vrrp_group_id vrrp_group_list	{ }
		;

vrrp_group_id:	ID				{ }
		;


misc_check_stmts: misc_check_stmt | misc_check_stmt misc_check_stmts { }
		;

misc_check_stmt: MISC_PATH PATHSTR		{ /* printf ( "%s",$<sym>1 ); */ } 
|MISC_PATH STRING_LITERAL			{ /* printf ( "%s",$<sym>1 ); */ }
|MISC_TIMEOUT NUM				{ /* printf ( "%s",$<sym>1 ); */ } 
|WARMUP NUM					{ /* printf ( "%s",$<sym>1 ); */ } 
|MISC_DYNAMIC					{ /* printf ( "%s",$<sym>1 ); */ } 
		;

include_stmt: INCLUDE PATHSTR   {
     printf("include %s\n", $<sym>2);
     include_files[include_total] = $<sym>2;
     include_total++;
 } 
           ;

%%
int main(int args, char *argv[])
{
  extern FILE *yyin;
  char *name;
  if(args < 2) {
     name = "/etc/keepalived/keepalived.conf";
  }
  else {
     name = argv[1];
  }
  printf("checking %s\n", name);
  yyin = fopen(name, "r");
  yyparse();
  return 0;
}
