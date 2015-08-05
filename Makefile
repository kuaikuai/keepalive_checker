all:
	gcc -g -o check check.bison.o check.lex.o
check.bison.o:
	gcc -g -c keepalived.tab.c -o check.bison.o
check.lex.o:
	gcc -g -c lex.yy.c -o check.lex.o
keepalived.tab.c:
	bison -d keepalived.y
lex.yy.c:
	flex keepalived.l
