%define api.pure full
%lex-param {void *scanner}
%parse-param {void *scanner}{module *mod} //  传入参数

%define parse.trace
%define parse.error verbose

%{
#include "ast.h"
#include "parser.h"
#include "scanner.h"

void yyerror (yyscan_t *locp, module *mod, char const *msg);

%}

%code requires
{
#include "ast.h"
}
%union 
{
    int 		intval;
	char 		*strval;
	Cpro		*cp;
	CproList 	*cplist;
	CNode 		*node;
	CList 		*list;
} /* Generate YYSTYPE from these types:  */

%token <strval>	NAME
%token <intval> PIDNUM

%type <mode> sexps
%type <cp> CproClause
%type <node> expr
%type <list> Expression
%type <strval> CPU_INFO

%%
%start sexps;

sexps:CproClause				{
									if ($1 != NULL)
									{
										mod -> cpro = $1;
										mod -> cproIsNull = false;
										mod -> cnum = mod -> cpro -> cproList -> length;
									}
									else
									{
										mod -> cpro = NULL;
										mod -> cproIsNull = true;
										mod -> cnum = 0;
									}
									return 0;
								};

CproClause:	'[' Expression ']'	{
									if ($2 != NULL)
									{
										$$ = makeCNode(Cpro);	
										$$ -> cproList = $2;
									}
									else
										$$ = NULL;
								};

Expression:	expr				{	
									if ($1 != NULL)
									$$ = clist_make1($1);	
								}
| Expression ',' expr			{	
									if ($3 != NULL)
									$$ = clappend($1, $3);	
								};


expr: 	{	}
| '{' CPU_INFO ':' PIDNUM '}'
								{
									if ($4 != 0)
									{
										CproList *cpro;
										cpro = makeCNode(CproList);
										cpro -> cpunum = atoi((const char *)($2 + 4));
										cpro -> pidnum = $4;
										$$ = (CNode *)cpro;
									}
									else
									{
										$$ = NULL;	
									}
								};

CPU_INFO: '"' NAME '"'			{	$$ = $2;	};

%%

void yyerror (yyscan_t *locp, module *mod, char const *msg) 
{
	fprintf(stderr, "--> %s\n", msg);
}

