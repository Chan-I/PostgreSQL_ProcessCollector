%{
#include "parser.h"
int oldstate;
%}

%option reentrant
%option yylineno
%option noinput
%option nounput
%option noyywrap

%option case-insensitive
%option bison-bridge

%x COMMENT
%s BTWMODE

%%
   /* numbers */ 
cpu_[0-9]*	{ yylval->strval = strdup(yytext);   return NAME; }
[0-9]*      { yylval->intval = atoi(yytext);     return PIDNUM; }
[{}\[\]":,] { return yytext[0]; }
