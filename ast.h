#ifndef __AST_H
#define __AST_H

#include "pg_header.h"

#define MAX_COLNAME_LENGTH 128
#define isdigit_string(_s)  isdigit_strend(_s, NULL)
#define _DEVICES_SYS_NODE_ "/sys/devices/system/node"
#define _SSCANF_PARAMS_                                                                         \
    "%c "                                                                                       \
    "%d %d %d %d %d "                                                                           \
    "%lu %lu %lu %lu %lu "                                                                      \
    "%Lu %Lu %Lu %Lu "                                                                          \
    "%ld %ld "                                                                                  \
    "%d "                                                                                       \
    "%ld "                                                                                      \
    "%Lu "                                                                                      \
    "%llu "                                                                                     \
    "%ld "                                                                                      \
    "%llu " "%llu " "%llu " "%llu " "%llu " "%llu "                                             \
    "%*s %*s %*s %*s "                                                                          \
    "%llu" "%*u %*u "                                                                           \
    "%d %d "                                                                                    \
    "%llu %llu",                                                                                \
    &P->state,                                                                                  \
    &P->ppid, &P->pgrp, &P->session, &P->tty, &P->tpgid,                                        \
    &P->flags, &P->min_flt, &P->cmin_flt, &P->maj_flt, &P->cmaj_flt,                            \
    &P->utime, &P->stime, &P->cutime, &P->cstime,                                               \
    &P->priority, &P->nice,                                                                     \
    &P->nlwp,                                                                                   \
    &P->alarm,                                                                                  \
    &P->start_time,                                                                             \
    &P->vsize,                                                                                  \
    &P->rss,                                                                                    \
    &P->rss_rlim, &P->start_code, &P->end_code, &P->start_stack, &P->kstk_esp, &P->kstk_eip,    \
    &P->wchan,                                                                                  \
    &P->exit_signal, &P->processor,                                                             \
    &P->rtprio, &P->sched                                               


#define CFREE(a) do { 	\
	if (a) pfree(a);       \
	a = NULL;		          \
}while(0)

#define FCLOSE(a) do { 	\
	if (a) fclose(a);       \
	a = NULL;		          \
}while(0)

#define CERROR(msg)  do {  \
  yyerror(scanner,mod,msg);  \
  return 1; \
}while(0)

#define cnewNode(size, tag) \
({                      \
     CNode *_result;  \
     Assert((size) >= sizeof(CNode));    /* 检测申请的内存大小，>>=sizeof(Node) */ \
     _result = (CNode *) palloc(size);   /* 申请内存 */ \
     _result->type = (tag);             /*设置TypeTag */ \
     _result;                   		/*返回值*/\
})
#define makeCNode(_type_) ((_type_ *)cnewNode(sizeof(_type_),C_##_type_))
#define cnodeTag(nodeptr) (((const CNode *)(nodeptr))->type)
#define CNodeSetTag(nodeptr,t)	(((CNode*)(nodeptr))->type = (t))  
#define IsC(nodeptr,_type_)		(cnodeTag(nodeptr) == C_##_type_)  /* IsA(stmt,T_Stmt)*/
#define cforeach(cell, l)	\
	for ((cell) = clist_head(l); (cell) != NULL; (cell) = clnext(cell))

#define CNIL					((CList *) NULL)
#define clnext(lc)				((lc)->next)
#define clfirst(lc)				((lc)->data.ptr_value)
#define clist_make1(x1)      clcons(x1, CNIL)
#define IsPointerCList(l)    ((l) == CNIL || IsC((l), CList))


typedef struct
{
	int                     ppid;
	char                    cmd[32];
	char                    state;
	unsigned long long      utime;
	unsigned long long      stime;
	unsigned long long      cutime;
	unsigned long long      cstime;
	unsigned long long      start_time;
	unsigned long long      start_code;
	unsigned long long      end_code;
	unsigned long long      start_stack;
	unsigned long long      kstk_esp;
	unsigned long long      kstk_eip;
	unsigned long long      wchan;
	long                    priority;
	long                    nice;
	long                    rss;
	long                    alarm;
	unsigned long long      rtprio;
	unsigned long long      sched;
	unsigned long long      vsize;
	unsigned long long      rss_rlim;
	unsigned long           flags;
	unsigned long           min_flt;
	unsigned long           maj_flt;
	unsigned long           cmin_flt;
	unsigned long           cmaj_flt;
	int                     pgrp;
	int                     session;
	int                     nlwp;
	int                     tty;
	int                     tpgid;
	int                     exit_signal;
	int                     processor;
	char                    errmsg[64];
} proc_t;

struct lscpu_cxt {
	int maxcpus;        /* size in bits of kernel cpu mask */
	int cflag;
	size_t nnodes;      /* number of NUMA modes */
	int *cpuarr;        /* arr for cpu nodes */
};

typedef enum CNodeTag
{
	C_Node,
	C_CList,
	C_Cpro,
	C_CproList
} CNodeTag;

typedef struct CNode
{
	CNodeTag type;
} CNode;

typedef struct CListCell CListCell;

struct CListCell
{
	union
	{
		void    *ptr_value;   /* data */
		int     int_value;
	}       data;
	CListCell    *next;  
};

typedef struct CList
{
	CNodeTag   type;   /* T_List T_IntList .... */
	int       length; /* length of this list */
	CListCell  *head;
	CListCell  *tail;
} CList;

typedef struct CproList
{
	CNodeTag             type;
	unsigned int        cpunum;
	unsigned long int   pidnum;
} CproList;

typedef struct Cpro
{
	CNodeTag             type;
	CList           *cproList;
} Cpro;

typedef struct
{
	FILE        *src;
	int         cnum;

	bool		cproIsNull;
	Cpro        *cpro;

} module;


int	GetPidProcStat(pid_t pid, proc_t *p);
int	file2str(const char *dir, const char * what, char * ret, int cap);
int	isdigit_strend(const char *str, const char **end);
int	lscpu_read_numas(struct lscpu_cxt *cxt);
void lscpu_cxt_fini(struct lscpu_cxt *cxt);
void lscpu_cxt_init(struct lscpu_cxt *cxt);
void parse_cpu_list(char* cpu_list, struct lscpu_cxt* cpu_set);
void stat2proc(char *S, proc_t *__restrict__ P, int is_proc);
CList *clappend(CList *list, void *datum);
CList *clcons(void *datum, CList *list);
CList *new_clist(CNodeTag type);
void check_clist_invariants(const CList *list);
void new_head_ccell(CList *list);
void new_tail_ccell(CList *list);
void clist_free(CList *list);
void delete_cpro(Cpro *cpro);
void delete_cpro_module(module *mod);

static inline CListCell * clist_head(const CList *l){	return l ? l->head : NULL;}
static inline CListCell * clist_tail(CList *l)		{	return l ? l->tail : NULL;}
static inline int clist_length(const CList *l)		{	return l ? l->length : 0;}

int parse_module(module *mod);
module *new_module_from_file(const char *filename);
module *new_module_from_stdin(void);
module *new_module_from_string(char *src);

#endif
