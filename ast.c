#include "ast.h"
#include "parser.h"
#include "scanner.h"

CList *
clcons(void *datum, CList *list)
{
	Assert(IsPointerCList(list));

	if (list == CNIL)
		list = new_clist(C_CList);
	else
		new_head_ccell(list);

	clfirst(list->head) = datum;
	return list;
}

CList *
new_clist(CNodeTag type)
{
	CList	   *new_list;
	CListCell   *new_head;

	new_head = (CListCell *) palloc(sizeof(*new_head));
	new_head->next = NULL;
	/* new_head->data is left undefined! */

	new_list = (CList *) palloc(sizeof(*new_list));
	new_list->type = type;
	new_list->length = 1;
	new_list->head = new_head;
	new_list->tail = new_head;

	return new_list;
}

void
new_head_ccell(CList *list)
{
	CListCell   *new_head;

	new_head = (CListCell *) palloc(sizeof(*new_head));
	new_head->next = list->head;

	list->head = new_head;
	list->length++;
}

void
new_tail_ccell(CList *list)
{
	CListCell   *new_tail;

	new_tail = (CListCell *) palloc(sizeof(*new_tail));
	new_tail->next = NULL;

	list->tail->next = new_tail;
	list->tail = new_tail;
	list->length++;
}

CList *
clappend(CList *list, void *datum)
{
	Assert(IsPointerCList(list));

	if (list == CNIL)
		list = new_clist(C_CList);
	else
		new_tail_ccell(list);

	clfirst(list->tail) = datum;
	return list;
}

void
check_clist_invariants(const CList *list)
{
	if (list == CNIL)
		return;

	Assert(list->length > 0);
	Assert(list->head != NULL);
	Assert(list->tail != NULL);

	if (list->length == 1)
		Assert(list->head == list->tail);
	if (list->length == 2)
		Assert(list->head->next == list->tail);
	Assert(list->tail->next == NULL);
}

static void
clist_free_private(CList *list, bool deep)
{
	CListCell   *cell;

	check_clist_invariants(list);

	cell = clist_head(list);
	while (cell != NULL)
	{
		CListCell   *tmp = cell;

		cell = clnext(cell);
		if (deep)
			CFREE(clfirst(tmp));
		CFREE(tmp);
	}

	CFREE(list);
}

void
clist_free(CList *list)
{
	clist_free_private(list, true);
}

module *
new_module_from_file(const char *filename)
{
    module *mod = (module *) palloc(sizeof(module));
    mod->src = fopen(filename, "r");
    return mod;
}

module *
new_module_from_stdin(void)
{
    module *mod = (module *) palloc(sizeof(module));
    mod->src = stdin;
    return mod;
}

module *
new_module_from_string(char *src)
{
    module *mod = (module *) palloc(sizeof(module));
    mod->src = fmemopen(src, strlen(src)+1, "r");
    return mod;
}

int
file2str(const char *dir, const char * what, char * ret, int cap)
{
	static char filename[40];
	int fd, num_read;

	sprintf(filename, "%s/%s", dir, what);
	fd = open(filename, O_RDONLY, 0);

	if (unlikely(fd==-1)) 
		return -1;

	num_read = read(fd, ret, cap - 1);
	close(fd);

	if (unlikely(num_read<=0)) 
		return -1;

	ret[num_read] = '\0';
	return num_read;
}

void
stat2proc(char *S, proc_t *__restrict__ P, int is_proc)
{
	unsigned num;
	char* tmp;

	P -> processor = 0;
	P -> rtprio = -1;
	P -> sched = -1;
	P -> nlwp = 0;

	S = strchr(S, '(') + 1;
	tmp = strrchr(S, ')');
	num = tmp - S;

	if (unlikely(num >= sizeof P->cmd))
		num = sizeof P->cmd - 1;

	memcpy(P->cmd, S, num);
	P->cmd[num] = '\0';
	S = tmp + 2;                 // skip ") "

	num = sscanf(S,_SSCANF_PARAMS_);

	if (!P->nlwp)
		P->nlwp = 1;
}

int
GetPidProcStat(pid_t pid, proc_t *p)
{
	static char path[PATH_MAX], sbuf[1024];
	struct stat statbuf;
	int ret = 1;
	char err[128];

	sprintf(path, "/proc/%d", pid);

	if (stat(path, &statbuf))
	{
		sprintf(err,"stat failed on %s,please check pid.",path);
		strcpy(p -> errmsg, err);
		return 0;
	}
	if (file2str(path, "stat", sbuf, sizeof sbuf) >= 0)
	{
		stat2proc(sbuf, p, 0 );
	}
	else
	{
		sprintf(err,"stat failed on %s",path);
		strcpy(p->errmsg, err);
		return 0;
	}
	return ret;
}

static int
convert_str_to_int(char* begin)
{
	char *end;
	long num;

	if (!begin)
		ereport(ERROR, (errmsg("Invalid arguments for %s", __func__)));

	errno = 0;
	end = NULL;
	num = strtol(begin, &end, 10);

	if (errno || (*end != '\0') || (num > INT_MAX) || (num < 0))
		ereport(ERROR, (errmsg("Invalid integer: %s", begin)));

	return (int)num;
}

void
parse_cpu_list(char* cpu_list, struct lscpu_cxt* cpu_set)
{
	char *begin, *hyphen, *end;	
	bool last_token;
	int first_cpu, last_cpu;
	cpu_list[strlen(cpu_list) - 1] = 0;

	if (!cpu_list || !cpu_set)
		ereport(ERROR, (errmsg("Invalid arguments for %s", __func__)));

	begin = cpu_list;
	while (1)
	{
		last_token = false;
		end = strchr(begin, ',');


		if (!end)
			last_token = true;
		else
			*end = '\0';

		hyphen = strchr(begin, '-');

		if (hyphen)
		{
			*hyphen = '\0';
			first_cpu = convert_str_to_int(begin);
			last_cpu = convert_str_to_int(hyphen + 1);

			if ((first_cpu > last_cpu) || (last_cpu >= cpu_set -> maxcpus))
				ereport(ERROR,(errmsg("Invalid cpu list: %s", cpu_list)));

			for (int i = first_cpu; i <= last_cpu; cpu_set -> cpuarr[cpu_set->cflag++] = i++);
		}
		else
			cpu_set->cpuarr[cpu_set->cflag++] = convert_str_to_int(begin);

		if (last_token)
			break;
		else
			begin = end + 1;
	}
}

int
isdigit_strend(const char *str, const char **end)
{
	const char *p;

	for (p = str; p && *p && isdigit((unsigned char) *p); p++);

	if (end)
		*end = p;

	return p && p > str && !*p;
}

static inline int
is_node_dirent(struct dirent *d)
{
	return
		d &&
		strncmp(d->d_name, "node", 4) == 0 &&
		isdigit_string(d->d_name + 4);
}

void
lscpu_cxt_init(struct lscpu_cxt *cxt)
{
	cxt -> cpuarr = malloc(cxt -> maxcpus * sizeof(int));
	cxt -> nnodes = 0;
	cxt -> cflag = 0;
}

void
lscpu_cxt_fini(struct lscpu_cxt *cxt)
{
	if (cxt->cpuarr)
		free(cxt -> cpuarr);
}

int
lscpu_read_numas(struct lscpu_cxt *cxt)
{
	static char filename[32];
	static char sbuf[1024];

	while (1) 
	{
		sprintf(filename, "%s/node%ld", _DEVICES_SYS_NODE_, cxt -> nnodes++);

		if (file2str(filename, "cpulist", sbuf, sizeof(sbuf)) >= 0)
			parse_cpu_list(sbuf, cxt);
		else
			return 0;
	}
	return 1;
}

int
parse_module(module *mod)
{
    yyscan_t sc;
    int res;

    yylex_init(&sc);
    yyset_in(mod->src, sc);

#ifdef _YYDEBUG
    yydebug = 1;
#endif

    res = yyparse(sc, mod);

    return res;
}

void
delete_cpro(Cpro *cpro)
{
    if (cpro -> cproList != CNIL)
    {
        clist_free(cpro -> cproList);
    }
}

void
delete_cpro_module(module *mod)
{
    if (!mod -> cproIsNull)
    {
        delete_cpro(mod -> cpro);
        mod -> cproIsNull = true;
        CFREE(mod->cpro);
    }
    FCLOSE(mod -> src);
    CFREE(mod);
}
