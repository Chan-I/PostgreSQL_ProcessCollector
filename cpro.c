#include "cpro.h"

Timestamp currenttime = 0;
char	*CproDatabaseName = "";
bool	enable_cpro = false;
struct	timeval st,en;
static	cprostorage cpro;	
char	read_buf[READ_BUF_MAX];
static volatile bool need_exit = false;
static volatile bool got_SIGHUP = false;


PG_MODULE_MAGIC;
PG_FUNCTION_INFO_V1(cpro_query);
PG_FUNCTION_INFO_V1(cpro_time);
PG_FUNCTION_INFO_V1(crosstab);
PG_FUNCTION_INFO_V1(what_is_cpro);


Size cprodbstat_memsize(void);
bool ReadCproFile(void);
bool beentryCheckState(PgBackendStatus *bs);
char *CurrentUserName(void);
char *parse_cpro_list(cprostorage *cpro);
char *timestamptz_2_str_en(TimestampTz t);
char *timestamptz_2_str_st(TimestampTz t);
int  GetCpuNum(void);
long int GetCproTimeZone(void);
TimestampTz timestamp2timestamptz(Timestamp timestamp);
void CproWorkerMain(Datum arg);
void WriteCproFile(void);
void _PG_init(void);
void cleanupcproinfo(Relation heap,AttrNumber columnnum,TimestampTz currenttime);
void collect_cpro_info(cprostorage *cpro);
void cpro_info(cprostorage *cpro);


/* Basic Udf for cpro. Print Info About Cpro Analyzer. */
Datum
what_is_cpro(PG_FUNCTION_ARGS)
{
	PG_RETURN_TEXT_P(cstring_to_text("Cpro - An Extension For Monitering CPU And Processes"));
}

void
_PG_init(void)
{
	BackgroundWorker worker;
	if (process_shared_preload_libraries_in_progress)
	{
		DefineCustomStringVariable(
				"cpro.database_name",
				gettext_noop("Databases to monitor"),
				NULL,
				&CproDatabaseName,
				"postgres",
				PGC_POSTMASTER,
				GUC_SUPERUSER_ONLY,
				NULL, NULL, NULL);
		DefineCustomBoolVariable(
				"cpro.enable_cpro",
				"Determine wheather use cpro",
				NULL,
				&enable_cpro,
				false,
				PGC_POSTMASTER,
				GUC_SUPERUSER_ONLY,
				NULL,NULL,NULL);

		EmitWarningsOnPlaceholders("cpro_db_stat");
		RequestAddinShmemSpace(cprodbstat_memsize());
#if (PG_VERSION_NUM >= 90600)
		RequestNamedLWLockTranche("cpro_db_stat", 1);
#else
		RequestAddinLWLocks(1);
#endif

		worker.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
		worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
		worker.bgw_restart_time = 1;
#if (PG_VERSION_NUM < 100000)
		worker.bgw_main = CproWorkerMain;
#endif
		worker.bgw_main_arg = Int32GetDatum(0);
		worker.bgw_notify_pid = 0;
		sprintf(worker.bgw_library_name, "cpro");
		sprintf(worker.bgw_function_name, "CproWorkerMain");
		snprintf(worker.bgw_name, BGW_MAXLEN, "CeresDB Cpro Analyzer");
#if (PG_VERSION_NUM >= 110000)
		snprintf(worker.bgw_type, BGW_MAXLEN, "CeresDB Cpro Analyzer");
#endif
		RegisterBackgroundWorker(&worker);
	}
	else
	{
		ereport(ERROR, (errmsg("Cpro can only be loaded via shared_preload_libraries"),
					errhint("Add cpro to shared_preload_libraries configuration "
						"variable in postgres.conf in master and workers.")));
	}
}

Size
cprodbstat_memsize(void)
{
	Size            size;

	size = MAXALIGN(sizeof(cprodbstatSharedState));
	return size;
}

void
WriteCproFile(void)
{
	int fd, len;
	StringInfo fpath,fcontent;
	
	fpath = makeStringInfo();
	fcontent = makeStringInfo();
	
	appendStringInfo(fpath, "%s/cpro.stat", DataDir);

	for (int i = 0; i < cpro.cpu_num || 
			(appendStringInfo(fcontent, UINT64_FORMAT, cpro.cpro_arr[i]), 0); 
				appendStringInfo(fcontent, UINT64_FORMAT ",", cpro.cpro_arr[i++]));

	
	/* Open Cpro File */
	if ((fd = open(fpath -> data, O_CREAT|O_TRUNC|O_WRONLY,0777)) == -1)
	{
		ereport(ERROR, (errmsg("Can not open Cpro File in %s!", fpath -> data)));
	}
	
	/* Write Cpro File */
	if ((len = write(fd, fcontent -> data, fcontent -> len)) == -1)
	{
		ereport(ERROR, (errmsg("Write Cpro File failed!")));	
	}
	
	close(fd);	
}

bool
ReadCproFile(void)
{
	bool ret;
	int fd, len, i = 0;
	char *p;
	StringInfo fpath = makeStringInfo();

	appendStringInfo(fpath, "%s/cpro.stat", DataDir);
	
	/* Open Cpro File */
	if ((fd = open(fpath -> data, O_RDONLY)) == -1)
	{
		ereport(WARNING, (errmsg("Can not open Cpro File in %s!", fpath -> data)));
		ret = false;

		close(fd);	
	}
	else /* file exists */
	{	
		ret = true;
		/* Read Cpro File */
		if ((len = read(fd, read_buf, READ_BUF_MAX)) == -1)
		{
			ereport(ERROR, (errmsg("Read Cpro File failed!")));	
		}
		
		close(fd);	

		/* Insert read_buf into struct cpro... */

		p = strtok(read_buf, ",");

		while (p)
		{
			cpro.cpro_arr[i++] = atoll(p);
			p = strtok(NULL, ",");
		}	
		cpro.cpro_arr[i] = atoll(read_buf);

		remove(fpath -> data);
	}
	return ret;
}

static void
cprostat_exit(SIGNAL_ARGS)
{
	int			save_errno = errno;

	need_exit = true;
	SetLatch(MyLatch);

	errno = save_errno;
}

/* SIGHUP handler for collector process */
static void
cprostat_sighup_handler(SIGNAL_ARGS)
{
	int			save_errno = errno;

	got_SIGHUP = true;
	SetLatch(MyLatch);

	errno = save_errno;
}

static void
cpro_die(SIGNAL_ARGS)
{
    PG_SETMASK(&BlockSig);

	WriteCproFile();

    ereport(FATAL,
            (errcode(ERRCODE_ADMIN_SHUTDOWN),
             errmsg("terminating background worker" 
					"\"%s\" due to administrator command",
                    MyBgworkerEntry->bgw_type)));
}

void
CproWorkerMain(Datum arg)
{
	pqsignal(SIGHUP,  cprostat_sighup_handler);
	pqsignal(SIGINT,  SIG_IGN);
	pqsignal(SIGTERM, cpro_die);
	pqsignal(SIGQUIT, cprostat_exit);
	pqsignal(SIGALRM, SIG_IGN);
	pqsignal(SIGPIPE, SIG_IGN);
	pqsignal(SIGUSR1, SIG_IGN);
	pqsignal(SIGUSR2, SIG_IGN);
	pqsignal(SIGCHLD, SIG_IGN);

	cpro.cpu_num = GetCpuNum(); 
	cpro.cpro_arr = palloc(cpro.cpu_num * sizeof(uint64));

	memset(read_buf, 0, READ_BUF_MAX);
	if (!ReadCproFile())
		for(int i = 0; i <= cpro.cpu_num; cpro.cpro_arr[i++] = 0);

	gettimeofday(&st, NULL);

	/* We're now ready to receive signals */
	BackgroundWorkerUnblockSignals();
	if(strcmp(CproDatabaseName,"") == 0)
	{
		proc_exit(0);
	}

#if (PG_VERSION_NUM < 110000)
	BackgroundWorkerInitializeConnection(CproDatabaseName, NULL);
#else
	BackgroundWorkerInitializeConnection(CproDatabaseName, NULL, 0);
#endif
	pgstat_report_appname("cpro analyzer");

	for (;;)
	{
		MemoryContext CproLoopContext = NULL;
		MemoryContext oldcontext = NULL;
		sleep(1);
		StartTransactionCommand();
		CommitTransactionCommand();

		CproLoopContext = AllocSetContextCreate(CurrentMemoryContext,
													"cpro loop context",
													ALLOCSET_DEFAULT_MINSIZE,
													ALLOCSET_DEFAULT_INITSIZE,
													ALLOCSET_DEFAULT_MAXSIZE);

		oldcontext = MemoryContextSwitchTo(CproLoopContext);
		StartTransactionCommand();

		gettimeofday(&en,NULL);

		cpro_info(&cpro);

		/* store cpro every CPRO_MIN */
		if (!((en.tv_sec - st.tv_sec) % CPRO_MIN))
		{
			currenttime = GetCurrentTimestamp();
			
			/* Store cpro struct into table */
			collect_cpro_info(&cpro);	
		}

		/* Erase cpro struct every 24 hours. */
		if(!((en.tv_sec + 8 * 3600) % CPRO_DAY))
			for (int i = 0;i < cpro.cpu_num; cpro.cpro_arr[i++] = 0);

		CommitTransactionCommand();

		MemoryContextSwitchTo(oldcontext);
	}
	ereport(LOG, (errmsg("cpro analyzer shutting down")));
	proc_exit(0);
}

void
cleanupcproinfo(Relation heap,AttrNumber columnnum,TimestampTz currenttime)
{
	ScanKeyData scanKey;
	HeapTuple tuple = NULL;
	SysScanDesc scanDescriptor = NULL;

	ScanKeyInit(&scanKey,columnnum, InvalidStrategy, 
					F_INT8LE,TimestampTzGetDatum(currenttime-86400000000*7));

	scanDescriptor = systable_beginscan(heap,InvalidOid, false,NULL, 1, &scanKey);

	while (HeapTupleIsValid(tuple = systable_getnext(scanDescriptor)))
	{
		simple_heap_delete(heap,&(tuple->t_self));
	}
	systable_endscan(scanDescriptor);
}

long int
GetCproTimeZone(void)
{
	time_t t = time(NULL);
	struct tm lt = {0};
	
	localtime_r(&t, &lt);
	
	return lt.tm_gmtoff;
}

void
collect_cpro_info(cprostorage *cpro)
{
	Datum		values[2];
	bool		nulls[2];
	
	Oid cproInfoRelationId = InvalidOid;	
	Relation cproInfoTable = NULL;
	HeapTuple	tuple;
	TupleDesc tupleDescriptor = NULL;

	memset(values, 0, sizeof(values));
	memset(nulls, 0, sizeof(nulls));

	//values[0] = TimestampGetDatum(currenttime + (GetCproTimeZone() * 1000000));
	values[0] = TimestampGetDatum(currenttime);
	values[1] = CStringGetTextDatum(parse_cpro_list(cpro));

	cproInfoRelationId = get_relname_relid("cpro_info", get_namespace_oid("cpro", false));
	if (!OidIsValid(cproInfoRelationId))
		ereport(ERROR,errmsg("can not find table cwc_snap"));

	cproInfoTable = heap_open(cproInfoRelationId, RowExclusiveLock);
	tupleDescriptor = RelationGetDescr(cproInfoTable);
	tuple = heap_form_tuple(tupleDescriptor, values, nulls);

	cleanupcproinfo(cproInfoTable,1,currenttime);

	simple_heap_insert(cproInfoTable,tuple);
	heap_close(cproInfoTable, RowExclusiveLock);
}

char *
parse_cpro_list(cprostorage *cpro)
{
	StringInfoData *data = makeStringInfo();
	appendStringInfo(data,"[");				
	
	for (int i = 0; i < cpro->cpu_num || 
			(appendStringInfo(data,"{\"cpu_%d\":"
				UINT64_FORMAT"}]", i, cpro -> cpro_arr[i]), 0) ; 
					(appendStringInfo(data,"{\"cpu_%d\":"UINT64_FORMAT"},", 
						i, cpro -> cpro_arr[i]),i++));

	
	return data -> data;
}

void cpro_info(cprostorage *cpro)
{
	int	num_backends = pgstat_fetch_stat_numbackends();
	int	curr_backend;

	for (curr_backend = 1; curr_backend <= num_backends; curr_backend++)
	{
		LocalPgBackendStatus	*local_beentry;
		PgBackendStatus		*beentry;
		proc_t		*proc;

		proc = palloc(sizeof(proc_t));

		local_beentry = pgstat_fetch_stat_local_beentry(curr_backend);
		if (local_beentry && beentryCheckState(&(local_beentry->backendStatus)))
		{
			beentry = &local_beentry -> backendStatus;

			if (GetPidProcStat(beentry -> st_procpid, proc))
			{
				cpro -> cpro_arr[Int32GetDatum(proc->processor)]++;  
				ereport(DEBUG1, (errmsg("cpu_num:%d"
										"\tpid:%ld"
										"\tcpunum:%ld"
										"\tst_state:%d",
										cpro->cpu_num,
										Int32GetDatum(beentry->st_procpid),
										Int32GetDatum((proc->processor)),
										beentry -> st_state)));
			}
			else
				ereport(ERROR, (errmsg("%s",proc->errmsg)));

		}
	}
}

bool
beentryCheckState(PgBackendStatus *bs)
{
	bool ret = false;
	switch(bs -> st_state)
	{
		case STATE_UNDEFINED:
		case STATE_IDLE:
			ret = false;
			break;
		case STATE_RUNNING:
		case STATE_IDLEINTRANSACTION:
		case STATE_FASTPATH:
		case STATE_IDLEINTRANSACTION_ABORTED:
		case STATE_DISABLED:
			ret = true;
			break;
	}
	return ret;
}

int
GetCpuNum(void)
{
	static char path[PATH_MAX], sbuf[32];
	struct stat statbuf;
	int ret = -1;
	char *token;

	sprintf(path, "/sys/devices/system/cpu/");

	if (stat(path, &statbuf))
		ereport(ERROR, errmsg("stat failed on %s,please check pid.", path));

	if (file2str(path, "online", sbuf, sizeof sbuf) >= 0)
		scanf("%s", sbuf);
	else
		ereport(ERROR,errmsg("stat failed on %s", path));
	
	token = strtok(sbuf, "-");
	token = strtok(NULL, "-");

	if (token)
		ret = atoi(token);

	return ret;
}

Datum
cpro_query(PG_FUNCTION_ARGS)
{
#define CPRO_RETURN_COLS 4
	ReturnSetInfo	*rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	TupleDesc		tupdesc;
	MemoryContext	per_query_ctx;
	MemoryContext	oldcontext;

	Timestamp start =  PG_ARGISNULL(0) ? 0 : PG_GETARG_TIMESTAMP(0);	
	Oid cproSchemaId = InvalidOid;
	Oid cproSETJobRelationId = InvalidOid;
	Relation cproSETJobsTable = NULL;
	ScanKeyData		scanKey;
	TupleDesc		tupleDescriptor = NULL;
	HeapTuple		tuple;
	Tuplestorestate  	*tupleOut;
    TableScanDesc	scandesc;
	
	per_query_ctx = rsinfo->econtext->ecxt_per_query_memory;
	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
		elog(ERROR, "return type must be a row type");

	if (!start)
		ereport(ERROR, (errmsg("Input Value Can Not Be NULL!")));

	tupleOut = tuplestore_begin_heap(true, false, work_mem);
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupleOut;
	rsinfo->setDesc = tupdesc;
	MemoryContextSwitchTo(oldcontext);

	cproSchemaId = get_namespace_oid("cpro", false);
	cproSETJobRelationId = get_relname_relid("cpro_info", cproSchemaId);
	if (!OidIsValid(cproSETJobRelationId))
	{
		elog(ERROR, "can not find table cpro_info");
	}

	cproSETJobsTable = heap_open(cproSETJobRelationId, AccessShareLock);

	ScanKeyInit(&scanKey, 1,
						InvalidStrategy, F_TIMESTAMP_EQ, 
						TimestampGetDatum(start));

	scandesc = table_beginscan_catalog(cproSETJobsTable, 1, &scanKey);
	tupleDescriptor	= RelationGetDescr(cproSETJobsTable);		

	if (HeapTupleIsValid(tuple = heap_getnext(scandesc, ForwardScanDirection)))
	{
		bool		isNull = false;
		Datum		input_time, cpro_array;
		Timestamp	out_time;		
		char		*cproJsonb;		
		module		*mod;
		Datum		values[CPRO_RETURN_COLS];
		bool		nulls[CPRO_RETURN_COLS];
		CListCell	*e;
	
		memset(values, 0, sizeof(values));
		memset(nulls, 0, sizeof(nulls));
		
		input_time = heap_getattr(tuple, 1, tupleDescriptor, &isNull);
		cpro_array = heap_getattr(tuple, 2, tupleDescriptor, &isNull);

		out_time = DatumGetTimestamp(input_time);
		cproJsonb = TextDatumGetCString(cpro_array);

		mod = new_module_from_string(cproJsonb);
	
		if (!parse_module(mod))
		{
			/* TO DO ... */
			if (mod -> cpro)
			{
				cforeach (e, mod -> cpro -> cproList)	
				{
					CproList *cprl = (CproList *) clfirst(e);
					values[0] = TimestampGetDatum(out_time);
					values[1] = Int64GetDatum(cprl -> pidnum);
					values[2] = Int32GetDatum(cprl -> cpunum);
					ereport(DEBUG1, errmsg("%ld,%ld,%d", out_time, cprl -> pidnum, cprl -> cpunum));		
					tuplestore_putvalues(tupleOut, tupdesc, values, nulls);
				}
			}
		}
		delete_cpro_module(mod);
	}
	tuplestore_donestoring(tupleOut);
	
	table_endscan(scandesc);
	heap_close(cproSETJobsTable, AccessShareLock);
	
	return (Datum) 0;
}

static bool
compatCrosstabTupleDescs(TupleDesc ret_tupdesc, TupleDesc sql_tupdesc)
{
	Form_pg_attribute ret_attr;
	Form_pg_attribute sql_attr;
	Oid			sql_atttypid;
	Oid			ret_atttypid;

	if (ret_tupdesc -> natts < 2 ||
		sql_tupdesc -> natts < 3)
		return false;

	/* check the rowid types match */
	ret_atttypid = TupleDescAttr(ret_tupdesc, 0) -> atttypid;
	sql_atttypid = TupleDescAttr(sql_tupdesc, 0) -> atttypid;
	if (ret_atttypid != sql_atttypid)
		ereport(ERROR,
				(errcode(ERRCODE_DATATYPE_MISMATCH),
				 errmsg("invalid return type"),
				 errdetail("SQL rowid datatype does not match "
						   "return rowid datatype.")));

	sql_attr = TupleDescAttr(sql_tupdesc, 2);
	for (int i = 1; i < ret_tupdesc->natts; i++)
	{
		ret_attr = TupleDescAttr(ret_tupdesc, i);

		if (ret_attr -> atttypid != sql_attr->atttypid)
			return false;
	}

	/* the two tupdescs are compatible for our purposes */
	return true;
}


Datum
crosstab(PG_FUNCTION_ARGS)
{
	char	   *sql = text_to_cstring(PG_GETARG_TEXT_PP(0));
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	Tuplestorestate *tupstore;
	TupleDesc	tupdesc;
	uint64		call_cntr;
	uint64		max_calls;
	AttInMetadata *attinmeta;
	SPITupleTable *spi_tuptable;
	TupleDesc	spi_tupdesc;
	bool		firstpass;
	char	   *lastrowid;
	int			num_categories;
	MemoryContext per_query_ctx;
	MemoryContext oldcontext;
	int			ret;
	uint64		proc;

	if (rsinfo == NULL || !IsA(rsinfo, ReturnSetInfo))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("set-valued function called in context that cannot accept a set")));

	if (!(rsinfo->allowedModes & SFRM_Materialize))
		ereport(ERROR,
				(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
				 errmsg("materialize mode required, but it is not "
						"allowed in this context")));

	per_query_ctx = rsinfo -> econtext -> ecxt_per_query_memory;

	/* Connect to SPI manager */
	if ((ret = SPI_connect()) < 0)
		/* internal error */
		ereport(ERROR, (errmsg("crosstab: SPI_connect returned %d", ret)));

	/* Retrieve the desired rows */
	ret = SPI_execute(sql, true, 0);
	proc = SPI_processed;

	/* If no qualifying tuples, fall out early */
	if (ret != SPI_OK_SELECT || proc == 0)
	{
		SPI_finish();
		rsinfo -> isDone = ExprEndResult;
		PG_RETURN_NULL();
	}

	spi_tuptable = SPI_tuptable;
	spi_tupdesc = spi_tuptable -> tupdesc;

	if (spi_tupdesc -> natts != 3)
		ereport(ERROR,
				(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
				 errmsg("invalid source data SQL statement"),
				 errdetail("The provided SQL must return 3 "
						   "columns: rowid, category, and values.")));

	/* get a tuple descriptor for our result type */
	switch (get_call_result_type(fcinfo, NULL, &tupdesc))
	{
		case TYPEFUNC_COMPOSITE:
			/* success */
			break;
		case TYPEFUNC_RECORD:
			/* failed to determine actual type of RECORD */
			ereport(ERROR,
					(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
					 errmsg("function returning record called in context "
							"that cannot accept type record")));
			break;
		default:
			/* result type isn't composite */
			ereport(ERROR,
					(errcode(ERRCODE_DATATYPE_MISMATCH),
					 errmsg("return type must be a row type")));
			break;
	}

	if (!compatCrosstabTupleDescs(tupdesc, spi_tupdesc))
		ereport(ERROR,
				(errcode(ERRCODE_SYNTAX_ERROR),
				 errmsg("return and sql tuple descriptions are "
						"incompatible")));

	oldcontext = MemoryContextSwitchTo(per_query_ctx);

	tupdesc = CreateTupleDescCopy(tupdesc);

	tupstore =
		tuplestore_begin_heap(rsinfo->allowedModes & SFRM_Materialize_Random,
							  false, work_mem);

	MemoryContextSwitchTo(oldcontext);

	attinmeta = TupleDescGetAttInMetadata(tupdesc);

	max_calls = proc;

	num_categories = tupdesc->natts - 1;

	firstpass = true;
	lastrowid = NULL;

	for (call_cntr = 0; call_cntr < max_calls; call_cntr++)
	{
		bool	skip_tuple = false;
		char	**values;

		/* allocate and zero space */
		values = (char **) palloc0((1 + num_categories) * sizeof(char *));

		for (int i = 0; i < num_categories; i++)
		{
			HeapTuple	spi_tuple;
			char	   *rowid;

			/* see if we've gone too far already */
			if (call_cntr >= max_calls)
				break;

			/* get the next sql result tuple */
			spi_tuple = spi_tuptable->vals[call_cntr];

			/* get the rowid from the current sql result tuple */
			rowid = SPI_getvalue(spi_tuple, spi_tupdesc, 1);

			if (i == 0)
			{
				xpstrdup(values[0], rowid);

				if (!firstpass && xstreq(lastrowid, rowid))
				{
					xpfree(rowid);
					skip_tuple = true;
					break;
				}
			}

			if (xstreq(rowid, values[0]))
			{
				values[1 + i] = SPI_getvalue(spi_tuple, spi_tupdesc, 3);

				if (i < (num_categories - 1))
					call_cntr++;
				xpfree(rowid);
			}
			else
			{
				call_cntr--;
				xpfree(rowid);
				break;
			}
		}

		if (!skip_tuple)
		{
			HeapTuple	tuple;

			tuple = BuildTupleFromCStrings(attinmeta, values);
			tuplestore_puttuple(tupstore, tuple);
			heap_freetuple(tuple);
		}

		xpfree(lastrowid);
		xpstrdup(lastrowid, values[0]);
		firstpass = false;

		for (int i = 0; i < num_categories + 1; i++)
			if (values[i] != NULL)
				pfree(values[i]);
		pfree(values);
	}

	/* let the caller know we're sending back a tuplestore */
	rsinfo->returnMode = SFRM_Materialize;
	rsinfo->setResult = tupstore;
	rsinfo->setDesc = tupdesc;

	/* release SPI related resources (and return to caller's context) */
	SPI_finish();

	return (Datum) 0;
}

char *
CurrentUserName(void)
{
    Oid userId = GetUserId();
    return GetUserNameFromId(userId, false);   
}

TimestampTz
timestamp2timestamptz(Timestamp timestamp)
{
	TimestampTz result;
	struct pg_tm tt,
			   *tm = &tt;
	fsec_t		fsec;
	int			tz;

	if (TIMESTAMP_NOT_FINITE(timestamp))
		result = timestamp;
	else
	{
		if (timestamp2tm(timestamp, NULL, tm, &fsec, NULL, NULL) != 0)
			ereport(ERROR,
					(errcode(ERRCODE_DATETIME_VALUE_OUT_OF_RANGE),
					 errmsg("timestamp out of range")));

		tz = DetermineTimeZoneOffset(tm, session_timezone);

		if (tm2timestamp(tm, fsec, &tz, &result) != 0)
			ereport(ERROR,
					(errcode(ERRCODE_DATETIME_VALUE_OUT_OF_RANGE),
					 errmsg("timestamp out of range")));
	}

	return result;
}

char *
timestamptz_2_str_st(TimestampTz t)
{
	static char buf[MAXDATELEN + 1];
	int			tz;
	struct pg_tm tt,
			   *tm = &tt;
	fsec_t		fsec;
	const char *tzn;

	if (TIMESTAMP_NOT_FINITE(t))
		EncodeSpecialTimestamp(t, buf);
	else if (timestamp2tm(t, &tz, tm, &fsec, &tzn, NULL) == 0)
		EncodeDateTime(tm, fsec, true, tz, tzn, USE_ISO_DATES, buf);
	else
		strlcpy(buf, "(timestamp out of range)", sizeof(buf));

	return buf;
}

char *
timestamptz_2_str_en(TimestampTz t)
{
	static char buf[MAXDATELEN + 1];
	int			tz;
	struct pg_tm tt,
			   *tm = &tt;
	fsec_t		fsec;
	const char *tzn;

	if (TIMESTAMP_NOT_FINITE(t))
		EncodeSpecialTimestamp(t, buf);
	else if (timestamp2tm(t, &tz, tm, &fsec, &tzn, NULL) == 0)
		EncodeDateTime(tm, fsec, true, tz, tzn, USE_ISO_DATES, buf);
	else
		strlcpy(buf, "(timestamp out of range)", sizeof(buf));

	return buf;
}

Datum
cpro_time(PG_FUNCTION_ARGS)
{
	FuncCallContext *funcctx;
	Timestamp start =   PG_ARGISNULL(0) ? -1 : PG_GETARG_TIMESTAMP(0);
	Timestamp end =   PG_ARGISNULL(0) ? -1 : PG_GETARG_TIMESTAMP(1);
	TimestampTz ss,en;
		
    int call_cntr, max_calls, tupleCount, ret;
    TupleDesc tupdesc;
    AttInMetadata *attinmeta;
    char ***values;
    PGconn *conn = NULL;
    PGresult *result = NULL;
    StringInfo data = makeStringInfo();
	
	ss = timestamp2timestamptz(start);
	en = timestamp2timestamptz(end);
	
	if (start >= end)
		ereport(ERROR, (errmsg("Usage: cpro_time(start_time, end_time)\n"
								"\t start_time must by ahead of end_time!")));	
	
    if (SRF_IS_FIRSTCALL())
    {
        MemoryContext oldcontext;
        funcctx = SRF_FIRSTCALL_INIT();
        oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

        if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
            ereport(ERROR,
                    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                     errmsg("function returning record called in context "
                         "that cannot accept type record")));

        appendStringInfo(data,PG_CONNECT_PARAMS,PostPortNumber,
								CurrentUserName(),get_database_name(MyDatabaseId));

        conn = PQconnectdb(data->data);
        ret = PQstatus(conn);
        if (ret != CONNECTION_OK)
            ereport(ERROR,(errmsg("%s",conn->errorMessage.data)));
        result = PQexec(conn,"BEGIN;");
        ret = PQresultStatus(result);
        if (ret != PGRES_COMMAND_OK)
            ereport(ERROR,(errmsg("begin transaction failed")));

        resetStringInfo(data);

		appendStringInfo(data,"SELECT cpro.cpu_num, "
								"COALESCE(cpro.category_2,0) AS cap_time1, "
								"COALESCE(cpro.category_1,0) AS cap_time2, "								
								"ABS(COALESCE(cpro.category_1,0) - COALESCE(cpro.category_2,0)) AS pid_variation "
								"FROM (SELECT CAST(row_name AS INT) AS cpu_num, "
								"CAST(category_1 AS INT), CAST(category_2 AS INT) "
								"FROM crosstab2(\'SELECT CAST(cpu_num AS TEXT), "
								"CAST(cap_time AS TEXT), "
								"CAST(pid_num AS TEXT) "
								"FROM (SELECT cpu_num,cap_time,pid_num "
								"FROM cpro_query(\'\'%s\'\') ) AS a "
								"UNION SELECT CAST(cpu_num AS TEXT), "
								"CAST(cap_time AS TEXT), "
								"CAST(pid_num AS TEXT) "
								"FROM (SELECT cpu_num,cap_time,pid_num FROM "
								"cpro_query(\'\'%s\'\') ) AS b ORDER BY 1,2 DESC;\') "
								") AS cpro ORDER BY cpro.cpu_num;",
                                timestamptz_2_str_st(ss), timestamptz_2_str_en(en));

	elog(DEBUG1,"->	%s",data->data);

        result = PQexec(conn,data->data);
        ret = PQresultStatus(result);

        if (ret != PGRES_TUPLES_OK)
        {
            result = PQexec(conn,"ROLLBACK;");
            ret = PQresultStatus(result);
            if (ret == PGRES_COMMAND_OK)
                ereport(ERROR,(errmsg("select failed")));
        }

        tupleCount = PQntuples(result);
        if(tupleCount < 0)
        {
            result = PQexec(conn,"ROLLBACK;");
            ret = PQresultStatus(result);
            if (ret == PGRES_COMMAND_OK)
                ereport(ERROR,(errmsg("select failed")));
        }
        funcctx->max_calls = tupleCount;
        max_calls = funcctx->max_calls;
        values = (char ***) calloc(max_calls,sizeof(char **));

        for (int i = 0;i < max_calls;i++)
        {
            values[i] = (char **) calloc(12,sizeof(char *));
            for (int j = 0;j < CPRO_RETURN_COLS;j++)
            {
                values[i][j] = (char *) calloc(128,sizeof(char));
                if (PQgetvalue(result,i,j) == NULL)
                    values[i][j] = NULL;
				else if (!strcmp(PQgetvalue(result,i,j),""))
					strcpy(values[i][j],"0");
                else
                    strcpy(values[i][j],PQgetvalue(result,i,j));
            }
        }

        result = PQexec(conn,"COMMIT;");
        ret = PQresultStatus(result);
        if (ret != PGRES_COMMAND_OK)
        {
            result = PQexec(conn,"ROLLBACK;");
            ret = PQresultStatus(result);
            if (ret == PGRES_COMMAND_OK)
                ereport(ERROR,(errmsg("commit transaction failed")));
        }
        PQclear(result);
        PQfinish(conn);

        attinmeta = TupleDescGetAttInMetadata(tupdesc);
        funcctx->attinmeta = attinmeta;
        funcctx->user_fctx = values;
        MemoryContextSwitchTo(oldcontext);
    }
    funcctx = SRF_PERCALL_SETUP();
    call_cntr = funcctx->call_cntr;
    max_calls = funcctx->max_calls;
    attinmeta = funcctx->attinmeta;
    values = funcctx->user_fctx;

    if (call_cntr < max_calls)
    {
        Datum result2;
        HeapTuple tuple;

        tuple = BuildTupleFromCStrings(attinmeta, values[call_cntr]);
        result2 = HeapTupleGetDatum(tuple);
        SRF_RETURN_NEXT(funcctx, result2);
    }
    else
    {
        SRF_RETURN_DONE(funcctx);
    }
}
