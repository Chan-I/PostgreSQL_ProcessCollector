\echo Use "CREATE EXTENSION cpro '1.0'" to load this file. \quit
CREATE SCHEMA cpro;


CREATE TABLE cpro.cpro_info
(
	cpuinfotime	timestamp with time zone	NOT NULL,
	cpuinfo		text		NOT NULL
);


CREATE FUNCTION what_is_cpro()
RETURNS text
LANGUAGE C STRICT
AS 'MODULE_PATHNAME', 'what_is_cpro';


CREATE FUNCTION cpro_query
(
	IN	query_time	timestamp with time zone,
    OUT cap_time    timestamp with time zone,
    OUT pid_num     bigint,
    OUT cpu_num     int
)
RETURNS SETOF record
LANGUAGE C PARALLEL SAFE --IMMUTABLE STRICT
AS 'MODULE_PATHNAME', 'cpro_query';


CREATE FUNCTION crosstab(text)
RETURNS setof record
AS 'MODULE_PATHNAME','crosstab'
LANGUAGE C STABLE STRICT;


CREATE TYPE cpro.cpro_crosstab_2 AS
(
	row_name	TEXT,
	category_1	TEXT,
	category_2	TEXT
);

CREATE FUNCTION crosstab2(text)
RETURNS setof cpro.cpro_crosstab_2
AS 'MODULE_PATHNAME','crosstab'
LANGUAGE C PARALLEL SAFE STABLE STRICT;


CREATE FUNCTION cpro_time(
	IN	start_time		timestamp with time zone,
	IN	end_time		timestamp with time zone,
	OUT cpu_num			int,
	OUT pid_num_time1	int,
	OUT pid_num_time2	int,
	OUT pid_variation	int
)
RETURNS SETOF record
LANGUAGE C PARALLEL SAFE -- STRICT
AS 'MODULE_PATHNAME', 'cpro_time';


