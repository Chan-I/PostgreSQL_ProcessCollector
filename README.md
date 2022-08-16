# 闲着没事写着玩的PostgreSQL扩展，比master分支的复杂一点。
## 1.Cpro Analyzer —— 统计某个时间段每个CPU上运行过process的情况

功能描述：统计CPU上运行过的进程数量，每1分钟向表中写入一次，每24小时数据归零，数据只保留7天。

CommitId：9ce03f886f3475c2db30f995162c510c627b282a

编译参数：cd src/pl/cpro;make;make install

GUC参数：

| 参数名称 | 参数说明 | 参数范围 | 默认值 |
| -------- | -------- | -------- | ------ |
|          |          |          |        |
|          |          |          |        |
|          |          |          |        |

**对应函数**：

### 1.```cpro_query(timestamp);``` 显示某个时间点统计的cpro情况，输入参数为字符串类型的timestamp内容。


```sql
postgres=# select * from cpro_query('2022-06-15 01:37:45.545044');
          cap_time          | pid_num | cpu_num 
----------------------------+---------+---------
 2022-06-15 01:37:45.545044 |       7 |       2
 2022-06-15 01:37:45.545044 |      11 |      49
 2022-06-15 01:37:45.545044 |       1 |      51
 2022-06-15 01:37:45.545044 |       1 |      52
 2022-06-15 01:37:45.545044 |       6 |      53
(5 rows)

```

### 2.```cpro_time(timestamp1, timestamp2)```  显示某两个时间点的cpro情况，并将差异数据进行了展示。**   

**需要注意的是，text1的时间需要比text2提前，否则会提示错误信息。**

```sql
postgres=# select * from cpro_time('2022-06-15 01:37:45.545044','2022-06-15 01:41:45.595612');   <--   正确情况
 cpu_num | pid_num_time1 | pid_num_time2 | pid_variation 
---------+---------------+---------------+---------------
       2 |             7 |             7 |             0
      49 |            11 |            11 |             0
      51 |             1 |             1 |             0
      52 |             1 |             1 |             0
      53 |             6 |             6 |             0
(5 rows)

postgres=# select * from cpro_time('2022-06-15 01:41:45.595612','2022-06-15 01:37:45.545044');	<--	  错误情况
ERROR: Usage: cpro_time(start_time, end_time)
		 start_time must by ahead of end_time!


```


