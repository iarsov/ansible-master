

set echo on
set lines 80
col name for a20
col open_mode for a15
col database_role for a25
spool /tmp/checkdbstatus.out
select name, open_mode, database_role from v$database
/
spool off
