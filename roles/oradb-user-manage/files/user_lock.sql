

set echo on
set lines 80
spool /tmp/oradbusermanage.out
alter user &1 account lock;
spool off
