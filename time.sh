START_TIME=`date +%s%N`

#此处添加要执行的命令
zokrates export-verifier



END_TIME=`date +%s%N` 
EXECUTING_TIME=`expr $END_TIME - $START_TIME`
echo $EXECUTING_TIME
