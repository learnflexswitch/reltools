#!/bin/bash
infoFile=$SR_CODE_BASE/reltools/codegentools/._genInfo/generatedGoFiles.txt
#sort $infoFile|
mkdir -p $SR_CODE_BASE/reltools/codegentools/._genInfo/ 
touch $infoFile
touch $infoFile.tmp
uniq $infoFile >$infoFile.tmp
for srcFile in `cat $infoFile.tmp`;
do
	 touch $srcFile
	 rm $srcFile
done    
rm $infoFile
rm $infoFile.tmp
rm -f $SR_CODE_BASE/reltools/codegentools/._genInfo/*
rm -f $SR_CODE_BASE/snaproute/src/models/objects/genObj*
rm -f $SR_CODE_BASE/snaproute/src/models/objects/gen_objMap.go
rm -f $SR_CODE_BASE/snaproute/src/models/actions/genObj*
rm -f $SR_CODE_BASE/snaproute/src/models/actions/gen_actionMap.go
