#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Nankai University Information Security
#QiuKF 1055419050@qq.com
#fill the column of time_stamp by total time table

from multiprocessing import Process,Pool
import os
import pandas as pd
import time
import sys

SAMPLES_PATH='/data/malware/'
TIME_TABLE='latest.csv'
DIR_CHR=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
def get_total_table(table_path):
  origin_table=pd.read_csv(table_path)
  origin_table.sha256=origin_table.sha256.str.lower()
  origin_table['time_stamp']=origin_table['dex_date']
  #origin_table['file_size']=origin_table['dex_size']
  return origin_table[['sha256','time_stamp']]


#samples_path='/data/malware/collection/'
#<--------not use the function in this script-------->
#merge reports.csv from all sub directory ,for statistic
def merge_report():
  
  data = {"sha256":[],"type":[]}
  total_df=pd.DataFrame(data)
 
  for first in DIR_CHR:
    sub_dir_list=make_file_dir(first)
    for each in sub_dir_list:
      sub_pd=pd.read_csv(SAMPLES_PATH+each+'reports.csv')
      total=[total_df,sub_pd]
      total_df=pd.concat(total)
      print 'concat '+each+'reports.csv'
  total_df.to_csv('/data/Total_File_Data(QiuKF).csv',index=False)
#<------------------------------------------------------->
def merge_two_csv(first_dir,total_table):
  count=0

  print 'Run task %s (%s)...' % (first_dir, os.getpid())
  child_dir=make_file_dir(first_dir)
  for each_dir in child_dir:
    try:
      reports_df=pd.read_csv(SAMPLES_PATH+each_dir+'reports.csv')
      reports_df=reports_df.drop(['time_stamp'],axis=1)

      out =pd.merge(reports_df,total_table,how='left',on=['sha256'])

      out =out.fillna(' ')
      out.to_csv(SAMPLES_PATH+each_dir+'reports.csv',index=False)
      #os.popen('rm -f '+SAMPLES_PATH+each_dir+'processed.csv')
      #os.popen('rm -f '+SAMPLES_PATH+each_dir+'vt_report.csv')

    except Exception,e:
      print e,'continue'
      continue

    
def make_file_dir(first):
  ret=[]
  
  tmp=''
  for second in DIR_CHR:
    two='/'+second
    for third in DIR_CHR:
      three=two+'/'+third+'/'
      ret.append(first+three)
  return ret
  

def main():
  #print SAMPLES_PATH
  print('Parent process %s.' %os.getpid())
  #dic_list=make_file_dir()
  total_time_table=get_total_table(TIME_TABLE)
  
  p=Pool(16)
  for each in DIR_CHR:
    p.apply_async(merge_two_csv,args=(each,total_time_table,))
  p.close()
  p.join()
  
  #<--------not necessary-------->
  #merge_report()

if __name__=='__main__':
  main()
  #while True:
  #  main()
  #  time.sleep(36000)

                                           