#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Nankai University Information Security
#QiuKF 1055419050@qq.com
#concat processed.csv and vt_report.csv into reports.csv
#then delete vt_report.csv and processed.csv

from multiprocessing import Process,Pool
import os
import pandas as pd
import time
import sys

SAMPLES_PATH='/data/malware/'
DIR_CHR=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
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
def merge_two_csv(first_dir):
  count=0

  print 'Run task %s (%s)...' % (first_dir, os.getpid())
  child_dir=make_file_dir(first_dir)
  for each_dir in child_dir:
    try:
      processed_df=pd.read_csv(SAMPLES_PATH+each_dir+'processed.csv')
      processed_df.drop_duplicates('sha256','first',inplace=True)
      vt_report_df=pd.read_csv(SAMPLES_PATH+each_dir+'vt_report.csv')
      vt_report_df.drop_duplicates('sha256','first',inplace=True)
      out =pd.merge(processed_df,vt_report_df,how='outer',on=['sha256'])
      out =out.sort_values(by=['sha256'])
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
  
  p=Pool(16)
  for each in DIR_CHR:
    p.apply_async(merge_two_csv,args=(each,))
  p.close()
  p.join()
  
  #<--------not necessary-------->
  #merge_report()

if __name__=='__main__':
  main()
  #while True:
  #  main()
  #  time.sleep(36000)

                                           