#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Nankai University Information Security
#QiuKF 1055419050@qq.com
#get file results at fixed time
#create processed.csv at sub dirctories
#create Total_File_Data.csv at /collection

from multiprocessing import Process,Pool
import os
import pandas as pd
import time
import sys

SAMPLES_PATH='/data/malware/'
#samples_path='/data/malware/collection/'
#<--------not use the function in this script-------->
def merge_report():
  
  data = {"sha256":[],"type":[]}
  total_df=pd.DataFrame(data)
  chr=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
  for first in chr:
    sub_dir_list=make_file_dir(first)
    for each in sub_dir_list:
      sub_pd=pd.read_csv(SAMPLES_PATH+each+'report.csv')
      total=[total_df,sub_pd]
      total_df=pd.concat(total)
      print 'concat '+each+'report.csv'
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
      out.to_csv(SAMPLES_PATH+each_dir+'report.csv',index=False)
      #os.popen('rm -f '+SAMPLES_PATH+each_dir+'processed.csv')
      #os.popen('rm -f '+SAMPLES_PATH+each_dir+'vt_report.csv')

    except Exception,e:
      print e,'continue'
      continue

    
def make_file_dir(first):
  ret=[]
  chr_list=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
  tmp=''
  for second in chr_list:
    two='/'+second
    for third in chr_list:
      three=two+'/'+third+'/'
      ret.append(first+three)
  return ret
  

def main():
  #print SAMPLES_PATH
  print('Parent process %s.' %os.getpid())
  #dic_list=make_file_dir()
  first_dic=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
  p=Pool(16)
  for each in first_dic:
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

                                           