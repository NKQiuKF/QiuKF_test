#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Nankai University Information Security
#QiuKF 1055419050@qq.com
#add file_name,file_size,last_analysis_time  columns into reports.csv
#if there is no file_name for a sample,replace its name by sha256
#add time
#Wait Tian's time.csv

from multiprocessing import Process,Pool
import os
import pandas as pd
import time
import sys
import re

#add three columns (file_name,file_size,time_stamp) into reports.csv
#There are two function prepared for two Tinghua's server

#SAMPLES_PATH='/data/malware/'
SAMPLES_PATH='/data/benign/'

#detect sample file by sha256
# return is boolean
def is_sample(file_name):
  detect_pattern='[0123456789abcdef]{64}$'
  
  return re.match(detect_pattern, file_name)

def file_cmd_ret(abs_path):
  file_cmd=os.popen("file "+abs_path)
  file_ret=file_cmd.read()
  processed_ret=file_ret[file_ret.index(':')+2:file_ret.index('\n')]
  return processed_ret
  #file_cmd.read() return e.g. 
  #'3edff642fcd311d66c6f400f924700d606bb1cd5de1de3565ba99fc83b207636: Java archive data (JAR)\n'

def add_columns_in_150(first_dir):
  
 
  print 'Run task %s (%s)...' % (first_dir, os.getpid())
  child_dir=make_file_dir(first_dir)
  #print child_dir
  for each_dir in child_dir:
    #process file results first
    #filter files like .data,.xml
    samples_files=os.listdir(SAMPLES_PATH+each_dir)
    #print samples_files
    for each_file in samples_files:
      #print each_file
      if not is_sample(each_file):

        samples_files.remove(each_file)
  
    file_ret_list=[]
    for each_sample in samples_files:
      try:
        sample_file_ret=file_cmd_ret(SAMPLES_PATH+each_dir+each_sample)
      except Exception,e:
        print e
        sample_file_ret=' '
      file_ret_list.append(sample_file_ret)
    file_ret_pd=pd.DataFrame({'sha256':samples_files,'type':file_ret_list})
    # test
    #print file_ret_pd
    
    try:
      vt_report_pd=pd.read_csv(SAMPLES_PATH+each_dir+'vt_report.csv')
      #use in server:150
      #reports_pd=pd.read_csv(SAMPLES_PATH+each_dir+'vt_report.csv')
    except Exception,e:
      print e,' in ',SAMPLES_PATH+each_dir+'vt_report.csv'
      continue
    vt_report_pd['file_name']=' '
    vt_report_pd['file_size']=' '
    #replace it by scan_date
    #reports_pd['last_analysis_time']=' '
    vt_report_pd['time_stamp']=' '

    #concat
    reports_pd=pd.merge(file_ret_pd,vt_report_pd,on=['sha256'],how='outer')
    reports_pd=reports_pd.fillna(' ')
    reports_pd.drop_duplicates('sha256','first',inplace=True)
    #write
    print SAMPLES_PATH+each_dir+'reports.csv'
    reports_pd.to_csv(SAMPLES_PATH+each_dir+'reports.csv',index=False)
    #delete vt_report.csv
    os.popen('rm -f '+SAMPLES_PATH+each_dir+'vt_report.csv')

def add_columns_in_151(first_dir):

  print 'Run task %s (%s)...' % (first_dir, os.getpid())
  child_dir=make_file_dir(first_dir)
  for each_dir in child_dir:
    try:
      reports_pd=pd.read_csv(SAMPLES_PATH+each_dir+'reports.csv')
      #use in server:150
      #reports_pd=pd.read_csv(SAMPLES_PATH+each_dir+'vt_report.csv')
    except Exception,e:
      print e,' in ',SAMPLES_PATH+each_dir+'reports.csv'
      continue
    reports_pd['file_name']=' '
    reports_pd['file_size']=' '
    #replace it by scan_date
    #reports_pd['last_analysis_time']=' '
    reports_pd['time_stamp']=' '
    #
    reports_pd=reports_pd.fillna(' ')
    #
    reports_pd.to_csv(SAMPLES_PATH+each_dir+'reports.csv',index=False)

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
  print('Parent process %s.' %os.getpid())
  first_dic=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
  p=Pool(16)
  for each in first_dic:
    p.apply_async(add_columns_in_150,args=(each,))
  p.close()
  p.join()


if __name__=='__main__':
  main()

