#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Nankai University Information Security
#QiuKF 1055419050@qq.com

from multiprocessing import Process,Pool
import os
import pandas as pd
import time
import sys
import re

#clean the reports.csv in every sub dirctory 
#because their some sha256.data sha256.xml in reports's sha256 column

MALWARE_PATH='/data/malware/'
BENIGN_PATH='/data/benign/'

def exe_filter(reports_path):
  origin_file=open(reports_path,'r')
  origin_data=origin_file.readlines()
  origin_file.close()
  ret=[]
  for each_line in origin_data:
    tmp=list(each_line)
    try:
      first_index=each_line.index('"')
      second_index=each_line.index('"',first_index+1)
      comma_index=each_line.index(',',first_index+1,second_index)
      tmp[comma_index]='-'
      #print each_line[comma_index]
      #print each_line[first_index:second_index+1]

      third_index=each_line.index('"',second_index+1)
      fouth_index=each_line.index('"',third_index+1)
      comma_index=each_line.index(',',third_index+1,fouth_index)
      tmp[comma_index]='-'

      fifth_index=each_line.index('"',fouth_index+1)
      sixth_index=each_line.index('"',fifth_index+1)
      comma_index=each_line.index(',',fifth_index+1,sixth_index)
      tmp[comma_index]='-'
      #print each_line[third_index:fouth_index+1]

    except Exception,e:
      pass
      #print e
    tmp=''.join(tmp)
    ret.append(tmp)

    #print each_line
  out=open(reports_path,'w')
  out.writelines(ret)
  out.close()

def filter_comma_malware(first_dir):

  print 'Run task %s (%s)...' % (first_dir, os.getpid())
  child_dir=make_file_dir(first_dir)
  for each_dir in child_dir:
    try:
      exe_filter(MALWARE_PATH+each_dir+'reports.csv')
      #use in server:150
      #reports_pd=pd.read_csv(SAMPLES_PATH+each_dir+'vt_report.csv')
    except Exception,e:

      print e,' in ',MALWARE_PATH+each_dir+'reports.csv'
      continue
    #clean lines which sha256 column is't sha256
    #filter_pd=reports_pd[~reports_pd.md5.str.contains('apk')]
    print MALWARE_PATH+each_dir,' completed'

def filter_comma_benign(first_dir):

  print 'Run task %s (%s)...' % (first_dir, os.getpid())
  child_dir=make_file_dir(first_dir)
  for each_dir in child_dir:
    try:
      exe_filter(BENIGN_PATH+each_dir+'reports.csv')
      #use in server:150
      #reports_pd=pd.read_csv(SAMPLES_PATH+each_dir+'vt_report.csv')
    except Exception,e:

      print e,' in ',BENIGN_PATH+each_dir+'reports.csv'
      continue
    #clean lines which sha256 column is't sha256
    #filter_pd=reports_pd[~reports_pd.md5.str.contains('apk')]
    print BENIGN_PATH+each_dir,' completed'

def clean_reports(first_dir):

  print 'Run task %s (%s)...' % (first_dir, os.getpid())
  child_dir=make_file_dir(first_dir)
  for each_dir in child_dir:
    try:
      reports_pd=pd.read_csv(SAMPLES_PATH+each_dir+'reports.csv')
      reports_pd.drop_duplicates('sha256','last',inplace=True)
      #use in server:150
      #reports_pd=pd.read_csv(SAMPLES_PATH+each_dir+'vt_report.csv')
    except Exception,e:

      print e,' in ',SAMPLES_PATH+each_dir+'reports.csv'
      continue
    #clean lines which sha256 column is't sha256
    #filter_pd=reports_pd[~reports_pd.md5.str.contains('apk')]
    filter_pd.to_csv(SAMPLES_PATH+each_dir+'reports.csv',index=False)
    print SAMPLES_PATH+each_dir,' completed'

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
    p.apply_async(filter_comma_benign,args=(each,))
    p.apply_async(filter_comma_malware,args=(each,))
  p.close()
  p.join()


if __name__=='__main__':
  main()

