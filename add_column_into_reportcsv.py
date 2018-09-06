#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Nankai University Information Security
#QiuKF 1055419050@qq.com
#add origin_name,length,analyze_time columns into reports.csv

from multiprocessing import Process,Pool
import os
import pandas as pd
import time
import sys

SAMPLES_PATH='/data/malware/'
#SAMPLES_PATH='/data/benign/'

def add_columns(first_dir):

  print 'Run task %s (%s)...' % (first_dir, os.getpid())
  child_dir=make_file_dir(first_dir)
  for each_dir in child_dir:
    try:
      reports_pd=pd.read_csv(SAMPLES_PATH+each_dir+'reports.csv')
    except Exception,e:
      print e,' in ',SAMPLES_PATH+each_dir+'reports.csv'
      continue
    reports_pd['origin_name']=' '
    reports_pd['analyze_time']=' '
    reports_pd['length']=' '
    reports_pd=reports_pd.fillna(' ')
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
    p.apply_async(merge_two_csv,args=(each,))
  p.close()
  p.join()


if __name__=='__main__':
  main()

