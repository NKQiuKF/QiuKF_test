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
#rename reports.csv  as reports_future.csv
#create reports.csv only contains samples info with its label

#SAMPLES_PATH='/data/malware/'
SAMPLES_PATH='/data/benign/'


def clean_reports(first_dir):

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
    #clean lines which sha256 column is't sha256
    filter_pd=reports_pd[~reports_pd.sha256.str.contains('\.')]
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
    p.apply_async(clean_reports,args=(each,))
  p.close()
  p.join()


if __name__=='__main__':
  main()

