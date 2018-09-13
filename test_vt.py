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

#SAMPLES_PATH='/data/malware/'
SAMPLES_PATH='/data/benign/'


def get_file(first_dir):

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
    file_to_list=list(reports_pd['sha256'])
    ret_list=[]
    for each in file_to_list:
      try:
        ret_list.append(file_cmd_ret(SAMPLES_PATH+each_dir+each))
      except Exception,e:
        print 'no '+each
        ret_list.append(' ')
    reports_pd['type_x']=ret_list
    reports_pd.to_csv(SAMPLES_PATH+each_dir+'reports.csv',index=False).
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

def file_cmd_ret(abs_path):
  file_cmd=os.popen("file "+abs_path)
  file_ret=file_cmd.read()
  processed_ret=file_ret[file_ret.index(':')+2:file_ret.index('\n')]
  return processed_ret
  #file_cmd.read() return e.g. 
  #'3edff642fcd311d66c6f400f924700d606bb1cd5de1de3565ba99fc83b207636: Java archive data (JAR)\n'

def main():
  print('Parent process %s.' %os.getpid())
  first_dic=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
  p=Pool(16)
  for each in first_dic:
    p.apply_async(get_file,args=(each,))
  p.close()
  p.join()


if __name__=='__main__':
  main()

