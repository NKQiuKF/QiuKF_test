#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Nankai University Information Security
#QiuKF 1055419050@qq.com
#make  label_todo_list.csv
#find those samples in floder without label in reports.csv

import os
import pandas as pd
import time
import sys
import re

#SAMPLES_PATH='/data/malware/'
SAMPLES_PATH='/data/benign/'
LABEL_TODO_LIST_PATH='/home/nkamg/QiuKF_test/label_todo_list.csv'

total_label_todo_list=[]

#back up the function ,Supposed it will be used in future
def is_sample(file_name):
  detect_pattern='[0123456789abcdef]{64}$'  
  return re.match(detect_pattern, file_name)
#back up the function ,Supposed it will be used in future
def select_samples_from_list(files_list):
  for each in files_list:
    if not is_sample(each):
      files_list.remove(each)
  return files_list


def create_all_path():
  ret=[]
  tmp_path=''
  chr_list=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
  for first_level in chr_list:
    
    first_path=first_level
    for second_level in chr_list:
      sencond_path=first_path+'/'+second_level
      for third_level in chr_list:
        third_path=sencond_path+'/'+third_level+'/'
        #print tmp_path
        ret.append(third_path)
  #print ret
  return ret

def write_todo_list(path_list):
  for each in path_list:
    print each
    #backup
    #files_list=os.listdir(each)
    #sample_files=select_samples_from_list(files_list)
    #backup
    #if scan_date is a space , suppose that there is no label for the sha256
    try:    
      reports_pd=pd.read_csv(SAMPLES_PATH+each+'reports.csv')
    except Exception,e:
      print e,' in ',SAMPLES_PATH+each+'reports.csv'
      continue
    need_label_pd=reports_pd[(reports_pd['scan_date']==' ')|(reports_pd['scan_date']=='')]
    need_label_pd=need_label_pd['sha256']
    need_label_pd.to_csv(LABEL_TODO_LIST_PATH,index=False, sep=',', mode='a', header=False)
    print SAMPLES_PATH+each+'reports.csv','completed'
  
def main():
  all_subdir_path=create_all_path()
  write_todo_list(all_subdir_path)

if __name__=='__main__':
  main()

