#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Nankai University Information Security
#QiuKF 1055419050@qq.com
#check each sample in reports.csv whether it has its label
#if not, insert its sha256 into to_list prepared for get_label.py

from multiprocessing import Process,Pool
import os
import pandas as pd
import time
import sys

SAMPLES_PATH='/data/malware/'
#SAMPLES_PATH='/data/benign/'

def check_labels_exist(first_dir):

  print 'Run task %s (%s)...' % (first_dir, os.getpid())
  child_dir=make_file_dir(first_dir)
  for each_dir in child_dir:
    try:
      reports_pd=pd.read_csv(SAMPLES_PATH+each_dir+'reports.csv')
    except Exception,e:
      print e,' in ',SAMPLES_PATH+each_dir+'reports.csv'
      continue

    select_pd=reports_pd[['sha256','scan_date']]

    #if scan_date is a space , suppose that there is no label for the sha256
    need_label_list=select_pd[(select_pd['scan_date']==' ')|(select_pd['scan_date']=='')]
    #save the no-label sha256 in label_todo_list.csv,abs path attention!
    need_label_list['sha256'].to_csv(SAMPLES_PATH+each_dir+'label_todo_list.csv',index=False)

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
    p.apply_async(check_labels_exist,args=(each,))
  p.close()
  p.join()


if __name__=='__main__':
  main()

