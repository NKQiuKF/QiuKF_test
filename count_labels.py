#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Nankai University Information Security
#QiuKF 1055419050@qq.com
#make  label_todo_list.csv
#count labels by 'posutives'
#cout count of positives>=2
#cout count of positives=1
#cout count of positives=0
import os
import pandas as pd
import time
import sys
import re

#SAMPLES_PATH='/data/malware/'
SAMPLES_PATH='/data/benign/'
LABEL_TODO_LIST_PATH='/home/nkamg/QiuKF_test/label_todo_list.csv'

DIR_CHR=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
no_vt=[]
positives_2=[]
positives_1=[]
positives_0=[]
def create_all_path():
  ret=[]
  tmp_path=''
  for first_level in DIR_CHR:
    
    first_path=first_level
    for second_level in DIR_CHR:
      sencond_path=first_path+'/'+second_level
      for third_level in DIR_CHR:
        third_path=sencond_path+'/'+third_level+'/'
        #print tmp_path
        ret.append(third_path)
  #print ret
  return ret

def count_labels(path_list):
  global no_vt
  global positives_0
  global positives_1
  global positives_2
  for each in path_list:
    print each

    try:    
      reports_pd=pd.read_csv(SAMPLES_PATH+each+'reports.csv')
    except Exception,e:
      print e,' in ',SAMPLES_PATH+each+'reports.csv'
      continue
    try:
      positives_df=reports_pd[reports_pd['positives']!=' '] 
      positives_df=positives_df[positives_df['positives']=='0.0']
      positives_0+=list(positives_df['sha256'])
    except Exception,e:
      print e
      continue
      
    #no_vt_df=reports_pd[reports_pd['positives']==' ']
    #no_vt+=list(no_vt_df['sha256'])
    #one_positives=reports_pd[reports_pd['positives']=='1.0']
    #positives_1+=list(one_positives['sha256'])
    #more_positives=reports_pd[reports_pd['positives']!=' ']
    #more_positives=more_positives[more_positives['positives']!='1.0']
    #positives_2+=list(more_positives['sha256'])
    print SAMPLES_PATH+each+'reports.csv','completed'
  
def main():
  all_subdir_path=create_all_path()
  count_labels(all_subdir_path)
  a=open('benign_vt.csv','w')
  a.write(str(positives_0))
  a.close()
  #a=open('1_vt.csv','w')
  #a.write(str(positives_1))
  #a.close()
  #a=open('2_vt.csv','w')
  #a.write(str(positives_2))
  #a.close()
  print '0 posiitives',len(positives_0)
  print "1 positives",len(positives_1)
  print "2 positives",len(positives_2)

if __name__=='__main__':
  main()
