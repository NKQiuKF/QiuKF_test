#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Nankai University Information Security
#QiuKF 1055419050@qq.com
import os
import pandas as pd
def get_labeled_set(file):  #abs path

  labeled_list=pd.read_csv(file,names=['sha256'])
  return set(list(labeled_list['sha256']))
  

def get_data_set(path):
  file_list=os.listdir(path)
  ret=[]
  for each in file_list:
    ret.append(each.split('.')[0])
  #print ret[:3]
  return set(ret)

def main():
 
  abs_path='/data/poison/dataset/2016/'
  total_list_path='/data/poison/poisoning/year_distribution/'
  #get total set first
  data_file_set=set()
  data_dir=['2016']
  for each in data_dir:
    data_file_set=data_file_set|(get_labeled_set(total_list_path+each))
  print len(data_file_set)
  #get labeled set second
  labeled_set=set()
  labeled_dir=['2016_malware','2016_benign']
  for each in labeled_dir:
    labeled_set=labeled_set|(get_labeled_set(abs_path+each))
  #print len(labeled_set) 
  need_label_set=data_file_set-labeled_set
  print len(need_label_set)
  #remove gray label third
  gray_set=get_labeled_set('/data/poison/poisoning/year_distribution/year_gray/2016_gray')
  need_label_set=need_label_set-gray_set
  print len(need_label_set)

  df=pd.DataFrame({'sha256':list(need_label_set)})
  df.to_csv("2016_need_label_list.csv",index=False,header=False)

if __name__=='__main__':
  main()
