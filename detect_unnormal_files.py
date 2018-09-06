#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Nankai University Information Security
#QiuKF 1055419050@qq.com
#detect illegal file from samples' folder

import os
import re

SAMPLES_PATH='/data/malware/'
unnormal_list=[]
detect_pattern='(([0123456789abcdef]{64})|(reports.csv)|([0123456789abcdef]{64}(.data|.xml)))$'
#detect_pattern_150='(([0123456789abcdef]{64})|(vt_report.csv)|([0123456789abcdef]{64}(.data|.xml)))$'


def detect():
  first_level=os.listdir(SAMPLES_PATH)
  for first_chr in first_level:
    second_level=os.listdir(SAMPLES_PATH+first_chr+'/')
    for second_chr in second_level:
      third_level=os.listdir(SAMPLES_PATH+first_chr+'/'+second_chr+'/')
      for third_chr in third_level:
        files=os.listdir(SAMPLES_PATH+first_chr+'/'+second_chr+'/'+third_chr+'/')
        for each_file in files:
          if not re.match(detect_pattern, each_file):
            print SAMPLES_PATH+first_chr+'/'+second_chr+'/'+third_chr+'/'+each_file
            unnormal_list.append(SAMPLES_PATH+first_chr+'/'+second_chr+'/'+third_chr+'/'+each_file)
            file_rm = SAMPLES_PATH+first_chr+'/'+second_chr+'/'+third_chr+'/'+each_file
            os.popen("rm -fr " + file_rm)

if __name__=='__main__':
  detect()

  print  unnormal_list


  




  
  
