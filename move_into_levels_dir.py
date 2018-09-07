#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Nankai University Information Security
#QiuKF 1055419050@qq.com
#move files from failed folder into malware three levels
#The script is the frame of transport samples by multiprocess

from multiprocessing import Process,Pool
import os
import pandas as pd
import time
import sys

SAMPLES_PATH='/data/failed/'
CORRECT_PATH='/data/malware/'

#samples_path='/data/malware/collection/'

def move_samples(first_dir):

  print 'Run task %s (%s)...' % (first_dir, os.getpid())
  
  child_dir=make_file_dir(first_dir)
  #print child_dir
  for each_dir in child_dir:
    pre=SAMPLES_PATH+each_dir
    try:
      samples_list=os.listdir(pre)
    except Exception,e:
      print e
      continue
    #print samples_list
    for each_sample in samples_list:
      if len(each_sample)!=64:
      	print 'error ',each_sample
      	continue
      dst=CORRECT_PATH+each_sample[0]+'/'+each_sample[1]+'/'+each_sample[2]+'/'

      cmd_str='mv '+pre+each_sample+' '+dst
      print cmd_str
      #os.popen(cmd_str)

      #os.popen('rm -f '+SAMPLES_PATH+each_dir+'processed.csv')
      #os.popen('rm -f '+SAMPLES_PATH+each_dir+'vt_report.csv')

    #except Exception,e:
    #  print e,'continue'
    #  continue

    
def make_file_dir(first):
  ret=[]
  #print 1
  chr_list=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
  tmp=''
  for second in chr_list:
    two='/'+second
    for third in chr_list:
      three=two+'/'+third+'/'
      ret.append(first+three)
  return ret
  

def main():
  #print SAMPLES_PATH
  #print('Parent process %s.' %os.getpid())
  #dic_list=make_file_dir()
  #first_dir=['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
  #p=Pool(16)
  #for each in first_dir:
  #  p.apply_async(move_samples,args=(each,))
  #p.close()
  #p.join()
  
  #<--------not necessary-------->
  #merge_report()
  samples=os.listdir(SAMPLES_PATH)
  for each_sample in samples:
    dst=CORRECT_PATH+each_sample[0]+'/'+each_sample[1]+'/'+each_sample[2]+'/'
    cmd_str='mv '+SAMPLES_PATH+each_sample+' '+dst
    print cmd_str
    os.popen(cmd_str)

if __name__=='__main__':
  main()
  #while True:
  #  main()
  #  time.sleep(36000)

                                           
