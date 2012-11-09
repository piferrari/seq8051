#!/usr/bin/env python
# -*- coding: UTF-8 -*-

## Copyright (C) 2011  Pierre Ferrari <pif@piferrari.org>
## 
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## (at your option) any later version.
## 
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
## 
## You should have received a copy of the GNU General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import re
import serial
from optparse import OptionParser
import time
import pdb

## Remove c comments from file
## Source:http://stackoverflow.com/questions/844681/python-regex-question-stripping-multi-line-comments-but-maintaining-a-line-brea
comments_regex = re.compile(
  r'(^)?[^\S\n]*/(?:\*(.*?)\*/[^\S\n]*|/[^\n]*)($)?',
  re.DOTALL | re.MULTILINE
)

## find label. The label must begin with letter and it can contain letter, number and underscore. It must ending with colon.
## Example of legal label:
## Label: or Label_1: or lAbEl: or l_abel1: or Label123: or Label       : or Label  \t   \t   :
##
## Example of illegal label:
## _Label: or 1Label: or Label
label_regex = re.compile(
  r'(^)?[ \t]*((?P<label>(\b[^0-9_]{1}?[a-z0-9_]+)[ \t]*):)[ \t]*($)',
  re.IGNORECASE
)

jump_regex = re.compile(
  r'(^)?[ \t]*(saut|jump)[ \t]+(?P<line>(\b[^0-9_]{1}?[a-z]{1}[a-z0-9_]+))[ \t]*($)',
  re.IGNORECASE
)

call_regex = re.compile(
  r'(^)?[ \t]*(call)[ \t]+(?P<line>(\b[^0-9_]{1}?[a-z]{1}[a-z0-9_]+))[ \t]*($)',
  re.IGNORECASE
)

ret_regex = re.compile(
  r'(^)?[ \t]*ret[ \t]*($)',
  re.IGNORECASE
)

ew_regex = re.compile(
  r'(^)?[ \t]*(?P<cmd>[e|w]{1}?)[ \t]+(?P<value>([0-9]{1,3}|[01X]{8}b))[ \t]*($)',
  re.IGNORECASE
)

shift_regex = re.compile(
  r'(^)?[ \t]*(?P<where>p1|p3|[0-9]{1,3})[ \t]+(?P<shift><<|>>)[ \t]+(?P<rang>[1-7]{1})[ \t]*($)',
  re.IGNORECASE
)

incdec_regex = re.compile(
  r'(^)?[ \t]*(?P<cmd>(inc|incremente{1}?)|(dec|decremente{1}?))[ \t]+(?P<value>((p1|p3){1}|[0-9]{1,3}))[ \t]*($)',
  re.IGNORECASE
)

end_regex = re.compile(
  r'(^)?[ \t]*(?P<cmd>(end|fin{1}?))[ \t]*($)',
  re.IGNORECASE
)

sleep_regex = re.compile(
  r'(^)?[ \t]*(pause|sleep){1}?[ \t]+(?P<value>([0-9]+))[ \t]*ms[ \t]*($)',
  re.IGNORECASE
)

if_regex = re.compile(
  r'(^)?[ \t]*(if|si)[ \t]+(?P<statment>(p1|p3|\([0-9]{1,3}\)|[0-9]{1,3}){1}[ \t]*=[ \t]*(p1|p3|\([0-9]{1,3}\)|[0-9]{1,3}){1})[ \t]+(saut|jump)[ \t]+(?P<line>(\b[^0-9_]{1}?[a-z]{1}[a-z0-9_]+))[ \t]*($)',
  re.IGNORECASE
)

three_regex = re.compile(
  r'(^)?[ \t]*3[ \t]+(?P<mem>[0-9]{1,3})[ \t]+(?P<value>([0-9]{1,3}|[01X]{8}b))[ \t]*($)',
  re.IGNORECASE
)

def print_syntaxe():
 print """
 ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
 ┃                 Syntaxe of seq2051 file                    ┃
 ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

  All of the seq2051 syntaxe are case-insensitive!
  
 │Comments
 └────────────────────────────────────────────────────────────┐
  Comments allowed are the same as C/C++ comments like        │
  //One line comment                                          │
  /*************************                                  │
   Multiples lines comment                                    │
   *************************/                                 ┘  

 │Writing on port
 └────────────────────────────────────────────────────────────┐
  e value                   write «value» on p1 port          │
                            «value» must be between 0 and 255 │
  w value                   write «value» on p3 port          │
                            «value» must be between 0 and 255 │
                                                              ┘
  
 │Write value into a memory
 └────────────────────────────────────────────────────────────┐
  3 address value           write «value» into address memory │
                            «value» must be between 0 and 255 │
                                                              ┘
 │Incrementation/decremente port or memory
 └────────────────────────────────────────────────────────────┐
  inc destination           increment «destination»           │
                            «destination» can be «p1», «p3» or│
                            memory address between 64 and 127 │
  incremente destination    same as inc                       │
  dec destination           same as inc but for decrementation│
  decremente destination    same as dec                       │
                                                              ┘
 │Jump to...  
 └────────────────────────────────────────────────────────────┐
  jump label                jump to «label»                   │
  saut label                same as jump                      │
                                                              ┘
 │Labels  
 └────────────────────────────────────────────────────────────┐
  label:                    label consist of alphanumeric     │
                            and underscore characters followed│
                            by a colon but it can't begin with│
                            numeric or underscore character   │
                                                              ┘
 │If statment                                                 
 └────────────────────────────────────────────────────────────┐
  if left=right jump label  left and right posibilities are   │
                            «p1», «p3», memory address or     │
                            direct value. for memory address, │
                            you must enclose the value by     │
                            brackets like (64).               │
  si left=right saut label  same as if                        │
                                                              ┘

 │Sub routine                                                 
 └────────────────────────────────────────────────────────────┐
  call label                call jump to label and execute    │
                            sub routine commands. When it find│
                            ret command, it return to the next│
                            line after the call               │
  ret                       command to ending and return from │
                            sub routine                       │
                                                              ┘
                                                              
 │Shift                                                 
 └────────────────────────────────────────────────────────────┐
  destination << value      left shift destination execute    │
                            a destination value division by   │
                            2^value                           │
  destination >> value      right shift destination execute   │
                            a destination value division by   │
                            2^value                           │
                                                              ┘""" 

def scan_serial_port():
  # scan for available ports. return a list of tuples (num, name)
  available = []
  for i in range(256):
    try:
      s = serial.Serial('/dev/ttyS%d' % i)
      available.append(s.portstr)
      s.close()
    except serial.SerialException:
      pass
  for i in range(256):
    try:
      s = serial.Serial('/dev/ttyUSB%d' % i)
      available.append(s.portstr)
      s.close()
    except serial.SerialException:
      pass
  return available

def find_labels(lines):
  ## find label and the num of line who is
  all_labels = dict()
  for (index, line) in enumerate(lines):
    m = label_regex.match(line)
    if m:
      all_labels[m.group('label')] = index
  return all_labels
  
def compile(_lines):
  try:
    ## parse seq file and execute command
    i = 0
    compilation_status = True
    while i < len(_lines):
      reconized_line = False
      ## try if it's call command
      m = call_regex.match(_lines[i])
      if m:
        reconized_line = True
        if labels.get(m.group('line')) == None:
          print "Label '%s' not reconized" % m.group('line')
          compilation_status = False      
      ## try if it's jump command
      m = jump_regex.match(_lines[i])
      if m:
        reconized_line = True
        if labels.get(m.group('line')) == None:
          print "Label '%s' not reconized" % m.group('line')
          compilation_status = False
      ## try for e or w command
      m = ew_regex.match(_lines[i])
      if m and not reconized_line:
        reconized_line = True
        if len(m.group('value')) == 3:
          i_value = int(m.group('value'))
          if i_value < 0 or i_value > 255:
            compilation_status = False
            print "Value '%s' out of range" % m.group('value')
      ## try for shift command
      m = shift_regex.match(_lines[i])
      if m and not reconized_line:
        reconized_line = True
        p_value = m.group('where').lower()
        if p_value != 'p1' and p_value != 'p3':
          value = int(m.group('where'))
          if value > 127 or value < 64:
            compilation_status = False
            print "Memory value '%s' out of range" % value      
      ## try for inc or dec command
      m = incdec_regex.match(_lines[i])
      if m and not reconized_line:
        reconized_line = True
        p_value = m.group('value').lower()
        if p_value != 'p1' and p_value != 'p3':
          value = int(m.group('value'))
          if value > 127 or value < 64:
            compilation_status = False
            print "Memory value '%s' out of range" % value
      ## try for ret or fin command
      m = ret_regex.match(_lines[i])
      if m and not reconized_line:
        reconized_line = True
      ## try for end or fin command
      m = end_regex.match(_lines[i])
      if m and not reconized_line:
        reconized_line = True
       ## try for pause value ms command
      m = sleep_regex.match(_lines[i])
      if m and not reconized_line:
        reconized_line = True
      ## try for if statment
      m = if_regex.match(_lines[i])
      if m and not reconized_line:
        reconized_line = True
        ## is label reconized ?
        if labels.get(m.group('line')) == None:
          print "Label '%s' not reconized" % m.group('line')
          compilation_status = False
        ## split value statment from '='
        statment = re.sub(r'\s', '', m.group('statment'))
        statments = statment.split('=')
        for st_num in range(2):
          ## is memory value like (mem) ?
          m = re.match(r'^\(([0-9]{1,3})\)$', statments[st_num])
          if m:
            mem = int(m.group(1))
            if mem > 127 or mem < 64:
              compilation_status = False
              print "Memory value '%s' out of range" % statments[st_num]
          ## if len = 3 is an value -> test if not out of range
          elif len(statments[st_num]) == 3:
              value = int(statments[st_num])
              if value < 0 or value > 255:
                compilation_status = False
                print "Value '%s' out of range" % statments[st_num]
      ## try for 3 command (write value in memory)
      m = three_regex.match(_lines[i])
      if m and not reconized_line:
        reconized_line = True
        mem = int(m.group('mem'))
        if mem > 127 or mem < 64:
          compilation_status = False
          print "Memory value '%s' out of range" % m.group('mem')
        value = int(m.group('value'))
        if value < 0 or value > 255:
          compilation_status = False
          print "Value '%s' out of range" % m.group('value')
      if not reconized_line and not label_regex.match(_lines[i]):
        print "Unreconized this command '%s'" % _lines[i]
        compilation_status = False
      i = i + 1
  except:
    print "Unexpected error:", sys.exc_info()[0]
    pass
  finally:
    return compilation_status

def monitor_read(_where):
  ## send command to read actual value
  if _where == 'p1':
    com.write('l')
  elif _where == 'p3':
    com.write('r')
  else:
    _where = re.sub(r'[^0-9]+', '', _where) ## remove brackets (64) -> 64
    ## you must convert _where to int and to char '64'->64->'@'
    ## before sending to monitor
    com.write('4%s' % chr(int(_where)))
  
  ## read binary value from serial
  _port_value = com.read(1)
  ## return int value
  return ord(_port_value)

def monitor_write(_where, _value):
  if _where == 'p1':
    com.write('e%s' % chr(_value))
  elif _where == 'p3':
    com.write('w%s' % chr(_value))
  else:
    com.write('3%s%s' % (chr(int(_where)), chr(_value)))
  
def clean_code(text):
  code_wo_comments = remove_comments(text)

  lines = code_wo_comments.splitlines()
  ##remove empty lines
  lines = filter(None, lines)
  
  ##remove lines containing only whitespaces
  lines = filter(remove_whitespace, lines)
  return lines

def remove_whitespace(item):
  if re.match(r'^\s*$', item, flags=re.IGNORECASE):
    return False
  else:
    return True

def comments_regexplacer(match):
  start,mid,end = match.group(1,2,3)
  if mid is None:
    # single line comment
    return ''
  elif start is not None or end is not None:
    # multi line comment at start or end of a line
    return ''
  elif '\n' in mid:
    # multi line comment with line break
    return '\n'
  else:
    # multi line comment without line break
    return ' '

def remove_comments(text):
  return comments_regex.sub(comments_regexplacer, text)


if __name__ == '__main__':
  com = None
  parser = OptionParser("usage: %prog [options] FILE", version="%prog 0.1")
  parser.description = """
  This program is an short version of seq2051. It use the same seq2051 file.
  It's able to verifie (-c option) only the syntaxe of seq2051 file or interpret
  all command found in the seq2051 file and send it to serial port.
  You can use a debug mode (-d option) to enter in step by step mode."""
  
  parser.add_option("-c", "--compile", dest="compile", action="store_true",
                  default=False, help="only compile the FILE")
  parser.add_option("-i", "--interpreter", dest="interpreter", action="store_true",
                  default=False, help="compile an interpret the FILE")
  parser.add_option("-d", "--debug", dest="debug", action="store_true",
                  default=False, help="same as -i but in step by step mode")
  parser.add_option("-s", "--scan-ports", dest="scan", action="store_true",
                  default=False, help="scan serial ports")
  parser.add_option("-p", "--port", dest="port", metavar="PORT",
                  default='/dev/ttyUSB0', help="which PORT you want to use [default: %default]")
  parser.add_option("-x", "--syntaxe", dest="syntaxe", action="store_true",
                  default=False, help="print seq2051 syntaxe")

  (options, args) = parser.parse_args()
  
  if options.syntaxe:
    print_syntaxe()
    exit()
  
  if options.scan:
    ports = scan_serial_port()
    print "Found %d serial ports! Choose one of them using its name:" % len(ports)
    for port in ports:
      print "port name:'%s'" % port
    sys.exit()

  if len(args) != 1:
    print "Wrong number args"
    parser.print_usage()
    sys.exit()
    
  try:
    filename = args[0]
    code_w_comments = open(filename).read()
    lines = clean_code(code_w_comments)
  
    ## find all labels and place it in an dict
    labels = find_labels(lines)

    if options.compile:
      compilation_status = compile(lines)
      if compilation_status == False:
        print "Compilation failed"
      else:
        print "Compilation success"
    
    if options.interpreter:
      compilation_status = compile(lines)
      if compilation_status == False:
        print "Compilation failed"
        exit()
      
      current_command = 'empty command'
      ## open serial port
      com = serial.Serial(options.port, baudrate=9600, parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_TWO, timeout=1)
      ## disable atmel echo
      com.write("p\r\n")
      ## active binary mode
      com.write("n\r\n")

      ## parse seq file and execute command
      ## stack for return value of pc when call is find
      stack = []
      pc = 0
      while pc < len(lines) and com.isOpen():
        command_found = False
        
        ## try if it's call command
        m = call_regex.match(lines[pc])
        if m:
          ##pdb.set_trace()
          command_found = True
          current_command = "call %s" % m.group('line')
          if options.debug:
            null = raw_input("« %s » Press enter to continue\n" % current_command)
          new_line = int(labels[m.group('line')])
          if new_line >= 0 and new_line < len(lines):
            stack.append(pc+1)
            pc = new_line            
            continue
        
        ## try if it's ret command
        m = ret_regex.match(lines[pc])
        if m:
          command_found = True
          current_command = "ret"
          if options.debug:
            null = raw_input("« %s » Press enter to continue\n" % current_command)
          pc = stack.pop()
          continue
        
        ## try if it's jump command
        m = jump_regex.match(lines[pc])
        if m:
          command_found = True
          current_command = "saut %s" % m.group('line')
          if options.debug:
            null = raw_input("« %s » Press enter to continue\n" % current_command)
          new_line = int(labels[m.group('line')])
          if new_line >= 0 and new_line < len(lines):
            pc = new_line
            continue
        
        ## try for e or w command
        m = ew_regex.match(lines[pc])
        if m and not command_found:
          cmd = m.group('cmd')
          ## get the value as string like 75
          value = int(m.group('value'))
          current_command = "%s %d" % (cmd, value)
          if options.debug:
            null = raw_input("« %s » Press enter to continue\n" % current_command)
          ## send the value like chr. chr(value), if value = 75 -> K
          com.write('%s%s' % (cmd, chr(value)))
        
        ## try for shift command
        m = shift_regex.match(lines[pc])
        if m and not command_found:
          where = m.group('where').lower()
          shift = m.group('shift')
          rang  = m.group('rang')
          current_command = "%s %s %s" % (where, shift, rang)
          if options.debug:
            null = raw_input("« %s » Press enter to continue\n" % current_command)
          p_value = monitor_read(where)

          rang = int(rang)
          if shift == '>>':
            p_value = p_value / 2**rang
          else:
            p_value = p_value * 2**rang
          
          p_value = p_value & 255
          ## write new value to destination
          monitor_write(where, p_value)
        
        ## try for inc or dec command
        m = incdec_regex.match(lines[pc])
        if m and not command_found:
          cmd = m.group('cmd')
          value = m.group('value').lower()
          current_command = "%s %s" % (cmd, value)
          if options.debug:
            null = raw_input("« %s » Press enter to continue\n" % current_command)
            
          p_value = monitor_read(value)

          ## inc or dec ?
          if cmd[0] == 'd':
            delta = -1
          elif cmd[0] == 'i':
            delta = 1
          
          ## convert value from bin to dec
          p_value = p_value + delta
          ## loop value
          if p_value < 0:
            p_value = 255
          elif p_value > 255:
            p_value = 0
          ## write new value to destination
          monitor_write(value, p_value)

        ## try for end or fin command
        m = end_regex.match(lines[pc])
        if m and not command_found:
          current_command = "end"
          if options.debug:
            null = raw_input("« %s » Press enter to continue\n" % current_command)
          sys.exit()
    
         ## try for pause value ms command
        m = sleep_regex.match(lines[pc])
        if m and not command_found:
          current_command = "pause %sms" % value
          if options.debug:
            null = raw_input("« %s » Press enter to continue\n" % current_command)
          value = m.group('value')
          time.sleep(float(value)/1000.0)
          if options.debug:
            print current_command

        ## try for if statment
        m = if_regex.match(lines[pc])
        if m and not command_found:
          current_command = "if %s saut %s" % (m.group('statment'), m.group('line'))
          if options.debug:
            null = raw_input("« %s » Press enter to continue\n" % current_command)
          statment = re.sub(r'\s', '', m.group('statment'))
          ## split value statment from '='
          statments = statment.split('=')
          ## analyse left value
          left = statments[0].lower()
          if left == 'p1' or left == 'p3' or left[0] == '(':## if start with ( it's memory value
            left_value = monitor_read(left)
          else:
            left_value = int(left) ## direct value
          ## analyse right value
          right = statments[1].lower()
          if right == 'p1' or right == 'p3' or right[0] == '(':## if start with ( it's memory value
            right_value = monitor_read(right)
          else:
            right_value = int(right) ## direct value
          
          if left_value == right_value:
            new_line = int(labels[m.group('line')])
            pc = new_line
            continue
        
        ## try for 3 command (write value in memory)
        m = three_regex.match(lines[pc])
        if m and not command_found:
          memory = m.group('mem')
          value = m.group('value')
          current_command = "3 %s %s" % (memory, value)
          if options.debug:
            null = raw_input("« %s » Press enter to continue\n" % current_command)
          com.write("3%s%s" % (chr(int(memory)), chr(int(value))))
        pc = pc + 1

  except serial.SerialException, e:
    print 'Serial COM raise an exception when current command was « %s »' % current_command
    print e
    exit()
  except serial.SerialTimeoutException:
    print 'Serial COM raise timeout when current command was « %s »' % current_command
    exit()
  except KeyboardInterrupt:
    print '\nReceived keyboard interrupt, quitting threads'
    exit()
  except KeyError:
    print 'Error with this command « %s ». Label not found!' % current_command
    exit()
  except ValueError:
    print 'Conversion error exception. Current command when it raise was « %s »' % current_command
    sys.exit()
  except SystemExit:
    pass
  except IOError, e:
    print e
    exit()
  except TypeError:
    print e
    exit()
  except UnboundLocalError:
    print e
    exit()
  except:
    print 'Unexpected error [%s]. Current command was « %s »' % (sys.exc_info()[0], current_command)
    sys.exit()
  finally:
    if com:
      if com.isOpen():
        com.close()