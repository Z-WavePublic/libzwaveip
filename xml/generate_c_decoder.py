# Copyright 2016 Sigma Designs, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import xml.dom.minidom as xdm
import sys
from lib2to3.pgen2.token import RPAR
x = xdm.parse("../config/ZWave_custom_cmd_classes.xml")

#struct zw_command_class {
#  int cmd_class_number;
#  int cmd_class_number_version;
#
#  char* name;
#  char* help;
#  struct zw_command** commands;
#};

def dom2unique_name(d):
  s= str(d).split()
  return "dom_" + s[2]+ s[4].rstrip(">")

def deserailize_domlist(parent, tagname):  
  s=""
  if(not type(tagname) is list):
      tagname = [tagname]

  childs = filter( lambda n: n.nodeType==1 and n.tagName in tagname ,  parent.childNodes)
  for c in childs:
      s = s +"&"+dom2unique_name(c) + ","
  return s


def emit_cmd_class(c):
    print "static struct zw_command_class  "+dom2unique_name(c) +" = {"
    print int(c.getAttribute("key"),16),",",
    print int(c.getAttribute("version"),16),",",
    print '"'+c.getAttribute("name")+'",',
    print '"'+c.getAttribute("help")+'",',
    print '{',deserailize_domlist(c,"cmd"),'0,}'
    print '};';

def emit_cmd(c):
    print "static struct zw_command  "+dom2unique_name(c) +" = {"
    print int(c.getAttribute("key"),16),",",
    print int(c.getAttribute("cmd_mask"),16) if c.hasAttribute("cmd_mask") else 0xFF,",", 
    print '"'+c.getAttribute("name")+'",',
    print '"'+c.getAttribute("help")+'",',
    print '{',deserailize_domlist(c,["param","variant_group"]),'0}'
    print '};';

def emit_varinat_group(c):

    name = c.getAttribute("name")
    mask = 0xFF
    length_location = int(c.getAttribute("paramOffs"),16)
    
    
    if(length_location != 255):
        offs = [ x for x in c.parentNode.getElementsByTagName("param") if int(x.getAttribute("key"),16) == length_location ]
        length_location = "&"+dom2unique_name(offs[0]) if len(offs)>0 else "0"
    else:        length_location = "0"
        
        
    length_location_mask = int(c.getAttribute("sizemask"),16)
    display =   "DISPLAY_STRUCT" 
    sub_params = deserailize_domlist(c,["param","variant_group"])
    
    print '''
static struct zw_parameter %s = {
  255, //length
  %s, //length_location
  %i, //length_location_mask
  255, //mask
  %s, //display
  "%s", //name
  0, // optionaloffs
  0, //optionalmask
  0, // enums
  {%s 0 }, //subparams
};
''' % (dom2unique_name(c),  length_location,length_location_mask,
       display,name,sub_params)
    
    
def emit_param(c):
    p_type = c.getAttribute("type")
    name = c.getAttribute("name")

    if(c.hasAttribute("optionaloffs")):
        key = c.getAttribute("optionaloffs")
        offs = [ x for x in c.parentNode.getElementsByTagName("param") if x.getAttribute("key") == key ]
        optionaloffs = "&"+dom2unique_name(offs[0]) 
    else:
        optionaloffs = "0"
        
    optionalmask =  int(c.getAttribute("optionalmask"),16) if c.hasAttribute("optionalmask") else 0x0
    mask = 0xFF
    length_location = None
    length_location_mask = 0
    length = 0
    if(c.hasAttribute("showhex") and getAttribute("hasdefines") == "true"):
        display =   "DISPLAY_HEX" 
    else:
        display = "DISPLAY_DECIMAL"
    
    enums=""
    sub_params=""
        

    if(p_type=="BYTE"):
        length = 1
        #a = c.getElementsByTagName('valueattrib')[0]
        #if( a.getAttribute("showhex") == "true"):
        #    display = "DISPLAY_HEX"
        #
        #if( a.getAttribute("hasdefines") == "true"):
        #    display = "DISPLAY_ENUM"
            
        for s in [ (k.getAttribute("flagname"),k.getAttribute("flagmask")) for k in c.getElementsByTagName("bitflag")]:
            enums = enums+'{"'+s[0]+'",'+s[1]+'},'

    elif( p_type== "WORD" ):
        length = 2
    elif( p_type== "DWORD" ):
        length = 4
    elif( p_type== "BIT_24" ):
        length = 3
    elif( p_type == "ARRAY" ):
        a = c.getElementsByTagName('arrayattrib')[0]
        if(a.getAttribute("is_ascii") =="true"):
            display ="DISPLAY_ASCII"
        length = int(a.getAttribute("len"),16) if a.hasAttribute("len") else 0

        a = c.getElementsByTagName('arraylen')
        if(len(a) >0 ):
            length_location = int(a[0].getAttribute("paramoffs"))
            length_location_mask =int(a[0].getAttribute("lenmask"),16)
        
    elif(p_type == "BITMASK"):        
        a = c.getElementsByTagName('bitmask')[0]
        display = "DISPLAY_STRUCT"

        length = int(a.getAttribute("len"),16) if a.hasAttribute("len") else 0
        
        length_location = int(a.getAttribute("paramoffs"))
        length_location_mask =int(a.getAttribute("lenmask"),16)
        
        for c2 in c.getElementsByTagName("bitflag"):
            emit_bitparm(c2)

        sub_params = sub_params+ deserailize_domlist(c,"bitflag")

    elif( p_type == "STRUCT_BYTE"):
        length = 1
        display = "DISPLAY_STRUCT"
        
        for c2 in c.getElementsByTagName("bitfield"):
            emit_bitparm(c2)
    
        for c2 in c.getElementsByTagName("bitflag"):
            emit_bitparm(c2)
    
        for c2 in c.getElementsByTagName("fieldenum"):
            emit_bitparm(c2)

        sub_params = deserailize_domlist(c,"bitfield")
        sub_params = sub_params+ deserailize_domlist(c,"bitflag")
        sub_params = sub_params+deserailize_domlist(c,"fieldenum")
    elif( p_type == "ENUM" or p_type == "ENUM_ARRAY" ):
        length = 1 if(p_type == "ENUM") else 255
        
        display = "DISPLAY_ENUM"
        for s in [ (k.getAttribute("name"),k.getAttribute("key")) for k in c.getElementsByTagName("enum")]:
            enums = enums+'{"'+s[0]+'",'+s[1]+'},'
    elif( p_type == "MULTI_ARRAY"):
        #TODO
        length = 1
        pass
    elif( p_type == "CONST"):
        length = 1
        display = "DISPLAY_ENUM_EXCLUSIVE"
        for s in [ (k.getAttribute("flagname"),k.getAttribute("flagmask")) for k in c.getElementsByTagName("const")]:
            enums = enums+'{"'+s[0]+'",'+s[1]+'},'
    elif( p_type == "VARIANT" ):
        k = c.getElementsByTagName('variant')[0]
        length = 255

        if(k.hasAttribute("paramoffs")):
            length_location = int(k.getAttribute("paramoffs"))

        length_location_mask = int(k.getAttribute("sizemask"),16)
        if(k.getAttribute("is_ascii") == "true"):
            display = "DISPLAY_ASCII"
        elif( k.getAttribute("showhex") == "true"):
            display = "DISPLAY_HEX"
    elif( p_type == "MARKER" ):
        length = 1
    else:
        print "Unknown type ",p_type
        sys.exit(-1)


    if(length_location and length_location != 255):
        offs = [ x for x in c.parentNode.getElementsByTagName("param") if int(x.getAttribute("key"),16) == length_location ]
        length_location = "&"+dom2unique_name(offs[0]) if len(offs)==1 else "0"
    else:
        length_location = "0"
        
       
    if(enums != ""):
        enum_name =dom2unique_name(c) + "_enum"
        print '''
static struct zw_enum %s[] = { 
    %s 
    {0,0}
};
''' %(enum_name,enums)

    else:
        enum_name = 0

    print '''
static struct zw_parameter %s = {
  %i, //length
  %s, //length_location
  %i, //length_location_mask
  %i, //mask
  %s, //display
  "%s", //name
  %s, // optionaloffs
  %i, //optionalmask
  %s, // enums
  {%s 0 }, //subparams
};
''' % (dom2unique_name(c), length, length_location,length_location_mask,255,
       display,name,optionaloffs,length_location_mask,enum_name,sub_params)

def emit_bitparm(c):

    enum="0"
    display = "DISPLAY_HEX"
    if(c.tagName == "bitfield"):
        name = c.getAttribute("fieldname")
        mask = int(c.getAttribute("fieldmask"),16)
    elif(c.tagName == "bitflag"):
        name = c.getAttribute("flagname")
        mask = int(c.getAttribute("flagmask"),16)
    elif(c.tagName == "fieldenum"):
        display = "DISPLAY_ENUM"
        if(not c.hasAttribute("fieldmask")):
            return
        name = c.getAttribute("fieldname")
        mask = int(c.getAttribute("fieldmask"),16)
        n=0
        
        enum = dom2unique_name(c)+"_enum"
        print 'struct zw_enum %s[] = {' % enum
        for s in [ k.getAttribute("value") for k in c.getElementsByTagName("fieldenum")]:
            print '{"%s",0x%x },' % (s,n)
            n+1
        print ' {0,0} };'

    print '''
static struct zw_parameter %s = {
    0, //length
    0, //length_location
    0, //length_location_mask
    0x%x,
    %s, //display
    "%s", //name
    0, //optionaloffs
    0, //optionalmask
    %s, //enums
    { 0 }, //subparams
};''' % (dom2unique_name(c),mask,display,name,enum)    


print '''
#include<stdint.h>
#include"zw_cmd_tool.h"
'''


for c in x.getElementsByTagName("param"):    
    emit_param(c)


for c in x.getElementsByTagName("variant_group"):
    emit_varinat_group(c)

for c in x.getElementsByTagName("cmd"):
    emit_cmd(c)

for c in x.getElementsByTagName("cmd_class"):
    emit_cmd_class(c)



cmd_classes = x.getElementsByTagName("cmd_class");

cmd_classes = sorted(cmd_classes, key =lambda  c: c.getAttribute("key") )

print 'struct zw_command_class* zw_cmd_classes[] = { '
for c in cmd_classes:
    print  "&"+dom2unique_name(c),","
    
print '0,};'



