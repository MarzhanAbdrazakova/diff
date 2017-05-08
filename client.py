import sys
import json
import requests

i=0
a=[]
t = raw_input("Enter math expression: ")
a=t.split(' ')
d = {}
while i<len(a):
    st={i:a[i]}
    d.update(st)
    i+=1
json1=json.dumps(d, ensure_ascii=False)
url = 'http://10.0.0.2:4000'
r=requests.post(url,json1)
print(r.text)





