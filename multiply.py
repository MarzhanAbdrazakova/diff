from flask import Flask
from flask import request
import json
import requests

app = Flask(__name__)
@app.route('/', methods=['POST'])
def api():
    data=request.get_data()
    resp=json.loads(data)
    d={int(k): (v) for k,v in resp.items()} 
    while d[1]=="*":
        res=int(d[0])*int(d[2])
        d[0]=res
        m=3
        if len(d.keys())==3: 
            return (json.dumps(res))
        for i in range(1,len(d.keys())-2): 
            d[i]=d.pop(m) 
            i+=1
            m+=1
        if d[1]=="+":
            url='http://10.0.0.2:5000'
        elif d[1]=="-":
            url='http://10.0.0.2:5100'
        elif d[1]=="/":
            url='http://10.0.0.2:5200'
        
    if d[1]=="+":
        url='http://10.0.0.2:5000'
    elif d[1]=="-":
        url='http://10.0.0.2:5100'
    else:
        url='http://10.0.0.2:5200'
    
    p=requests.post(url,json.dumps(d))
    return p.text
    
if __name__ == '__main__':
    app.run(host='10.0.0.2',port=5300)

