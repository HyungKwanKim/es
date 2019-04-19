import psutil
import time

delay = 0.05

#from es_sender_udp_v4 start
from datetime import datetime, date
from elasticsearch import Elasticsearch
import time
import sys
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
#import matplotlib
#import matplotlib.pyplot as plt
import numpy as np
import udp_sender
import json
import uuid
from datetime import datetime
from datetime import timezone
import pandas as pd
import _pickle as pickle

#cpu, mem, disk
import psutil

    
def get_summary(df):
    return [df.mean(), df.min(), df.max()]

class Tool(object):
    
    def __init__(self):
        pass
    
    def save(self, df, filename):
        with open(filename, 'wb') as fp:
            pickle.dump(df, fp)
            #pickle.dump(es, fp)
        print('save ok to:', filename)
        
    def load(self, filename):
        with open(filename, 'rb') as fp:
            df = pickle.load(fp)
            #es = pickle.load(fp)
        print('load ok from', filename)
        return df#, es

def func(a, b):
    print('func:', a, b)

def json_serial(data):
    org = data
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(data, (date, datetime)):
        return data.isoformat()
    elif isinstance(data, Decimal):
        return float(data)
    elif isinstance(data, uuid.UUID):
        return str(data)
    raise TypeError("Unable to serialize %r (type: %s)" % (data, type(data)))
    
raw_wins = b'<36>[SNIPER-0001] [Attack_Name=(0400)SMB Service connect(tcp-445)], [Time=2018/07/19 11:39:22], [Hacker=192.0.0.0], [Victim=192.0.0.0], [Protocol=tcp/445], [Risk=Medium], [Handling=Alarm], [Information=], [SrcPort=63883], [HackType=00004]'
    
class ElasticsearchWrapper(object):
    def __init__(self, IP, PORT, USERID='', PW=''):
        self.user_id = USERID
        if self.user_id != '':
            self.es = Elasticsearch("http://"+IP+":"+str(PORT), http_auth=(USERID,PW), use_ssl=False)
            print('connected by', USERID)
        else:
            self.es = Elasticsearch("http://"+IP+":"+str(PORT), use_ssl=False)
            print('connected anonymous')

        UDP_IP = IP
        UDP_PORT = 5514
        self.udpsender = udp_sender.UdpSender(UDP_IP, UDP_PORT)
        self.n_loss = 0

    def add_mapping(self, index, mapping):
        res = self.es.indices.create(index=index, ignore=400, body=mapping)#400?
        print(res)
    
    def send(self, index, doc_type, id, json_data):
        res = self.es.index(index=index, doc_type=doc_type, id=id, body=json_data)
        #print(res['result'])
        return res

    def send_by_udp(self, msg):

        #TODO 7.20
        json_data_bytes = json.dumps(msg, default=json_serial)
        #json_data_bytes = json.dumps(msg, default=str)
        self.udpsender.send(json_data_bytes)
        
    def get(self, index, doc_type, doc_id):
        res = self.es.get(index=index, doc_type=doc_type, id=doc_id)
        #print(res['_source'])
        return res

    def delete(self, index, doc_type, id):
        res = self.es.delete(index=index,doc_type=doc_type,id=id)
        return res

    def delete_index(self, index):
        res = self.es.indices.delete(index=index, ignore=[400, 404])
        return res

    def search(self, index, json_match):
        #res = es.search(index=index, body={"query": {"match": {"tag": "benchmark"}}})
        res = self.es.search(index=index, body={"query": json_match}, size=10000)
        print("Got %d Hits Total:" % res['hits']['total'])
        print("Got %d Hits Hits:" % len(res['hits']['hits']))
        #print(res)
        for hit in res['hits']['hits']:
            #print("%(timestamp)s %(text)s" % hit["_source"])
            print(hit["_source"])

        return res['hits']['hits']

    def put_pipeline_test(self):
        (ret_code, response) = es_client.transport.perform_request(
            method = 'PUT',
            url = '/bank_version1/account/new_id2',
            body = {
                'state': 'NY'
            })
        if ret_code == 200:
            print("PUT pipeline OK")
            
    def send_search_wait_compare(self, index, doc_type, doc_id, doc):
        doc['text'] = 'data'*10+'-'+str(doc_id)
        doc['doc_type'] = doc_type
        doc['doc_id'] = doc_id
        doc['index'] = index

        #make doc in advance -> make index/doc
        # res = self.send(index, doc_type, doc_id, doc)
        # print(res)
        
        while True:
            try:
                #TODO:option of es-direct or logstah-via
                #res = self.send(index, doc_type, doc_id, doc)
                res = self.send_by_udp(doc)
                time_start = time.time()
                break
            except Exception as e:
                print('retrying send... error:', e)

        #print('point-a')
        #print(res)
        time_sent = time.time()
        t1 = time_sent
        time_out = 30
        while True:#True:
            try:
                if time.time()-time_sent > time_out:
                    self.n_loss += 1
                    break
                
                res = es.get(index, doc_type, doc_id)
                print(res)
                text, n = res['_source']['text'].split('-')
                t21 = res['_source']['t21']
                t22 = res['_source']['t22']
                t23 = res['_source']['t23']
                t32 = res['_source']['t32']
                if int(n) == doc_id:
                    ok = True
                else:
                    ok = False
                    print(doc)
                    print(res['_source'])
                break
            except Exception as e:
                print('wait for es arriving...', e)
                #time.sleep(1)
                
        t34 = time.time()
        t_box = [t1, t21, t22, t23, t32, t34, ok]
        print(index, doc_type, doc_id, 'ok')

        #return time_start, time.time(), ok, time_sent, t_box
        return 0, 0, 0, 0, t_box

IP = "0.0.0.0"
PORT = 9200
es = ElasticsearchWrapper(IP=IP, PORT=PORT)
#USERID = "elastic"
#PW = "pw"
#es = ElasticsearchWrapper(IP=IP, PORT=PORT, USERID=ID, PW=PW)

index='trm10-time'
doc_type='tweet'
doc_id = 80001
#es.add_mapping(index, mapping)

#Es_sender_udp_v4 end
time_start = time.time()
time_measure = 1.0
time_end = time.time()
count_sent = 0
while True:
    # if time.time()-time_start > time_measure:
    #     time_end = time.time()
    #     break
    
    cpu_freq = psutil.cpu_freq()
    if cpu_freq != None:
        cpu_freq_now = cpu_freq[0]
        cpu_freq_min = cpu_freq[1]
        cpu_freq_max = cpu_freq[2]
        print('cpu_freq:', cpu_freq)
    # else:
    #     print('no cpu_freq info')

    #speed up required afterwards
    mem = psutil.virtual_memory()[2] #percent
    disk = psutil.disk_usage('/')[3]
    cpu = psutil.cpu_percent()
    cpu_io = psutil.cpu_times()
    io = cpu_io[4]
    irq= cpu_io[5]
    softirq = cpu_io[6]
    cpu_count = psutil.cpu_count()
    #n_handles = psutil.num_handles()
    n_thread = psutil.Process().num_threads()
    vm = psutil.virtual_memory()
    sm = psutil.swap_memory()
    pids = psutil.pids() #n_processes
    n_pid = len(pids)
    temps = psutil.sensors_temperatures()
    vm_total = vm[0] #total physical memory
    sm_percent = sm[3]
    sm_total = sm[0] #total swap memory
    net = psutil.net_io_counters()
    bytes_sent = net[0]
    bytes_recv = net[1]
    packets_sent = net[2]
    packets_recv = net[3]
    errin = net[4]
    errout = net[5]
    dropin = net[6]
    dropout = net[7]
    
    if len(temps) > 0:
        print('temps:', temps)

    print(round(time.time(),2), 'cpu:', cpu, 'mem:', mem, 'disk:', disk, 'io:', io, 'irq:', irq, 'softirq:', softirq, 'cpu_count',cpu_count, 'n_thread:', n_thread, 'n_pid:', n_pid, 'sm_percent:', sm_percent, 'vm_total:', vm_total, 'network:', bytes_sent, bytes_recv, packets_sent, packets_recv, errin, errout, dropin, dropout)

    #print(vm, sm)
    #svmem(total=2095837184, available=1397256192, percent=33.3, used=663449600, free=696631296, active=1090674688, inactive=154800128, buffers=211984384, cached=523771904, shared=1593344, slab=121819136)
    #sswap(total=1985998848, used=21938176, free=1964060672, percent=1.1, sin=1232478208, sout=2016452608)

    doc = {
        'timestamp': datetime.now(),
        'tag': 'benchmark'
    }
    
    #doc['text'] = 'data'*10+'-'+str(doc_id)
    # doc['doc_type'] = doc_type
    # doc['doc_id'] = doc_id
    # doc['index'] = index
    
    
    #variable parts
    doc['mem'] = mem
    doc['disk'] = disk
    doc['cpu'] = cpu
    doc['io'] = io
    doc['irq'] = irq
    doc['softirq'] = softirq
    doc['cpu_count'] = cpu_count
    doc['n_thread'] = n_thread
    doc['n_pid'] = n_pid
    doc['vm_total'] = vm_total
    doc['sm_percent'] = sm_percent
    doc['sm_total'] = sm_total
    doc['bytes_sent'] = bytes_sent
    doc['bytes_recv'] = bytes_recv
    doc['packets_recv'] = packets_recv
    doc['errin'] = errin
    doc['errout'] = errout
    doc['dropin'] = errout
    doc['dropout'] = errout

    res = es.send(index, doc_type, doc_id, doc)
    count_sent += 1
    doc_id += 1
    
    #res = es.send_by_udp(doc)
    print(res)

    sent_rate = count_sent / (time.time() - time_start)
    print('sent_rate:', round(sent_rate, 2), 'times/sec')
 
    #delay
    time.sleep(delay)



#make query using timestamp
#get query from es
#show data

#2018-08-02T15:52:03.439545
#timestamp to 2018-08-02T15:52:03.439545
#time_start_str = datetime.strptime(str(time_start), '%Y-%m-%dT%H:%M:%S.%fZ')
#time_end_str =  datetime.strptime(str(time_end), '%Y-%m-%dT%H:%M:%S.%fZ')
#time_start_str = datetime.strftime(time_start, '%Y-%m-%dT%H:%M:%S.%fZ')
#time_end_str =  datetime.strftime(time_end, '%Y-%m-%dT%H:%M:%S.%fZ')


#time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(1347517370))
#time_start_str = datetime.strftime('%Y-%m-%dT%H:%M:%S.%fZ', time_start)
#print('[DBG]', time_start_str)

#tmp for time gap calibration
# time_start -= 1000
# time_end +=1000

#query n -> all
time_start_str = datetime.fromtimestamp(time_start).strftime('%Y-%m-%dT%H:%M:%S.%f')
time_end_str = datetime.fromtimestamp(time_end).strftime('%Y-%m-%dT%H:%M:%S.%f')

#datetime reference
#datetime.datetime.now().strftime("%H:%M:%S.%f")
#datetime.datetime.fromtimestamp(1347517370).strftime('%Y-%m-%d %H:%M:%S')
#datetime.datetime.utcfromtimestamp(1347517370).strftime('%Y-%m-%d %H:%M:%S')

print('time_start:', time_start, 'time_end:', time_end)
print('time_start_str:', time_start_str, 'time_end_str:', time_end_str)
#print('time_start_str:', type(time_start_str))

print('wait before query...')
time.sleep(2)

# time_start = int(time_start)
# time_end = int(time_end)

#actual, time calibration required
json_match = {
    "range" : {
        "timestamp" : {
            "gte": time_start_str,
            "lte": time_end_str
#            "time_zone": "+09:00"
        }
    }
}

print('count_sent:', count_sent)
#json_match = {'match_all':{}}
res = es.search(index, json_match)
vtry: 
    #print(res)
    print('n:', len(res))
except Exception as e:
    print('no result', 'error:', e)

#todo search -> return
#todo search size -> 10000 or unlimited
