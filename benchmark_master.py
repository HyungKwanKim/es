from datetime import datetime, date, timedelta
from elasticsearch import Elasticsearch
import time
import sys
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import udp_sender
import json
import uuid
from datetime import datetime
from datetime import timezone
import pandas as pd
import _pickle as pickle
import multiprocessing
import copy
import psutil
import threading
import math

FLAG_GRAPH = True#False#True
FLAG_SHOW = False#True

#ES
IP = "0.0.0.0"
IP_ELK2 = "0.0.0.0"
IP_ELK3 = "0.0.0.0"

PORT = 0000

#Logstash
#UDP_IP = IP
UDP_IP = IP_ELK3
UDP_PORT = 0000
ELA_IP = IP_ELK2

#1st way
#N_WORKERS = 20
#N_EVENTS = 1000
#N_TRIALS = 10

#2nd way
N_TRIALS = 1#10

T_PERIOD = 1.0
T_TOTAL = 10.0

HIST_X_LIM = 1.0
LATENCY_Y_WARNING = T_PERIOD #not used
LATENCY_Y_LIM = 0.3#1.0
BOXPLOT_Y_LIM = 0.3#1.0

IDX_SPECIFIC = 0 #select IDS 0:snpier, 1:ahnlab, ...?
#IDX_SPECIFIC = 1
#IDX_SPECIFIC = 2

N_IDS = 1000#0
N_PLC = 0#20#30
N_OPC = 0#60#60
N_SET = [N_IDS, N_PLC, N_OPC]
N_EVENTS = N_IDS+N_PLC+N_OPC
N_WORKERS = N_EVENTS

def timeit(method):
    def timed(*args, **kw):
        ts = time.time()
        result = method(*args, **kw)
        te = time.time()
        if 'log_time' in kw:
            name = kw.get('log_name', method.__name__.upper())
            kw['log_time'][name] = int((te - ts) * 1000)
            return result
        else:
            print('%r  %2.2f ms' % (method.__name__, (te - ts) * 1000))
            return result
    return timed

def get_summary(df):
    return [df.mean(), df.min(), df.max()]

import sys
from threading import Thread
from builtins import super    # https://stackoverflow.com/a/30159479

if sys.version_info >= (3, 0):
    _thread_target_key = '_target'
    _thread_args_key = '_args'
    _thread_kwargs_key = '_kwargs'
else:
    _thread_target_key = '_Thread__target'
    _thread_args_key = '_Thread__args'
    _thread_kwargs_key = '_Thread__kwargs'

class ThreadWithReturn(Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._return = None

    def run(self):
        target = getattr(self, _thread_target_key)
        if not target is None:
            self._return = target(*getattr(self, _thread_args_key), **getattr(self, _thread_kwargs_key))

    def join(self, *args, **kwargs):
        super().join(*args, **kwargs)
        return self._return

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
    
raw_wins = b'<36>[SNIPER-0001] [Attack_Name=(0400)SMB Service connect(tcp-445)], [Time=2018/07/19 11:39:22], [Hacker=0.0.0.0], [Victim=0.0.0.1], [Protocol=tcp/000], [Risk=Medium], [Handling=Alarm], [Information=], [SrcPort=10000], [HackType=00004]'
    
class ElasticsearchWrapper(object):
    def __init__(self, IP, PORT, USERID='', PW=''):
        self.user_id = USERID
        if self.user_id != '':
            self.es = Elasticsearch("http://"+IP+":"+str(PORT), http_auth=(USERID,PW), use_ssl=False)
            print('connected by', USERID)
        else:
            self.es = Elasticsearch("http://"+IP+":"+str(PORT), use_ssl=False)
            print('connected anonymous')

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

    def delete(self, index, doc_type, doc_id):
        res = self.es.delete(index=index,doc_type=doc_type,id=doc_id)
        return res

    def delete_index(self, index):
        res = self.es.indices.delete(index=index, ignore=[400, 404])
        return res

    def search(self, index, json_match, size):
        print('[search]', index, json_match)
        #res = es.search(index=index, body={"query": {"match": {"tag": "benchmark"}}})
        #res = self.es.search(index=index, body={"query": json_match})
        res = self.es.search(index=index, body={"query": json_match}, size=size)
        
        print("Got %d Hits:" % res['hits']['total'])
        for hit in res['hits']['hits']:
            #print("%(timestamp)s %(text)s" % hit["_source"])
            #print(hit["_source"])
            pass
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
                #t22 = res['_source']['t22']
                t23 = res['_source']['t23']
                t32 = res['_source']['t32']
                tn1 = res['_source']['tn1']
                tn2 = res['_source']['tn2']
                tn3 = res['_source']['tn3']

                rawpacket_id = res['_source']['rawpacket_id']
                #tmp
                #print(rawpacket_id)
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
        #t_box = [t1, t21, t22, t23, t32, t34, ok, rawpacket_id]
        t_box = [t1, t21, t23, t32, t34, tn1, tn2, tn3, ok, rawpacket_id]
        print(index, doc_type, doc_id, 'ok')

        #return time_start, time.time(), ok, time_sent, t_box
        return 0, 0, 0, 0, t_box


es = ElasticsearchWrapper(IP=ELA_IP, PORT=PORT)
#USERID = "elastic"
#PW = "wpdjqhdks"
#es = ElasticsearchWrapper(IP=IP, PORT=PORT, USERID=ID, PW=PW)

index='trm10'
index_time='trm10-time'
doc_type='tweet'
id = 80001
#es.add_mapping(index, mapping)

#old test doc
# doc = {
#     'text': 'Data1'*10,
#     'timestamp': datetime.now(),
#     'tag': 'benchmark',
# }

#doc of WINS Sniper Event Log
doc = {
    'timestamp': datetime.now(),
    'tag': 'benchmark',
    "text": '',
    "PortAttacker":"161",
       "LevelRisk":"Low",
      "TypeAction":"Alarm",
      "IPAttacker":"0.0.0.2",
     "Attack_Name":"(0397)UDP Packet Flooding",
            "Time":"2018/06/22 11:41:25",
    "Machine_Name":"SNIPER-0001",
        "HackType":"00001",
            "host":"0.0.0.0",
        "IPVictim":"0.0.0.1",
        "Protocol":"udp",
      "PortVictim":"55295"
}

#delete all doc_type documents
# res = es.delete(index, doc_type, id)

#cpu, memory
cpu = psutil.cpu_percent()
mem = psutil.virtual_memory()[2] #percent
disk = psutil.disk_usage('/')[3]
print('cpu:', cpu, 'mem:', mem, 'disk:', disk)


list_x = list()
list_y = list()
list_x_y = list()
list_sent = list()
list_rate_count = list()
list_rate_kb = list()
list_ok = list()
dict_t_box = dict()
list_t_box_eles = ['t1', 't21', 't22', 't23', 't32', 't34', 'rate_count']
for ele in list_t_box_eles:
    dict_t_box[ele] = list()

n_iter = 20000
n_workers = 20
xs = list(range(1, n_iter+1))
data_size = sys.getsizeof(doc)
total_data_size = 0
count = 0

#time_start_benchmark = time.time()
if 0:
#with ThreadPoolExecutor(max_workers=n_workers) as executor:
    futures = {executor.submit(es.send_search_wait_compare, index, doc_type, x, doc): x for x in xs}
    time_start = time.time()
    offset = time.time()
    for future_each in as_completed(futures):
        arg_a = futures[future_each] #why url returned?
        try:
            data = future_each.result()
            dict_t_box['t1'].append(data[4][0])
            dict_t_box['t21'].append(data[4][1])
            dict_t_box['t22'].append(data[4][2])
            dict_t_box['t23'].append(data[4][3])
            dict_t_box['t32'].append(data[4][4])
            dict_t_box['t34'].append(data[4][5])

            #new for histogram grouping
            #dict_t_box['rawpacket_id'].append(data[4][6])

            count += 1
            total_data_size += data_size
            time_elapsed = (time.time() - time_start)
            rate_count = count / time_elapsed
            dict_t_box['rate_count'].append(rate_count)
            #print('COUNT/SEC:', rate_count, 'KB/SEC:', rate_kb)
        except Exception as e:
            print('Exception', arg_a, e)

#time_end_benchmark = time.time()
            
class Benchmark(object):
    def __init__(self):
        pass
    def generate_lst_doc(self, n_ips, n_plc, n_opc):
        lst_doc = list()
        for i in range(n_ips):
            lst_doc.append(self.raw_packet('IPS', n_ips))
        for i in range(n_plc):
            lst_doc.append(self.raw_packet('PLC', n_plc))
        for i in range(n_opc):
            lst_doc.append(self.raw_packet('OPC', n_points=50))

        return lst_doc
                           
    def raw_packet(self, machine, n_points=1):
        if machine == 'IPS':
            doc = {
                'timestamp': datetime.now(),
                'tag': 'benchmark',
                "text": '',
                "PortAttacker":"161",
                "LevelRisk":"Low",
                "TypeAction":"Alarm",
                "IPAttacker":"0.0.0.1",
                "Attack_Name":"(0397)UDP Packet Flooding",
                "Time":"2018/06/22 11:41:25",
                "Machine_Name":"SNIPER-0001",
                "HackType":"00001",
                "host":"0.0.0.0",
                "IPVictim":"0.0.0.3",
                "Protocol":"udp",
                "PortVictim":"55295",
                "rawpacket_id":"IPS"
                }
        elif machine == 'PLC':
            doc = {
                'timestamp': datetime.now(),
                'tag': 'benchmark',
                'event_id': 16,
                'event_time':'2018/07/06 10:00:00',
                "Event_name":"Logon successful for Web server user 2",
                'machine': 'PLC_1 ',
                'Client IPAddr': '0.0.0.0',
                "rawpacket_id":"PLC"
                }
        elif machine == 'OPC':
            doc = {
                'timestamp': datetime.now(),
                'tag': 'benchmark',
                "rawpacket_id":"OPC"
                }
            for i in range(n_points):
                doc['point_'+str(i)] = i*1.1 #to make float value

        return doc

    def run_onetime(self, n_workers, n_events, index, lst_doc, enable_dummy=False):

        #n_workers == n_events
        #n_events == len(lst_doc)
        if n_workers != n_events:
            print('[ERR] n_workers != n_events')
            return
        if n_events != len(lst_doc):
            print('[ERR] n_events != len(lst_doc)', n_events, len(lst_doc))
            return

        doc_type='tweet'
        if enable_dummy:
            xs = list(range(n_events+1, n_events+1+n_events))
        else:
            xs = list(range(1, n_events+1))
        #doc = self.raw_packet('IPS'))
        #doc = self.raw_packet('PLC')
        doc = self.raw_packet('OPC', n_points=50)
        
        data_size = sys.getsizeof(doc)
        total_data_size = 0
        count = 0
        dict_t_box = dict()
        #list_t_box_eles = ['t1', 't21', 't22', 't23', 't32', 't34', 'rate_count', 'rawpacket_id']
        list_t_box_eles = ['t1', 't21', 't23', 't32', 't34', 'tn1', 'tn2', 'tn3', 'rate_count', 'rawpacket_id']
        for ele in list_t_box_eles:
            dict_t_box[ele] = list()
        
        with ThreadPoolExecutor(max_workers=n_workers) as executor:
            #futures = {executor.submit(es.send_search_wait_compare, index, doc_type, x, doc): x for x in xs}
            futures = {executor.submit(es.send_search_wait_compare, index, doc_type, x, doc): (x,doc) for x,doc in zip(xs,lst_doc)}
            #futures = {executor.submit(es.send_search_wait_compare, index, doc_type, x, doc): x for x in xs for doc in lst_doc)}
            
            time_start = time.time()
            offset = time.time()
            for future_each in as_completed(futures):
                arg_a = futures[future_each] #why url returned?
                try:

                    #t_box = [t1, t21, t23, t32, t34, tn1, tn2, tn3, ok, rawpacket_id]
                    
                    data = future_each.result()
                    dict_t_box['t1'].append(data[4][0])
                    dict_t_box['t21'].append(data[4][1])
                    # dict_t_box['t22'].append(data[4][2])
                    # dict_t_box['t23'].append(data[4][3])
                    # dict_t_box['t32'].append(data[4][4])
                    # dict_t_box['t34'].append(data[4][5])
                    dict_t_box['t23'].append(data[4][2])
                    dict_t_box['t32'].append(data[4][3])
                    dict_t_box['t34'].append(data[4][4])

                    dict_t_box['tn1'].append(data[4][5])
                    dict_t_box['tn2'].append(data[4][6])
                    dict_t_box['tn3'].append(data[4][7])

                    print('test //// ')
                    print('data:', data)
                    count += 1
                    total_data_size += data_size
                    time_elapsed = (time.time() - time_start)
                    rate_count = count / time_elapsed
                    dict_t_box['rate_count'].append(rate_count)
                    #dict_t_box['rawpacket_id'].append(data[4][7])
                    dict_t_box['rawpacket_id'].append(data[4][9])
                    #print('COUNT/SEC:', rate_count, 'KB/SEC:', rate_kb)
                except Exception as e:
                    print('Exception', arg_a, e)

        for ele in list_t_box_eles:
            print('ele:', ele, '=========')
            print(dict_t_box[ele])
        print('list_to_box_eles 1:5 check === ')
        # print(list_t_box_eles[1:5])
        # for ele in list_t_box_eles[1:5]:#[1:-1]:
        print(list_t_box_eles[1:4] + list_t_box_eles[5:8])
        for ele in list_t_box_eles[1:4]+list_t_box_eles[5:8]:#[1:-1]:

            #calibrate of format
            dict_t_box_calibrated = list()
            for a in dict_t_box[ele]:
                #print('a:', a)
                if len(a) == 20:
                    a = a[:-1] + '.000Z'
                    print(a)
                elif len(a) == 22:
                    a = a[:-1] + '00Z'
                    print(a)
                elif len(a) == 23:
                    a = a[:-1] + '0Z'
                    print(a)
                dict_t_box_calibrated.append(a)
                
            dict_t_box[ele] = dict_t_box_calibrated
            
            print('ele:', ele)
            #old
            dict_t_box[ele] = [(datetime.strptime(x, '%Y-%m-%dT%H:%M:%S.%fZ') - datetime(1970, 1, 1)).total_seconds() for x in dict_t_box[ele]]
            #new

            
            # for x in dict_t_box[ele]:
            #     if x[-1] == 'Z':
            #         #x = x+timedelta(milliseconds=1)
            #         #x = x + '.001'
            #         pass
            #     else:
            #         pass
            #     dict_t_box[ele] = [(datetime.strptime(x, '%Y-%m-%dT%H:%M:%S.%fZ') - datetime(1970, 1, 1)).total_seconds()]

        #_df = pd.DataFrame(dict_t_box, columns = ['t1', 't21', 't22', 't23', 't32', 't34', 'rate_count', 'rawpacket_id'], dtype='float64')
        _df = pd.DataFrame(dict_t_box, columns = ['t1', 't21', 't23', 't32', 't34', 'tn1', 'tn2', 'tn3', 'rate_count', 'rawpacket_id'], dtype='float64')
        
        #_df['t1_datetime'] = pd.to_datetime(_df['t1'])
        print('n_loss:', es.n_loss, 'loss rate:', round(es.n_loss/n_iter,2))
        #TODO: n_loss += n_loss_http (n_loss == n_lose_es)
        _df = _df.sort_values(['t1'], ascending=[True])
        #_df.index = _df['t1']
        #del _df['t1']
        _df['t_total'] = _df['t34'].sub(_df['t1'].values, axis=0)
        #_df['t_internal'] = _df['t21'].sub(_df['t1'].values, axis=0)
        # _df['t_logstash'] = _df['t22'].sub(_df['t21'].values, axis=0)
        # _df['t_grok'] = _df['t23'].sub(_df['t22'].values, axis=0)
        # _df['t_external'] = _df['t32'].sub(_df['t23'].values, axis=0)
        # _df['t_elastic'] = _df['t34'].sub(_df['t32'].values, axis=0)

        #t21 calibration
        #1.find min value of t21 => offset
        # print(_df['t_internal'].min())
        # inpur('ok1?')

        #enable offset
        #offset = abs(_df['t_internal'].min())# + 0.001
        #disable offset
        offset = 0
        
        _df['t21'] = _df['t21'].add(offset)
        #_df['t22'] = _df['t22'].add(offset)
        _df['t23'] = _df['t23'].add(offset)
        _df['t32'] = _df['t32'].add(offset)

        #todo:if external network exisits, t_external should be calibrated also.

        #re calculate after calibration
        # _df['t_internal'] = _df['t21'].sub(_df['t1'].values, axis=0)
        # _df['t_logstash'] = _df['t22'].sub(_df['t21'].values, axis=0)
        # _df['t_grok'] = _df['t23'].sub(_df['t22'].values, axis=0)
        # _df['t_external'] = _df['t32'].sub(_df['t23'].values, axis=0)
        # _df['t_elastic'] = _df['t34'].sub(_df['t32'].values, axis=0)

        #re calculate after calibration
        _df['t_internal_cps'] = _df['tn1'].sub(_df['t1'].values, axis=0)
        _df['t_logstash_cps_input'] = _df['tn2'].sub(_df['tn1'].values, axis=0)
        _df['t_logstash_cps_filter'] = _df['tn3'].sub(_df['tn2'].values, axis=0)
        _df['t_external'] = _df['t21'].sub(_df['tn3'].values, axis=0)
        _df['t_logstash_center_input'] = _df['t23'].sub(_df['t21'].values, axis=0)
        _df['t_internal_center'] = _df['t32'].sub(_df['t23'].values, axis=0)
        _df['t_elastic'] = _df['t34'].sub(_df['t32'].values, axis=0)


        return _df

    def run_n_time(self, n_workers, n_events, n):
        index = 'trm10'

        print('cleaning up index before benchmarking... index:', index)
        res = es.delete_index(index)
        print(res)

        df_box = list()
        for i in range(n):
            print('try n:', i+1, '/', n)
            df = self.run_onetime(n_workers, n_events, index)
            df_box.append(df)
        return df_box

    def run_n_time_period(self, n_events, t_period, t_total, n, lst_doc, option_increase=False, option_increase_specific=False, idx_specfic=0, lst_doc_basic=[], option_pairs=False):

        #delete
        indexes = list()
        for i in range(n): 
            for j in range(int(t_total/t_period)):
                index = 'trm'+str(int(i))+'-'+str(int(j))
                # res = es.delete_index(index)
                # print(res)
                # res = es.es.indices.create(index=index)
                # print(res)
                indexes.append(index)

        n_workers = 12*2#8*2
        with ThreadPoolExecutor(max_workers=n_workers) as executor:
            futures = {executor.submit(es.delete_index, index): index for index in indexes}
            for future_each in as_completed(futures):
                arg_a = futures[future_each] #why url returned?
                try:
                    data = future_each.result()
                    print(data)
                except Exception as e:
                    print('waiting...', e)
                    
        with ThreadPoolExecutor(max_workers=n_workers) as executor:
            futures = {executor.submit(es.es.indices.create, index): index for index in indexes}
            for future_each in as_completed(futures):
                arg_a = futures[future_each] #why url returned?
                try:
                    data = future_each.result()
                    print(data)
                except Exception as e:
                    print('waiting...', e)

        df_box = list()
        pairs = list()
        n_pairs = int(math.sqrt(n))
        for pair in list(np.ndindex(n_pairs, n_pairs)):
            pairs.append((pair[1],pair[0]))
        print(pairs)
        #idx_ids = 0
        idx_plc = 1
        idx_opc = 2

        #dummy test for pre-mapping
        for i in range(n): 
            df_box_oneshot = list()
            threads = list()
            if option_pairs:
                coef = 5
                n_plc_loop = pairs[i][0]
                n_opc_loop = pairs[i][1]
                lst_doc_now = coef*n_plc_loop*[lst_doc_basic[idx_plc]] + coef*n_opc_loop*[lst_doc_basic[idx_opc]] + lst_doc
                n_events_now = len(lst_doc_now)
            elif option_increase_specific:
                lst_doc_now = pow(2,i)*[lst_doc_basic[idx_specfic]] + lst_doc
                #lst_doc_now = 2*i*N_SET[idx_specfic]*[lst_doc_basic[idx_specfic]] + lst_doc

                n_events_now = len(lst_doc_now)
            elif option_increase:
                lst_doc_now = (i+1)*lst_doc
                n_events_now = len(lst_doc_now)
            else:
                n_events_now = n_events
                lst_doc_now = lst_doc
            #for j in range(0,1): #do one time is enough
            for j in range(int(t_total/t_period)):
                print('try n:', i+1, '/', n)
                index = 'trm'+str(int(i))+'-'+str(int(j))
                thread = ThreadWithReturn(target=self.run_onetime, args=(n_events_now, n_events_now, index, lst_doc_now, True))
                thread.start()
                t_thread_start = time.time()
                threads.append(thread)
                #print('wait ', t_period, 'sec...')
                #t_offset = time.time()-t_thread_start
                #time.sleep(t_period+t_offset)
            for thread in threads:
                df_box_oneshot.append(thread.join())
#         print('========================')
#         print('dummy mapping finished...')
#         print('========================')
        #input('ok?')

        print('wait for stabilizing...')
        time.sleep(3)

        
        for i in range(n): 
            df_box_oneshot = list()
            threads = list()

            if option_pairs:
                coef = 5
                n_plc_loop = pairs[i][0]
                n_opc_loop = pairs[i][1]
                lst_doc_now = coef*n_plc_loop*[lst_doc_basic[idx_plc]] + coef*n_opc_loop*[lst_doc_basic[idx_opc]] + lst_doc
                n_events_now = len(lst_doc_now)

            elif option_increase_specific:
                lst_doc_now = pow(2,i)*[lst_doc_basic[idx_specfic]] + lst_doc
                #lst_doc_now = 2*i*N_SET[idx_specfic]*[lst_doc_basic[idx_specfic]] + lst_doc
                n_events_now = len(lst_doc_now)
                print('========== i:', i)
                print('lst_doc_now:')
                print(lst_doc_now)

            elif option_increase:
                lst_doc_now = (i+1)*lst_doc
                n_events_now = len(lst_doc_now)
            else:
                n_events_now = n_events
                lst_doc_now = lst_doc
                
            for j in range(int(t_total/t_period)):
                print('try n:', i+1, '/', n)
                index = 'trm'+str(int(i))+'-'+str(int(j))
                thread = ThreadWithReturn(target=self.run_onetime, args=(n_events_now, n_events_now, index, lst_doc_now))
                thread.start()
                t_thread_start = time.time()
                threads.append(thread)
                print('wait ', t_period, 'sec...')
                t_offset = time.time()-t_thread_start
                time.sleep(t_period+t_offset)
        
            for thread in threads:
                df_box_oneshot.append(thread.join())
                
            #df_box_onetime to df
            #df = pd.DataFrame(columns = ['t1', 't21', 't22', 't23', 't32', 't34', 'rate_count', 'rawpacket_id'], dtype='float64')
            df = pd.DataFrame(columns = ['t1', 't21', 't23', 't32', 't34', 'tn1', 'tn2', 'tn3', 'rate_count', 'rawpacket_id'], dtype='float64')
            for df_oneshot in df_box_oneshot:
                df = pd.concat([df, df_oneshot])

            print(df.to_string())
            df.reset_index(drop=True, inplace=True)
            df_box.append(df)

        print('contents of the df_box // len of df_box:', len(df_box))
        for df in df_box:
            print('length of df:', len(df))
            print(df.to_string())

        return df_box


class Graph(object):
    def __init__(self):
        pass

    @timeit
    def draw_heatmap(self, data, n_row, n_col, title):
        z_mean = np.array(data).reshape(-1, n_row)
        #z_max = np.array(lst_max).reshape(-1, n_row)    
        a = np.linspace(0, n_row, n_row+1)
        b = np.linspace(0, n_col, n_col+1)
        fig, ax = plt.subplots()
        im = ax.pcolormesh(a, b, z_mean, vmin=0, vmax=T_PERIOD*2, cmap='RdBu_r')#, shading='gouraud')
        #im = ax.pcolormesh(a, b, z_mean, vmin=0, vmax=T_PERIOD*2, cmap='RdBu_r')#RdBu #seismic #jet #RdBu_r
        fig.colorbar(im)#,cmap='RdBu')#, vmin=-1, vmax=1)
        ax.axis('tight')
        fig.savefig(title+".png")
        #plt.show()
        # print('n_row, n_col:', n_row, n_col)
    
    @timeit
    def draw_hist(self, data, xmin, xmax, title, by=''):
        if FLAG_GRAPH == False: return

        fig, ax = plt.subplots()
        # pos = list(range(len(data)))
        # p = plt.boxplot(data, positions=pos)

        if by != '':
            label=data[by].unique()
            print('label:', label)
            data.groupby(by).hist(ax=ax, alpha=0.75, histtype='bar')
            ax.legend()
            plt.legend(labels=label)
        else:
            ax.hist(data, 50, facecolor='g', alpha=0.75)

        ax.grid()
        #fig.savefig("hist_"+title+str(int(time.time()))+".png")
        #plt.xticks(list(range(len(header))),header)
        ax.set_xlim([xmin, xmax])
        # ax.set_ylim([ymin, ymax])
        ax.set(xlabel='x-axis label', ylabel='y-axis label', title=title)
        fig.tight_layout()
        #plt.show(block=False)
        plt.show(block=FLAG_SHOW)
        fig.savefig(title+".png")
        
    @timeit
    def draw_boxplot(self, data, header, ymin, ymax, title):
        if FLAG_GRAPH == False: return

        fig, ax = plt.subplots()
        pos = list(range(len(data)))
        p = plt.boxplot(data, positions=pos)
        ax.grid()
        plt.xticks(list(range(len(header))),header)
        ax.set_ylim([ymin, ymax])
        ax.set(xlabel='x-axis label', ylabel='y-axis label', title=title)
        fig.tight_layout()
        #fig.savefig("boxplot_"+title+str(int(time.time()))+".png")
        fig.savefig(title+".png")
        #plt.show(block=False)
        plt.show(block=FLAG_SHOW)
        
    @timeit
    def draw_coloful_bar5(self, list_pairs, title, ymin, ymax, limit_pass_fail, limit_warning):
        if FLAG_GRAPH == False: return

        fig, ax = plt.subplots()
        # for pair in list_pairs:
        #     #ax.bar(pair[0], pair[1], width=0.01)
        #     #plt.bar(pair[0], pair[1])
        #     ax.set_ylim([ymin, ymax])
        #     print('info:', len(pair[0]), len(pair[1]))
        #ind = list_pairs[0][0]
        ind = list(range(len(list_pairs[0][0])))
        width = 0.5

        # list_pairs.append([df['t1'], df['t_internal_cps']])
        # list_pairs.append([df['t1'], df['t_logstash_cps_input']])
        # list_pairs.append([df['t1'], df['t_logstash_cps_filter']])
        # list_pairs.append([df['t1'], df['t_external']])
        # list_pairs.append([df['t1'], df['t_logstash_center_input']])
        # list_pairs.append([df['t1'], df['t_internal_center']])
        # list_pairs.append([df['t1'], df['t_elastic']])
        
        p1 = plt.bar(ind, list_pairs[0][1], width=width, color='r')
        p2 = plt.bar(ind, list_pairs[1][1], width=width, bottom=list_pairs[0][1], color='b')
        p3 = plt.bar(ind, list_pairs[2][1], width=width, bottom=list_pairs[1][1]+list_pairs[0][1], color='g')
        p4 = plt.bar(ind, list_pairs[3][1], width=width, bottom=list_pairs[2][1]+list_pairs[1][1]+list_pairs[0][1], color='c')
        p5 = plt.bar(ind, list_pairs[4][1], width=width, bottom=list_pairs[3][1]+list_pairs[2][1]+list_pairs[1][1]+list_pairs[0][1], color='green')
        p6 = plt.bar(ind, list_pairs[5][1], width=width, bottom=list_pairs[4][1]+list_pairs[3][1]+list_pairs[2][1]+list_pairs[1][1]+list_pairs[0][1], color='lime')
        p7 = plt.bar(ind, list_pairs[6][1], width=width, bottom=list_pairs[5][1]+list_pairs[4][1]+list_pairs[3][1]+list_pairs[2][1]+list_pairs[1][1]+list_pairs[0][1], color='orange')

        xlabel = 'ID of event(#)'
        ylabel = 'elapsed time(sec)'

        ax.set(xlabel=xlabel, ylabel=ylabel)#, title=title)
        # print('dbg:', list_pairs[0][0], list_pairs[-1][0])
        xmin, xmax = ind[0], ind[-1]
        ax.set_xlim([xmin, xmax])
        ax.set_ylim([ymin, ymax])
        ax.grid(linestyle='-', linewidth=1)

        #draw pass/fail line
        #plt.plot([limit_pass_fail, 0], [limit_pass_fail, xmax], 'r-')

        #red threshold line
        #plt.plot([0, xmax], [limit_pass_fail, limit_pass_fail], 'r-')
        
        #plt.plot([0, xmax], [limit_warning, limit_warning], 'y-')

        #fig.savefig("bar5_"+title+str(int(time.time()))+".png")
        #header = ['internal_network', 'logstash_preprocess', 'logstash_grok', 'external_network', 'elasticsearch']
        header = ['t_internal_cps','t_logstash_cps_input', 't_logstash_cps_filter', 't_external', 't_logstash_center_input', 't_internal_center', 't_elastic']
        #plt.legend((p1[0], p2[0], p3[0], p4[0], p5[0]), (header[0], header[1], header[2], header[3], header[4]), fontsize=8, ncol=5, framealpha=0, fancybox=True)
        plt.legend((p1[0], p2[0], p3[0], p4[0], p5[0], p6[0], p7[0]), (header[0], header[1], header[2], header[3], header[4], header[5], header[6]), fontsize=8, ncol=3)
        #plt.show(block=False) 
        fig.tight_layout()
        plt.show(block=FLAG_SHOW)
        fig.savefig(title+".png", dpi=fig.dpi*5)
       
        
    @timeit
    def draw_multiple_groups_bar(self, list_pairs, title, ymin, ymax, figsize=(8,6)):
        if FLAG_GRAPH == False: return
        
        fig, ax = plt.subplots(figsize=figsize)
        for pair in list_pairs:
            ax.bar(pair[0], pair[1], width=0.01)
            #plt.bar(pair[0], pair[1])
            ax.set_ylim([ymin, ymax])

            print('info:', len(pair[0]), len(pair[1]))
        xlabel = 'time axis(sec)'
        ylabel = 'event per sec.'#'% for cpu, mem, disk, celcius degree for temp.'
        ax.set(xlabel=xlabel, ylabel=ylabel)#, title=title)
        ax.grid()
        fig.tight_layout()
        #fig.savefig("latency_stack"+title+str(int(time.time()))+".png")
        fig.savefig(title+".png")
        #plt.show(block=False)
        plt.show(block=FLAG_SHOW)

    #to delete
    @timeit
    def draw_multiple_groups_normal_and_bar(self, list_pairs1, title1, ymin1, ymax1, list_pairs2, title2, ymin2, ymax2):
        if FLAG_GRAPH == False: return

        #normal / upper
        plt.figure()
        fig, ax = plt.subplots(211)
        for pair in list_pairs1:
            ax.plot(pair[0], pair[1], style, markersize=4)
            print('info:', len(pair[0]), len(pair[1]))

        ax.set(xlabel=xlabel, ylabel=ylabel)#, title=title)
        ax.grid()
        plt.legend(legend_header, fontsize=8, ncol=3)
        fig.tight_layout()
        if title[0] == 's':
            fig.savefig(title+".png", dpi=fig.dpi*5)
        else:
            fig.savefig(title+".png")
        plt.show(block=FLAG_SHOW)
        
        #bar / lower
        fig, ax = plt.subplots()
        for pair in list_pairs2:
            ax.bar(pair[0], pair[1], width=0.01)
            ax.set_ylim([ymin1, ymax1])

            print('info:', len(pair[0]), len(pair[1]))
        xlabel = 'time axis(sec)'
        ylabel = 'event per sec.'#'% for cpu, mem, disk, celcius degree for temp.'
        ax.grid()
        fig.tight_layout()
        fig.savefig(title2+".png")
        plt.show(block=FLAG_SHOW)


        
    @timeit
    def draw_multiple_groups(self, list_pairs, title, style='.', legend_header='', xlabel='time axis(sec)', ylabel='y-value', figsize=(8,6)):
        if FLAG_GRAPH == False: return

        print('[draw_multiple_groups]', 'title:', title)
        fig, ax = plt.subplots(figsize=figsize)
        for pair in list_pairs:
            ax.plot(pair[0], pair[1], style, markersize=4)
            print('info:', len(pair[0]), len(pair[1]))

        #xlabel = 'time axis(sec)'
        #ylabel = 'y-value'
        ax.set(xlabel=xlabel, ylabel=ylabel)#, title=title)
        ax.grid()
        plt.legend(legend_header, fontsize=8, ncol=3)
        fig.tight_layout()
        #fig.savefig("test_multi"+str(int(time.time()))+".png")
        if title[0] == 's':
            fig.savefig(title+".png", dpi=fig.dpi*5)
        else:
            fig.savefig(title+".png")
        #plt.show(block=False)
        plt.show(block=FLAG_SHOW)
        
        
        #plt.show(block=False)
        #plt.gcf().clear()
        #plt.clf()
        #plt.cla()
        
#print('n_loss:', es.n_loss, 'loss rate:', round(es.n_loss/n_iter,2))
#TODO: n_loss += n_loss_http (n_loss == n_lose_es)
#df.index = df['t1']
#del df['t1']


benchmark = Benchmark()
tool = Tool()
filename = 'test.sav'

#enable on-line
if 1:
    #1st way : pool
    #df_box = benchmark.run_n_time(n_workers=N_WORKERS, n_events=N_EVENTS, n=N_TRIALS)
    
    #2nd way : t_period
    lst_doc = benchmark.generate_lst_doc(N_IDS, N_PLC, N_OPC)
    lst_doc_basic = benchmark.generate_lst_doc(1, 1, 1)
    #df_box = benchmark.run_n_time_period(N_EVENTS, t_period=T_PERIOD, t_total=T_TOTAL, n=N_TRIALS, lst_doc=lst_doc, option_increase=False)
    
    #3rd way : t_period increase specific
    df_box = benchmark.run_n_time_period(N_EVENTS, t_period=T_PERIOD, t_total=T_TOTAL, n=N_TRIALS, lst_doc=lst_doc, option_increase=False, option_increase_specific=True, idx_specfic=IDX_SPECIFIC, lst_doc_basic=lst_doc_basic)

    #histogram test
    #df_box = benchmark.run_n_time_period(N_EVENTS, t_period=T_PERIOD, t_total=T_TOTAL, n=N_TRIALS, lst_doc=lst_doc, option_increase=False, option_increase_specific=False, idx_specfic=0, lst_doc_basic=lst_doc_basic)
    
    #heatmap grid
    #df_box = benchmark.run_n_time_period(N_EVENTS, t_period=T_PERIOD, t_total=T_TOTAL, n=N_TRIALS, lst_doc=lst_doc, option_increase=False, option_increase_specific=True, idx_specfic=0, lst_doc_basic=lst_doc_basic, option_pairs=True)
    
    tool.save(df_box, filename)
    #exit(1)

#utilze off-line data
else:
    df_box = tool.load(filename)


#heatmap
import numpy as np
graph = Graph()

if False:
    lst_mean = list()
    lst_max = list()
    for df in df_box:
        lst_mean.append(df['t_total'].mean())
        lst_max.append(df['t_total'].max())
        
    n_row = int(math.sqrt(N_TRIALS))
    n_col = n_row
    
    title = "heatmap0"
    graph.draw_heatmap(lst_mean, n_row, n_col, title)
    
    title = "heatmap1"
    graph.draw_heatmap(lst_max, n_row, n_col, title)
    
#get syslog    
res_box = list()
for df in df_box:
    res_each_trial = list()
    #dbg
#     print('len:',len(df_box))
#     print('df:', df_box[1].to_string())
#     print(df.to_string())
    time_start = df['t1'].iloc[0]
    time_end = df['t34'].iloc[-1]
    time_start_str = datetime.fromtimestamp(time_start).strftime('%Y-%m-%dT%H:%M:%S.%f')
    time_end_str = datetime.fromtimestamp(time_end).strftime('%Y-%m-%dT%H:%M:%S.%f')
    print('time_start:', time_start, 'time_end:', time_end)
    print('time_start_str:', time_start_str, 'time_end_str:', time_end_str)
    json_match = {
        "range" : {
            "timestamp" : {
                "gte": time_start_str,
                "lte": time_end_str
            }
        }
    }
    size = 10000
    res = es.search(index_time, json_match, size)
    try:
        res_each_trial.append(res)
        print('len(res):', len(res))
        pass
    except Exception as e:
        print('no result', 'error:', e)
    res_box.append(res_each_trial)
    #print(res_box)

       
report_index = list()
report_line = list()
#box = ['t_total', 't_internal', 't_logstash', 't_grok', 't_external', 't_elastic']
box = ['t_total', 't_internal_cps','t_logstash_cps_input','t_logstash_cps_filter','t_external', 't_logstash_center_input','t_internal_center','t_elastic']

for idx in box:
    report_index.append([idx+'/avg', '/min', '/max'])
    report_line.append(get_summary(df_box[0][idx]))

for (a,b) in zip(report_index, report_line):
    print(a)
    print(b)
   
#list_idx_sys = ['cpu', 'disk', 'mem', 'sm_percent', 'n_pid', 'irq', 'softirq', 'timestamp']#'timestamp should be last'
#list_idx_sys = ['cpu', 'disk', 'mem', 'sm_percent', 'irq', 'timestamp']#'timestamp should be last'
list_idx_sys = ['cpu', 'disk', 'mem', 'cpu_temp_current', 'timestamp']#'timestamp should be last'

#temps: {'coretemp': [shwtemp(label='Physical id 0', current=38.0, high=74.0, critical=94.0), shwtemp(label='Core 8', current=33.0, high=74.0, critical=94.0), shwtemp(label='Core 9', current=32.0, high=74.0, critical=94.0), shwtemp(label='Core 10', current=36.0, high=74.0, critical=94.0), shwtemp(label='Core 11', current=33.0, high=74.0, critical=94.0), shwtemp(label='Core 12', current=34.0, high=74.0, critical=94.0), shwtemp(label='Core 13', current=32.0, high=74.0, critical=94.0), shwtemp(label='Core 0', current=33.0, high=74.0, critical=94.0), shwtemp(label='Core 1', current=34.0, high=74.0, critical=94.0), shwtemp(label='Core 2', current=34.0, high=74.0, critical=94.0), shwtemp(label='Core 3', current=32.0, high=74.0, critical=94.0), shwtemp(label='Core 4', current=34.0, high=74.0, critical=94.0), shwtemp(label='Core 5', current=34.0, high=74.0, critical=94.0)]}

df_box_sys = list()
for res_each_trial in res_box:
    #print('res_each_trial:', res_each_trial)
    dict_sys = dict()
    for idx in list_idx_sys: #cpu, mem, ...
        dict_sys[idx] = list()
        for res in res_each_trial[0]:#1st row, 2nd row, ...
            #print(res)
            #input('go?')
            dict_sys[idx].append(res['_source'][idx])
            
    dict_sys['timestamp'] = [(datetime.strptime(x, '%Y-%m-%dT%H:%M:%S.%f') - datetime(1970, 1, 1)).total_seconds() for x in dict_sys['timestamp']]
    df_sys = pd.DataFrame(dict_sys, columns = list_idx_sys, dtype='float64')
    df_sys = df_sys.sort_values(['timestamp'], ascending=[True])
    df_box_sys.append(df_sys)
    #print('len of df_sys:', len(df_sys))

#job = list()
for df_sys, n in zip(df_box_sys, range(1000)):
    list_pairs = list()
    for idx in list_idx_sys[0:-1]:
        list_pairs.append([df_sys['timestamp'], df_sys[idx]])
        print('len of df_sys[idx]:', len(df_sys[idx]))
    #print(list_idx_sys)
    graph.draw_multiple_groups(list_pairs, 'syslog'+str(n), style='-', legend_header=(list_idx_sys[0:-1]), figsize=(8,3))

#df = pd.DataFrame()
#print('len of df_box:', len(df_box))
for df, n in zip(df_box, range(100)):
    # print('raw-data-confirm======')
    # print(df['t1'][0])

    #task1
    #multiple lines graph
    list_pairs = list()
    list_pairs.append([df['t1'], df['tn1']])
    list_pairs.append([df['t1'], df['tn2']])
    list_pairs.append([df['t1'], df['tn3']])
    list_pairs.append([df['t1'], df['t21']])
    list_pairs.append([df['t1'], df['t23']])
    list_pairs.append([df['t1'], df['t32']])
    list_pairs.append([df['t1'], df['t34']])
    xlabel = 'depart time at benchmark thread 1'
    ylabel = 'passed time at each timestamp spots'
    graph.draw_multiple_groups(list_pairs, 'scatter'+str(n), legend_header = ['t2', 't3', 't4', 't5', 't6', 't7', 't8'], xlabel=xlabel, ylabel=ylabel)
    #p1 = multiprocessing.Process(target=graph.draw_multiple_groups, args=(list_pairs, 'all',))

    #task2
    #single line graph
    #list_pairs = list()
    #list_pairs.append([df['t1'], df['t_internal']])
    #graph.draw_multiple_groups_bar(list_pairs, 't_internal', 0.0, 1.0)
    #p2 = multiprocessing.Process(target=graph.draw_multiple_groups_bar, args=(list_pairs, 't_internal', 0.0, 1.0,))
    
    #task3
    #list_pairs = list()
    #list_pairs.append([df['t1'], df['t_logstash']])
    #graph.draw_multiple_groups_bar(list_pairs, 't_logstash', 0.0, 1.0)
    #p3 = multiprocessing.Process(target=graph.draw_multiple_groups_bar, args=(list_pairs, 't_logstash', 0.0, 1.0,))

    # print('multiprocessing starts...')
    # p1.start()
    # p2.start()
    # p3.start()
    # print('waiting multiprocessing ends...')
    # p1.join()
    # p2.join()
    # p3.join()
    
    
    #task4
    # list_pairs = list()
    # list_pairs.append([df['t1'], df['t_grok']])
    #graph.draw_multiple_groups_bar(list_pairs, 't_grok', 0.0, 1.0)
    #p = multiprocessing.Process(target=, args=(,))
    #task5
    # list_pairs = list()
    # list_pairs.append([df['t1'], df['t_external']])
    #graph.draw_multiple_groups_bar(list_pairs, 't_external', 0.0, 1.0)
    #p = multiprocessing.Process(target=, args=(,))
    
    #task6
    # list_pairs = list()
    # list_pairs.append([df['t1'], df['t_elastic']])
    #graph.draw_multiple_groups_bar(list_pairs, 't_elastic', 0.0, 1.0)
    #p = multiprocessing.Process(target=, args=(,))

    #task7
    #colorful bar5
    list_pairs = list()
    # list_pairs.append([df['t1'], df['t_internal']])
    # list_pairs.append([df['t1'], df['t_logstash']])
    # list_pairs.append([df['t1'], df['t_grok']])
    # list_pairs.append([df['t1'], df['t_external']])
    # list_pairs.append([df['t1'], df['t_elastic']])
    # list_pairs.append([df['t1'], df['t21']])
    # list_pairs.append([df['t1'], df['t22']])
    # list_pairs.append([df['t1'], df['t23']])
    # list_pairs.append([df['t1'], df['t32']])
    # list_pairs.append([df['t1'], df['t34']])
    list_pairs.append([df['t1'], df['t_internal_cps']])
    list_pairs.append([df['t1'], df['t_logstash_cps_input']])
    list_pairs.append([df['t1'], df['t_logstash_cps_filter']])
    list_pairs.append([df['t1'], df['t_external']])
    list_pairs.append([df['t1'], df['t_logstash_center_input']])
    list_pairs.append([df['t1'], df['t_internal_center']])
    list_pairs.append([df['t1'], df['t_elastic']])
    limit_pass_fail = T_PERIOD
    limit_warning = 0#LATENCY_Y_WARNING
    ymax = LATENCY_Y_LIM
    graph.draw_coloful_bar5(list_pairs, 'latency'+str(n), 0.0, ymax, limit_pass_fail, limit_warning)
    #p = multiprocessing.Process(target=, args=(,))

    #task 8
    #todo:hist, bar5 graph ylim should be same in all df in df_box
    xmin = 0; xmax = HIST_X_LIM
    title = 'hist'+str(n)#_on_t_total'
    graph.draw_hist(df['t_total'], xmin, xmax, title)
    title = 'hist_group'+str(n)#_on_t_total'
    print(df)
    print(df[['t_total', 'rawpacket_id']])
    graph.draw_hist(df[['t_total', 'rawpacket_id']], xmin, xmax, title, by='rawpacket_id')
    #p = multiprocessing.Process(target=, args=(,))

    #task 9
    #rate
    list_pairs = list()
    list_pairs.append([df['t1'], df['rate_count']])
    #graph.draw_multiple_groups(list_pairs, 'rate_count', 'bo')
    title = 'rate'+str(n)
    graph.draw_multiple_groups_bar(list_pairs, title, 0, max(df['rate_count'])*1.1, figsize=(8,3))
    #p = multiprocessing.Process(target=, args=(,))


#special plot for rate + syslog
# for df, n in zip(df_box, range(100)):
#     list_pairs = list()
#     list_pairs.append([df['t1'], df['rate_count']])
#     #graph.draw_multiple_groups(list_pairs, 'rate_count', 'bo')
#     title = 'rate'+str(n)
#     graph.draw_multiple_groups_bar(list_pairs, title, 0, max(df['rate_count'])*1.1)
    
#boxplots
if True:
    for df_idx in box:
        data_boxplot = [x[df_idx] for x in df_box]
        header_boxplot = ['trial #'+str(x) for x in list(range(len(df_box)))]
        ymin = 0; ymax = BOXPLOT_Y_LIM
        title = 'boxplot_'+df_idx
        graph.draw_boxplot(data_boxplot, header_boxplot, ymin, ymax, title)
        print('[boxplpot]df_idx:', df_idx)

        
#from xls_class.py
import xlsxwriter  
import collections
import pandas as pd

class XlsWrapper(object):
    def __init__(self, filename):
        self.filename = filename
        self.workbook = xlsxwriter.Workbook(self.filename)
        self.dict_ws = dict()

    def add_worksheet(self, ws_name):
        ws = self.workbook.add_worksheet(ws_name)
        self.dict_ws.update({ws_name: ws}) 

    def widen_cols(self, target_cols, size, worksheet):
        worksheet.set_column(target_cols, size)#target_cols:A:A

    # def write_text(self, colrow, text, style='', worksheet):
    #     if style == '':
    #         # Write some simple text.  
    #         worksheet.write(colrow, text)#colrow:'A1', text:'blah'
    #     else:
    #         # Text with formatting.  
    #         worksheet.write(colrow, text, style)

    def write(self, row, col, text, worksheet):
        worksheet.write(row, col, text)

    def write_num_by_pos(self, row, col, val, worksheet):
        worksheet.write(row, col, vol)

    def insert_img(self, row, col, filename, worksheet):
        worksheet.insert_image(row, col, filename)

    def close(self):
        self.workbook.close()
        
    def insert_cell_dict(self, row_cell, col_cell, dict_data, worksheet):
        row = 24*row_cell
        col = 10*col_cell
        sorted_dict_data = collections.OrderedDict(sorted(dict_data.items()))
        r = row
        c = col
        for k, v in sorted_dict_data.items():
            self.write(r, c, k, worksheet)
            self.write(r, c+3, v, worksheet)
            r += 1
            
    def insert_cell_img(self, row_cell, col_cell, filename_img, worksheet):
        row = 24*row_cell
        col = 10*col_cell
        self.insert_img(row, col, filename_img, worksheet)

    def make_page(self, ws, lst_filename, n_col):
        list_ji = list()
        for j in range(int(len(lst_filename)/n_col+1)):
            for i in range(n_col):
                list_ji.append([j,i])
        for pair, filename in zip(list_ji, lst_filename):
            self.insert_cell_img(pair[0], pair[1], filename, ws)
            print(pair[0], pair[1], filename)

    def df_to_lsts(self, df):
        box = list()
        #print('[from]', df)
        for b,c in zip(df.index.tolist(), df.values.tolist()):
            if type(c) == list:
                box.append([b]+c)
            else:
                box.append([b]+[c])
                
        box.insert(0, df.columns.tolist())
        #print('[to]', box)
        return box

    def lsts_to_table(self, ws, row, col, lsts, style='', title='', ofst_row=0):
        #make all elements to string for unified alignment
        new_lsts = list()
        for lst in lsts:
            new_lsts.append([str(x) for x in lst])
            #new_lsts.append([str(x) for x in [round(y,3) for y in lst if type(y)!=str]])
        lsts = new_lsts
        row = row*24 + ofst_row
        col = col*10
        
        if title != '':
            format_bold = self.workbook.add_format({'bold': True})
            # format_bold.set_font_size(30)
            ws.write(row, col, title, format_bold)
            row = row + 1

        #lsts = self.df_to_nestedlists(df)
        n_width = len(lsts[0])
        n_height = len(lsts[1:])
        #draw table and values
        header = ['']
        for col_name in lsts[0]:
            header.append({'header': col_name})
        ws.add_table(row, col, row+n_height, col+n_width, {'data': lsts[1:], 'columns':header, 'style':style})

    def add_paper_title(self, row, col, title):
        format_bold = self.workbook.add_format({'bold': True})
        format_bold.set_font_size(25)
        ws.write(row, col, title, format_bold)
        
def generate_list_filename(topic, n):
    buf = list()
    for i in range(n):
        buf.append(topic+str(i)+'.png')
    return buf

xls = XlsWrapper('report_'+str(int(time.time()))+'.xlsx')
xls.add_worksheet('summary')
xls.add_worksheet('boxplot')
xls.add_worksheet('latency')
xls.add_worksheet('scatter')
xls.add_worksheet('syslog')
xls.add_worksheet('hist')
xls.add_worksheet('hist_group')
xls.add_worksheet('rate')
xls.add_worksheet('heatmap')

#tmp for demo
ips_name = 'WINS-SNIPER'
raw_wins = b'<36>[SNIPER-0001] [Attack_Name=(0400)SMB Service connect(tcp-445)]\
, [Time=2018/07/19 11:39:22], [Hacker=0.0.0.0], [Victim=0.0.0.1], [\
Protocol=tcp/000], [Risk=Medium], [Handling=Alarm], [Information=], [SrcPort=00000], [HackType=00004]'
n_workers = 20
n_events = 1000
test_start = '2018-08-13T13:24:42'
test_end = '2018-08-13T13:25:12'
plugin = 'udp-plugin'
avg_req_rate = 19.8323
max_total_latency = 1.212
min_total_latency = 0.452
avg_total_latency = 0.763
loss = 0
feasibility_score = 99.0
pass_fail = 'PASS'

#0. summary worksheet
ws = xls.dict_ws['summary']

paper_title = 'Elastic Server Benchmark Test'
xls.add_paper_title(1, 0, paper_title)

desc_main = {}
desc = []
desc.append([''])
desc.append(['Elastic Server IP', str(IP)])
desc.append(['Elastic Server IP', str(PORT)])
desc.append(['Logstash Server IP', str(UDP_IP)])
desc.append(['Logstash Server IP', str(UDP_PORT)])
desc.append(['IPS_MACHINE_NAME,', ips_name])
desc.append(['RAW_PACKET',str(raw_wins)])
desc.append(['n_workers',N_WORKERS])
desc.append(['n_events',N_EVENTS])
desc.append(['n_trials',N_TRIALS])
desc.append(['test_start',test_start])
desc.append(['test_end',test_end])
desc.append(['plugin',plugin])
xls.lsts_to_table(ws, 0, 0, desc, 'Table Style Light 1', 'Experiment Setup', ofst_row=3)
ws.set_column('A:B', 60)

#measured data
measured = list()
measured.append([''])
measured.append(['Elastic Server CPU', 'i7 2.7Ghz'])
measured.append(['Elastic Server MEM', '16GB'])
measured.append(['Elastic Server DISK Rate', 12.13])
measured.append(['Logstash Server CPU','i7 2.7Ghz'])
measured.append(['Logstash Server MEM','16GB'])
measured.append(['Logstash Server DISK Rate', 12.13])
measured.append(['avg_req_rate',avg_req_rate])
measured.append(['min latency',max_total_latency])
measured.append(['max latency',min_total_latency])
measured.append(['avg latency',avg_total_latency])
measured.append(['loss',loss])
measured.append(['feasibility_score',feasibility_score])
measured.append(['pass/fail',pass_fail])
#lsts = xls.df_to_lsts(measured)
xls.lsts_to_table(ws, 1, 0, measured, 'Table Style Light 2', 'Summary', ofst_row=0)
ws.set_column('A:B', 60)

#[df, df, ...] -> [df.describe(), df.describe(), ...]
#pd.DataFrame({'email':sf.index, 'list':sf.values})
def dfs_to_describe(lsts):
    rslt = list()
    for df in lsts:
        describe = df.describe()
        print('type of describe:', type(describe))
        lsts_describe = xls.df_to_lsts(describe)
        rslt.append(lsts_describe)
    print(rslt)
    return rslt

        
#1. boxplot worksheet
ws = xls.dict_ws['boxplot']
#lst = ['boxplot_t_total.png', 'boxplot_t_internal.png', 'boxplot_t_logstash.png', 'boxplot_t_grok.png', 'boxplot_t_external.png', 'boxplot_t_elastic.png']
lst = ['boxplot_t_total.png', 'boxplot_t_internal_cps.png', 'boxplot_t_logstash_cps_input.png', 'boxplot_t_logstash_cps_filter.png', 'boxplot_t_external.png', 'boxplot_t_logstash_center_input.png', 'boxplot_t_internal_center.png', 'boxplot_t_elastic.png']

xls.make_page(ws, lst, 1)

#dummy data
a = {'trial1':[1,2,3], 'trial2':[4,5,6], 'trial3':[2.3,3.2,1.1]}
df = pd.DataFrame(a)
dummy_desc = df.describe()
lsts = xls.df_to_lsts(dummy_desc)
for df_idx, i in zip(box, range(100)):#t_total, ...
    lsts = list()
    for df, n in zip(df_box, range(100)):
        if n == 0:
            df_connected = copy.deepcopy(df.loc[:, [df_idx]])
        else:
            df_connected = df_connected.join(df.loc[:, df_idx], rsuffix='_'+str(n))
        
    df_connected_describe = df_connected.describe()
    lsts = xls.df_to_lsts(df_connected_describe)
    xls.lsts_to_table(ws, i, 1, lsts, 'Table Style Light 3',str('Latency@'+df_idx))

    
#2. latency worksheet
ws = xls.dict_ws['latency']
lst = generate_list_filename('latency', len(df_box))
xls.make_page(ws, lst, 1)
df_idx = 't_total'
for df, n in zip(df_box, range(100)):
    df_connected = copy.deepcopy(df.loc[:, [df_idx]])
    df_connected_describe = df_connected.describe()
    lsts = xls.df_to_lsts(df_connected_describe)
    xls.lsts_to_table(ws, n, 1, lsts, 'Table Style Light 3',str('Latency@Trial#'+str(n+1)))

#2-b. latency worksheet scatter
ws = xls.dict_ws['scatter']
lst = generate_list_filename('scatter', len(df_box))
xls.make_page(ws, lst, 1)
df_idx = 't_total'
for df, n in zip(df_box, range(100)):
    df_connected = copy.deepcopy(df.loc[:, [df_idx]])
    df_connected_describe = df_connected.describe()
    lsts = xls.df_to_lsts(df_connected_describe)
    xls.lsts_to_table(ws, n, 1, lsts, 'Table Style Light 3',str('Latency@Trial#'+str(n+1)))


#3. hist
ws = xls.dict_ws['hist']
lst = generate_list_filename('hist', len(df_box))
xls.make_page(ws, lst, 1)
#xls.lsts_to_table(ws, 0, 1, lsts, 'Table Style Light 3','Trial1 Histogram Statistics.')
df_idx ='t_total'
for df, n in zip(df_box, range(100)):
    df_connected = copy.deepcopy(df.loc[:, [df_idx]])
    df_connected_describe = df_connected.describe()
    lsts = xls.df_to_lsts(df_connected_describe)
    xls.lsts_to_table(ws, n, 1, lsts, 'Table Style Light 3',str('Latency@Trial#'+str(n+1)))

#3. hist_group
ws = xls.dict_ws['hist_group']
lst = generate_list_filename('hist_group', len(df_box))
xls.make_page(ws, lst, 1)
#xls.lsts_to_table(ws, 0, 1, lsts, 'Table Style Light 3','Trial1 Histogram Statistics.')
df_idx ='t_total'
for df, n in zip(df_box, range(100)):
    df_connected = copy.deepcopy(df.loc[:, [df_idx]])
    df_connected_describe = df_connected.describe()
    lsts = xls.df_to_lsts(df_connected_describe)
    xls.lsts_to_table(ws, n, 1, lsts, 'Table Style Light 3',str('Latency@Trial#'+str(n+1)))

    
#4. rate
ws = xls.dict_ws['rate']
lst = generate_list_filename('rate', len(df_box))
xls.make_page(ws, lst, 1)
df_idx = 'rate_count'
for df, n in zip(df_box, range(100)):
    df_connected = copy.deepcopy(df.loc[:, [df_idx]])
    df_connected_describe = df_connected.describe()
    lsts = xls.df_to_lsts(df_connected_describe)
    xls.lsts_to_table(ws, n, 1, lsts, 'Table Style Light 3',str('Rate@Trial#'+str(n+1)))

#5. syslog
ws = xls.dict_ws['syslog']
lst = generate_list_filename('syslog', len(df_box))
xls.make_page(ws, lst, 1)
for df_sys, n in zip(df_box_sys, range(1000)):
    df_connected = copy.deepcopy(df_sys.loc[:, list_idx_sys[0:-1]])
    df_connected_describe = df_connected.describe()
    lsts = xls.df_to_lsts(df_connected_describe)
    xls.lsts_to_table(ws, n, 1, lsts, 'Table Style Light 3',str('Syslog@Trial#'+str(n+1)))


#heatmap
if False:
    ws = xls.dict_ws['heatmap']
    lst = generate_list_filename('heatmap', 2)
    xls.make_page(ws, lst, 1)


xls.workbook.close()

