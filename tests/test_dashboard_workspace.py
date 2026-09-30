import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from urllib.request import urlopen,Request
from urllib.error import HTTPError

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from dashboard_server import DashboardHandler,ThreadingHTTPServer
from dashboard_store import WorkspaceStore


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        folder=Path(self.temp.name)
        class Handler(DashboardHandler):
            state_file=folder/'state.sqlite3'
            imports_dir=folder/'imports'
            alerts_file=folder/'live.csv'
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.base=f'http://127.0.0.1:{self.server.server_port}'

    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.temp.cleanup()

    def request(self,path,body=None):
        request=Request(self.base+path,data=json.dumps(body).encode() if body is not None else None,
                        headers={'Content-Type':'application/json'})
        return json.load(urlopen(request))

    def test_evidence_and_source_isolation(self):
        main=self.request('/api/workspace?source=main')
        self.assertEqual(len(main['rows']),140)
        self.assertEqual(sum(r['context']=='suppressed' for r in main['rows']),60)
        packet=next(r for r in main['rows'] if r['event_id']=='PCAP-118')
        self.assertEqual(packet['audit']['policy_id'],'CHG-OT-2026-001')
        self.assertEqual(packet['evidence']['register_values'],[55])
        self.assertEqual(packet['triage']['disposition'],'Unreviewed')
        self.assertEqual(self.request('/api/workspace?source=live')['rows'],[])
        with self.assertRaises(HTTPError):
            self.request('/api/triage',{'source':'challenge','keys':[packet['key']]})
        with self.assertRaises(HTTPError):
            self.request('/api/workspace?source=../main')

    def test_triage_persistence_and_case_lifecycle(self):
        row=self.request('/api/workspace?source=main')['rows'][0]
        body={'source':'main','keys':[row['key']],'status':'Closed','owner':'Analyst A','disposition':'False positive','note':'Ticket and packet verified.'}
        with self.assertRaises(HTTPError):
            self.request('/api/triage',{**body,'note':''})
        self.request('/api/triage',body)
        updated=self.request('/api/workspace?source=main')['rows'][0]
        self.assertEqual(updated['triage']['owner'],'Analyst A')
        self.assertEqual(updated['triage']['status'],'Closed')
        self.assertEqual(len(self.request('/api/history?key='+row['key'])),1)
        recreated=WorkspaceStore(Path(self.temp.name)/'state.sqlite3')
        self.assertEqual(recreated.states('main')[row['key']]['disposition'],'False positive')
        created=self.request('/api/cases',{**body,'title':'Maintenance review'})
        self.request('/api/case-update',{'source':'main','id':created['id'],'status':'Closed','owner':'Analyst A','note':'Review completed.'})
        case=self.request('/api/workspace?source=main')['cases'][0]
        self.assertEqual(case['status'],'Closed')
        self.assertEqual(len(self.request('/api/history?key=case:'+str(created['id']))),2)

    def test_import_zero_values_no_lab_evidence(self):
        csv='event_id,timestamp,src_ip,dst_ip,risk_score,latency_ms\nPCAP-118,1790762460,10.50.1.20,10.50.2.10,0,0\n'
        imported=self.request('/api/import',{'name':'zero.csv','csv':csv})
        data=self.request('/api/workspace?source='+imported['source'])
        self.assertEqual(data['source']['kind'],'imported')
        self.assertEqual(data['rows'][0]['risk'],0)
        self.assertEqual(data['rows'][0]['latency_ms'],0)
        self.assertIsNone(data['rows'][0]['lab_reference'])
        self.assertIsNone(data['rows'][0]['evidence'])
        self.assertIsNone(data['rows'][0]['audit'])

    def test_cross_origin_and_artifact_allowlist(self):
        request=Request(self.base+'/api/import',data=b'{}',headers={'Origin':'http://other.example'})
        with self.assertRaises(HTTPError) as error: urlopen(request)
        self.assertEqual(error.exception.code,403)
        with self.assertRaises(HTTPError): self.request('/api/artifacts/.env')
        self.assertEqual(self.request('/api/artifacts/report.json')['captures']['main']['bounded']['metrics']['TP'],80)
        with self.assertRaises(HTTPError): self.request('/api/triage',[])


if __name__=='__main__': unittest.main()
