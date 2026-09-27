"""Offline Beta review probes; no target traffic, temporary SQLite state only."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from helpers import isolated_state
from synapse_mcp.core import workspace
from synapse_mcp.app.context import ContextCompiler, ContextQueryInput, ContextTrust, canonical_context_bytes

out = {}
trust = ContextTrust(execution_profile="observe", principal_id="reviewer", authority_session_id="review")

def submit(request, analyses=None, observations=None):
    envelope = {"schemaVersion":"1.1", "requestId":request,
                "producer":{"name":"review-fixture","version":"1"},
                "entities": {"analyses":analyses or [], "observations":observations or []}}
    return workspace.ingest_data("review", "a.example.test", "contribution.v1", "consumer_submission", "json", json.dumps(envelope), principal_id="reviewer")

def analysis(cls, url="https://a.example.test/search", reason="Initial hypothesis", confidence="medium", method="synapse-web-browser-input", inconclusive=False):
    return {"kind":"candidate", "subject":{"url":url,"method":"GET","parameter":"q","location":"query"},
            "candidateClass":cls,"knowledgeState":"inferred","confidence":confidence,"reason":reason,
            "inconclusive":inconclusive,"methodRef":{"id":method,"digest":"sha256:"+"a"*64}}

def context():
    return ContextCompiler(workspace._activated_repository("review"),payload_encoder=canonical_context_bytes).compile(
        ContextQueryInput(workspace_id="review",targets=["a.example.test"],max_tokens=100000),trust=trust).model_dump(by_alias=True)

with TemporaryDirectory() as tmp, isolated_state(Path(tmp), store_version="sqlite-v2"):
    workspace.create_workspace("review",hosts=["a.example.test"])
    first=submit("first",[analysis("xss",reason="Browser-specific signal",confidence="high")])
    second=submit("second",[analysis("sqli",reason="Server signal remains inconclusive",confidence="low",method="synapse-web-server-input",inconclusive=True)])
    out["multi_class"]={"same_canonical_id":first["canonicalRecordIds"]==second["canonicalRecordIds"],"stored":workspace._activated_repository("review").collection("a.example.test","observations"),"context":context()["candidates"]}
    submit("update",[analysis("xss",reason="Browser signal now inconclusive",confidence="low",inconclusive=True)])
    out["same_class_update"]=workspace._activated_repository("review").collection("a.example.test","observations")[0]
    candidate=out["same_class_update"]["candidateId"]
    workspace.record_candidate_validation("review","a.example.test",{"candidateId":candidate},"refuted",vuln_class="xss",notes="Saved matched control refutes the browser hypothesis")
    out["partial_refutation_context"]=context()["candidates"]

with TemporaryDirectory() as tmp, isolated_state(Path(tmp), store_version="sqlite-v2"):
    workspace.create_workspace("review",hosts=["a.example.test"])
    first=submit("route-a",[analysis("xss",url="https://a.example.test/a/b",reason="Nested route signal")])
    second=submit("route-b",[analysis("xss",url="https://a.example.test/a-b",reason="Hyphen route signal")])
    out["surface_collision"]={"same_canonical_id":first["canonicalRecordIds"]==second["canonicalRecordIds"],"stored":workspace._activated_repository("review").collection("a.example.test","observations")}

with TemporaryDirectory() as tmp, isolated_state(Path(tmp), store_version="sqlite-v2"):
    workspace.create_workspace("review",hosts=["a.example.test"])
    workspace.ingest_data("review","a.example.test","adapter_result","review-fixture","json",json.dumps({"entities":{"endpoints":[{"url":f"https://a.example.test/p-{i:03}","method":"GET"} for i in range(205)]}}))
    compiler=ContextCompiler(workspace._activated_repository("review"),payload_encoder=canonical_context_bytes)
    def page(cursor=None,budget=1500):
        return compiler.compile(ContextQueryInput(workspace_id="review",targets=["a.example.test"],entity_types=["endpoint"],max_tokens=budget,cursor=cursor),trust=trust)
    a=page(); b=page(a.continuation.next_cursor)
    c=page(a.continuation.next_cursor,100000); d=page(c.continuation.next_cursor,100000)
    out["paging"]={"default_first_count":len(a.confirmed_facts),"default_second_count":len(b.confirmed_facts),"same_items":a.confirmed_facts==b.confirmed_facts,"cursor_repeats":a.continuation.next_cursor==b.continuation.next_cursor,"omissions":[x.model_dump(by_alias=True) for x in b.omissions],"larger_budget_count":len(c.confirmed_facts),"larger_budget_tokens":c.budget.used,"final_page_count":len(d.confirmed_facts),"complete":not d.continuation.has_more}

print(json.dumps(out,indent=2))
