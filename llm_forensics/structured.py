"""Separate bounded policies for evidence JSON and generated reports."""
import json
import math

EVIDENCE_NODES = 200000
REPORT_NODES = 8000000
REPORT_BYTES = 128 * 1024 * 1024


def validate(value, max_nodes=EVIDENCE_NODES):
    # Iterator stack bounds traversal overhead by nesting, not array width.
    stack=[iter((value,))];nodes=0
    while stack:
        try:node=next(stack[-1])
        except StopIteration:
            stack.pop();continue
        nodes+=1
        if len(stack)>65 or nodes>max_nodes:
            raise ValueError(f'JSON structure limit exceeded (depth 64 / {max_nodes} nodes)')
        if isinstance(node,float) and not math.isfinite(node):
            raise ValueError('Non-finite JSON number is not supported')
        if isinstance(node,dict):stack.append(iter(node.values()))
        elif isinstance(node,list):stack.append(iter(node))
    return value


def loads(data, max_nodes=EVIDENCE_NODES):
    def object_pairs(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('Duplicate JSON object key; ambiguous evidence is not interpreted')
            result[key]=value
        return result
    def invalid_constant(value):
        raise ValueError('Non-finite JSON number is not supported: '+value)
    try:value=json.loads(data,object_pairs_hook=object_pairs,parse_constant=invalid_constant)
    except RecursionError as exc:raise ValueError('JSON nesting limit exceeded') from exc
    return validate(value,max_nodes)


def report_json(report):
    if len(report.get("findings",[]))>10000:raise ValueError("Generated report exceeds 10000 artifact limit")
    validate(report,REPORT_NODES)
    data=json.dumps(report,indent=2,ensure_ascii=True)
    if len(data.encode('utf-8'))>REPORT_BYTES:raise ValueError('Generated report exceeds 128 MiB supported report limit')
    return data
