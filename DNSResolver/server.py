from flask import Flask, request, redirect
import json
from DNSResolver.DNSResolver import DNSResolver

app = Flask("DNSResolver")

dnsr = DNSResolver()

@app.route('/')
def hello_world():
    return 'Hello World!'


@app.route("/get-a-records")
def get_records():
    global dnsr
    domain = request.args.get("domain")
    trace = request.args.get("trace", default=False, type=bool)

    if domain is None:
        return "Error, domain is None"

    answer = {"domain": domain, "trace": trace}
    try:
        ip_info = dnsr.get_ip(domain, trace)
    except:
        return "Error, bad domain or internet connection problems"
    answer["domain"] = ip_info

    return json.dumps(answer)


if __name__ == '__main__':
    app.run()
