
import os
import pandas as pd
import threading
import requests
import builtwith
import whois
import argparse
import collections
from collector.Peeper import Peeper
from analyzer.get_chain import GetService
from Infra_analyzer.caLookup import CertResolver
from Infra_analyzer.dnsLookup import DNSResolver
from concurrent.futures import ThreadPoolExecutor
from Tools.adt.ATFilter import AdFilter, TrackerFilter


lock = threading.Lock()


class ToCSV:

    def __init__(self):
        self.df = pd.DataFrame(columns=["resource_url", "isThirdParty", "resource_type",
                                        "CA_url", "Issuer", "OCSP", "CDP", "NS", "isAd", "isTracker"])
        self.crtlook = CertResolver()
        self.dnslook = DNSResolver()
        self.ad = AdFilter()
        self.tr = TrackerFilter()

    def lookUp(self, value):
        ca_url, issuer, ocsp, crl = self.crtlook.get_CRL_OSCP(value["resource_url"])
        ns = self.dnslook.get_NS(value["resource_url"])
        # is_ad = self.ad.blocker.should_block(value["resource_url"])
        # is_tr = self.tr.blocker.should_block(value["resource_url"])
        lock.acquire()
        self.df.loc[self.df.shape[0]] = [value["resource_url"], value["isThirdParty"], value["resource_type"],
                                         ca_url, issuer, ocsp, str(crl), str(ns), False, False]
        lock.release()


def chainAna(results):
    chain = collections.defaultdict(str)
    for key, value in results.items():
        if value["parent"] == "0":
            continue
        if value["parent"] not in results or "r" + value["parent"] not in results:
            continue
        chain[value["resource_url"]] = results[value["parent"]]["resource_url"]

    chains = []
    for key, value in chain.items():
        li = [key]
        while value and value != "0" and value != key and value in chain and value[-1] != "/" and value not in li:
            li.append(value)
            value = chain[value]
            if len(li) > 20:
                break
            if len(li) >= 2:
                print(li)
                chains.append(li)
    return chains


def page_resource(path, dirname, sp):
    dumper = ToCSV()
    ana = GetService()
    results = ana.run(path)
    js_rank = []
    pool = ThreadPoolExecutor(max_workers=7)
    seen = set()
    for key, value in results.items():
        if not value["resource_url"] or value["resource_url"] in seen:
            continue
        seen.add(value["resource_url"])
        if value["resource_type"] == 1:
            js_rank.append((value["resource_url"], value["score"]))
        pool.submit(dumper.lookUp, value)
    pool.shutdown()
    js_rank.sort(key=lambda x: x[1], reverse=True)
    print("-----------------js排名情况------------------")
    for js, _ in js_rank:
        print(js)
    dumper.df.to_csv(sp + dirname + ".csv", index=False)

    print("-----------------引用链------------------")
    chains = chainAna(results)
    f = open(sp + "chain.txt", "w")
    for chain in chains:
        f.write(str(chain) + "\n")
    f.close()


def run(domain):
    url = "http://" + domain
    root = "/Users/mazeyu/rendering_stream/"
    me = Peeper()
    dirname, today = me.peeping(url)
    rdir = root + dirname
    filename = os.listdir(rdir)[0]

    path = os.path.join(rdir, filename)
    sp = "./result/" + dirname + today + "/"
    page_resource(path, dirname, sp)

    print("-----------------whois信息------------------")
    wh = whois.whois(domain)
    print(wh)
    f = open(sp + "whois", "w")
    f.write(str(wh))
    f.close()

    print("-----------------响应头------------------")
    header = {
        "headers": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
                   "Version/14.1.2 Safari/605.1.15"
    }
    req = requests.get(url, headers=header)
    for key, value in req.headers.items():
        print(key, value)
    f = open(sp + "header", "w")
    f.write(str(req.headers))
    f.close()

    print("-----------------组件使用情况------------------")
    components = builtwith.parse(url)
    for key, value in components.items():
        print(key, value)
    f = open(sp + "component", "w")
    f.write(str(components))
    f.close()

    # page_resource("/Users/mazeyu/rendering_stream/www.shandong-energy.com/log_www.shandong-energy.com_1649208675.692799.json", "www.shandong-energy.com")


if __name__ == "__main__":
    """
    api
    登录注释
    算分情况
    wapp
    linux
    easylist更新
    域名
    """
    # run("www.baidu.com")
    run("wanfangdata.com.cn")
    # run("csdn.net")
    # run("www.bilibili.com")
    # run("www.piaoliang.com")
