"""抓取 zeroxjf 推文"""
import json
import urllib.request

url = "https://cdn.syndication.twimg.com/tweet-result?id=2077216973256274272&lang=en"
try:
    r = urllib.request.urlopen(url)
    data = json.loads(r.read())
    print("== 推文内容 ==")
    print(data.get("text", "(无文字)"))
    print()
    print("== 时间 ==")
    print(data.get("created_at", "?"))
except Exception as e:
    print(f"错误: {e}")
    print("你的梯子可能不支持这个 API，请在浏览器直接看 x.com/0xjohnny/status/2077216973256274272")
