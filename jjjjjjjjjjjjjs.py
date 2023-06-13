import sys
import os
import re
import requests
import concurrent.futures
from tqdm import tqdm
import string
import random
import pandas as pd
import subprocess
from collections import Counter
import mimetypes
import urllib.parse
from urllib.parse import urlparse

DEBUG=False
Verbose=False
class ErrorClass:
    usageTips="错误！！！使用方式：python3 jjjjjjjs.py  url|urlfile [[fuzz [noapi] [nobody|nofuzz]]|[api [nobody|nofuzz]]]\nurl|file:目标url\nfuzz:自动fuzz接口\napi:用户指定api根路径\nnoapi:排除输入的指定api\nnobody: 禁用输出响应body\nnofuzz: 仅获取有效api，无后续响应获取"

#移除敏感高危接口  delete remove drop update shutdown restart
#todo 这里需要修改为在api中判断而不是在url中，域名中有可能出现列表中的值
#todo 识别非webpack站点，仅输出js信息 输出匹配敏感信息?
dangerApiList=["del","delete","insert","logout","remove","drop","shutdown","stop","poweroff","restart","rewrite"]
commonApiList=["api","Api","system","sys","user"]#常见api根路径
# 完善黑名单功能
apiRootBlackList=["\\","#","$","@","*","+","-","|","!","%","^","~","[","]"]#api根黑名单，这里的值不可能出现在根API 起始值 中
apiBlackList=["\\","#","$","@"]#api黑名单，这里的值不可能出现在URL中
anchorUserInterface="#"#单独输出拼接#为根api的情况，用于手动浏览器访问，排序从短到长
fileExtBlackList=["exe","apk","mp4","mkv","mp3","flv","js","css","less","woff","vue","svg","png","jpg","swf","html"]#todo url文件扩展名黑名单 是否增加html
urlBlackList=[" "]#URL不可能出现空格
# juicyApiListKeyWords=["upload","download","config","conf","import","query","list","user","sys","system","adm","admin","customer"]#todo 用于在fuzz结束时，提示用户需要高度关注的api
juicyApiListKeyWords=["upload","download","config","conf","import","export","query","list","customer","register","reg","info","reset","password","pass","pwd","credential","actuator","refresh","druid","metrics","httptrace","swagger-ui","redis","user","sys","system","adm","admin","datasource","database"]#todo 用于在fuzz结束时，提示用户需要高度关注的api
#高危文件库
juicyFileExtList=["xls","xlsx","doc","docx","txt",]#获取敏感接口时会与juicyApiListKeyWords合并
#{"tag":"jwt","desc":"jwt","regex":r'7{10000}'},
# 增加content-type tag库
contentTypeList=[
    {"key":"text/html","tag":"html"},
    {"key":"application/json","tag":"json"},
    {"key":"text/plain","tag":"txt"},
    {"key":"text/xml","tag":"xml"},
    {"key":"image/gif","tag":"gif"},
    {"key":"image/jpeg","tag":"jpg"},
    {"key":"image/png","tag":"png"},
    {"key":"application/xhtml+xml","tag":"xhtml"},
    {"key":"application/xml","tag":"xml"},
    {"key":"application/atom+xml","tag":"atom+xml"},
    {"key":"application/octet-stream","tag":"bin"},
    {"key":"audio/x-wav","tag":"wav"},
    {"key":"audio/x-ms-wma","tag":"w文件"},
    {"key":"audio/mp3","tag":"mp3"},
    {"key":"video/x-ms-wmv","tag":"wmv"},
    {"key":"video/mpeg4","tag":"mp4"},
    {"key":"video/avi","tag":"avi"},
    {"key":"application/pdf","tag":"pdf"},
    {"key":"application/msword","tag":"msword"},
    {"key":"application/vnd.openxmlformats-officedocument.wordprocessingml.document","tag":"docx"},
    {"key":"application/vnd.ms-excel","tag":"excel"},
    {"key":"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet","tag":"xlsx"},
    {"key":"application/vnd.ms-powerpoint","tag":"ppt"},
    {"key":"application/vnd.openxmlformats-officedocument.presentationml.presentation","tag":"pptx"},
    {"key":"application/zip","tag":"zip"},
    {"key":"application/x-zip-compressed","tag":"zip"},
    {"key":"application/x-tar","tag":"tar"},
    {"key":"multipart/form-data","tag":"file"},
    # {"key":"html","tag":"html"},
]
#敏感信息指纹库
#todo 输出敏感信息匹配内容
sensitiveInfoRegex=[#todo 待完善
    #正则偷的hae和findsomething的正则
    #https://github.com/gh0stkey/HaE
    #https://github.com/momosecurity/FindSomething
    {"tag":"idcard","desc":"身份证","regex":r'[^0-9]((\d{8}(0\d|10|11|12)([0-2]\d|30|31)\d{3}$)|(\d{6}(18|19|20)\d{2}(0[1-9]|10|11|12)([0-2]\d|30|31)\d{3}(\d|X|x)))[^0-9]'},
    {"tag":"phone","desc":"手机号","regex":r'[^0-9A-Za-z](1(3([0-35-9]\d|4[1-8])|4[14-9]\d|5([\d]\d|7[1-79])|66\d|7[2-35-8]\d|8\d{2}|9[89]\d)\d{7})[^0-9A-Za-z]'},
    {"tag":"jwt","desc":"jwt","regex":r'ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}|ey[A-Za-z0-9_\/+-]{10,}\.[A-Za-z0-9._\/+-]{10,}'},
    {"tag":"accesskey","desc":"accesskey","regex":r'([A|a]ccess[K|k]ey[I|i][d|D]|[A|a]ccess[K|k]ey[S|s]ecret)'},
    {"tag":"password","desc":"password","regex":r'["\']?((p|P)assword|PASSWORD|(c|C)redential|CREDENTIAL)["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?|["\']?[\w_-]*?password[\w_-]*?["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?'},
    {"tag":"email","desc":"邮箱","regex":r'(([a-zA-Z0-9][_|\.])*[a-zA-Z0-9]+@([a-zA-Z0-9][-|_|\.])*[a-zA-Z0-9]+\.((?!js|css|jpg|jpeg|png|ico)[a-zA-Z]{2,}))'},
    {"tag":"internalIP","desc":"内网IP","regex":r'[^0-9]((127\.0\.0\.1)|(localhost)|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3}))'},
    {"tag":"miniopass","desc":"minio账号密码(minioadmin)","regex":r'minioadmin/minioadmin|=minioadmin|= minioadmin'},
    {"tag":"MAC Address","desc":"MAC地址","regex":r'(^([a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5})|[^a-zA-Z0-9]([a-fA-F0-9]{2}(:[a-fA-F0-9]{2}){5}))'},
    {"tag":"username","desc":"username","regex":r'["\']?((u|U)sername|USERNAME)["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?|["\']?[\w_-]*?username[\w_-]*?["\']?[^\S\r\n]*[=:][^\S\r\n]*["\']?[\w-]+["\']?'},
]

#todo 扩充完善指纹库
apiFingerprintWithTag=[
    #{"fingerprint":"fingerprint","tag":"tag"}
    #使用 in 逻辑 不是正则表达式
    {"fingerprint":"<html><body><h1>Whitelabel Error Page</h1>","tag":"springboot"},#springboot
    {"fingerprint":"<title>Swagger UI</title>","tag":"swagger-ui"},
    {"fingerprint":"<title>Swagger-Bootstrap-UI</title>","tag":"Swagger-Bootstrap-UI"},
    {"fingerprint":"{\"_links\":{\"self\":{\"href\":\"","tag":"actuator"},
    ]#稳定api响应页面swagger springboot


#爬取实现
resultJs=[]
resultUrl=[]
endUrl=[]
ua="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
domainblacklist=[
                "www.w3.org", "example.com", "github.com","example.org",
            ]
urlblacklist=[".js?", ".css?", ".jpeg?", ".jpg?", ".png?", ".gif?", "github.com", "www.w3.org", "example.com","example.org", "<", ">", "{", "}", "[", "]", "|", "^", ";", "/js/", "location.href", "javascript:void"]
urlextblacklist=[".js",",",".css",".jpeg",".jpg",".png",".gif",".ico",".svg",".less",".svga"]
countspider=[]
# configdomainurl=None
configdomainurlroot=[]

def readFileIntoList(filename):
    tmpLines=[]
    with open(filename,'r',encoding='utf-8') as f:
        for line in f.readlines():
            if line!="\n":
                tmpLines.append(line.strip())
    return tmpLines


def writeLinesIntoFile(lines,filename):
    with open(filename,'w',encoding='utf-8') as f:
        for line in lines:
            f.write(line+"\n")
        f.close()
def isFileValidTxt(filename):
    # 使用mimetypes来获取文件的MIME类型
    mimetype, encoding = mimetypes.guess_type(filename)
    if mimetype and mimetype.startswith('text'):
        # 如果MIME类型以"text"开头，则可以认为文件是文本文件
        return True
    else:
        return False
def isUrlValid(URL):
    return True if "http://" in URL or "https://" in URL else False
def getHost(URL):
    # if isUrlValid(URL):
    #     tmpHost=URL.split("//")[1]
    #     Host=tmpHost if "/" not in tmpHost else tmpHost.split("/")[0]
    #     if DEBUG and Verbose:
    #         print(f"Host: {Host}")
    #     return Host
    # else:
    #     sys.exit(f"不是有效的URL：{URL}")#* 这里不用处理意外退出，已经在输入的地方处理
    if not isUrlValid(URL):
        return
    parsed_url=urlparse(URL)
    path = parsed_url.path
    host = parsed_url.hostname#不含端口
    port=parsed_url.port
    scheme = parsed_url.scheme
    return host

def getCleanUrl(origionUrl):
    if "/" in origionUrl.replace("http://","").replace("https://",""):
        pattern = re.compile(r'https?://.+?(?=/)')
    else:
        pattern = re.compile(r'https?://.+')
    if pattern.match(origionUrl):
        return pattern.match(origionUrl).group(0)
    else:
        return

def urlExcludeJs(urlList,origionUrl):
    """仅采用url列表里的包含初始host的链接，同时排除js文件
    使用fileExtBlackList和urlBlackList进行过滤

    Args:
        urlList (_type_): _description_
        origionUrl (_type_): _description_

    Returns:
        _type_: _description_
    """
    #去除爬取到的存在参数的链接中的参数
    urlList=[x if "?" not in x else x.split("?")[0] for x in urlList]
    # tmpList=[url for url in urlList if url.split(".")[-1].rstrip("\\") not in fileExtBlackList and not any(x in url for x in urlBlackList) and getHost(origionUrl) in url]
    #todo 去除host限制，综合所有爬取到的路径
    tmpList=[url for url in urlList if url.split(".")[-1].rstrip("\\") not in fileExtBlackList and not any(x in url for x in urlBlackList)]
    return tmpList
def requestWithHttpx(filename):
    command=f"httpx -l {filename} -title -sc -cl -silent -fr -t 500 -fc 404"
    print(f"httpx命令 排除404: {command}")
    os.system(command)
def somehowreplaceHttpx(mode,origionUrl,apiList):
    """移除httpx调用

    Args:
        urlList (_type_): _description_
    """
    cleanurl=getCleanUrl(origionUrl)
    apiList=[{"url":api,"tag":"httpx","api":api} for api in apiList]
    # urlListWithTag=[cleanurl+ele["url"] for ele in apiList]
    urlListWithTag=[]
    for ele in apiList:
        ele["url"]=cleanurl+ele["url"]
        urlListWithTag.append(ele)
    fuzz=apiFuzz()
    threads=50
    anchorRespList=[]
    Results=fuzz.taskUsingThread(fuzz.universalGetRespWithTagUsingRequests,mode,origionUrl,urlListWithTag,anchorRespList,threads)
    #排除404响应
    Results=[x for x in Results if x["status"]["code"]!=404]
    #标记所有初始响应
    # 从每个字典中提取size键
    sizes = [d['status']['size'] for d in Results]
    # 使用Counter计数
    size_counts = Counter(sizes)
    # 找到计数最高的元素
    most_common_size = size_counts.most_common(1)[0][0]
    # print(f"最大相同值: {most_common_size}")
    # 找到具有最多相同size键的元素
    if most_common_size:
        most_common_elements = sorted([d for d in Results if d['status']['size'] == most_common_size],key=lambda item:item["api"])
        diffResults=sorted([d for d in Results if d['status']['size'] != most_common_size],key=lambda item:item["api"])
        result=most_common_elements[0]
        if result["status"]["code"]!=404:
            print()
            print(f"默认(初始)响应页面:")
            if result["status"]['locationtimes']==0:
                    print(f"{result['url']} [{result['status']['code']}] [{result['status']['size']}] [{result['status']['title']}]")
            else:
                code=",".join([str(x) for x in result["status"]["locationcode"]])
                location="-->".join(result["status"]["location"])
                print(f"{result['url']} [{code}] [{result['status']['size']}] [{result['status']['title']}] [{location}]")
    if diffResults:
        print()
        print(f"差异响应页面:")
        #*[{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title,"locationcode":[],"location":[],"locationtimes":0},"resp":resp,"tag":tag,"api":"api"}]
        for result in diffResults:
            if result["status"]["code"]!=404:
                if result["status"]['locationtimes']==0:
                    print(f"{result['url']} [{result['status']['code']}] [{result['status']['size']}] [{result['status']['title']}]")
                else:
                    code=",".join([str(x) for x in result["status"]["locationcode"]])
                    location=" --> ".join(result["status"]["location"])
                    print(f"{result['url']} [{code}] [{result['status']['size']}] [{result['status']['title']}] [{location}]")
        if DEBUG:
            print(f"验证:发包次数: {len(countspider)} 次")
def somehowreplaceUrlfinder(url):
    """移除urlfinder调用

    Args:
        url (_type_): _description_
    """
    global resultUrl
    global resultJs
    global endUrl
    mySpider=jsSpider()
    mySpider.Spider(url)#def Spider(self,url,isdeep=True):
    resultUrl = mySpider.RemoveRepeatElement(resultUrl)
    # resultJs = mySpider.RemoveRepeatElement(resultJs)
    lst=resultUrl.copy()
    lst=urlExcludeJs(lst,url)
    # if DEBUG:
    #     print(f"resultUrl: {len(resultUrl)} 个")
    #     print(f"resultJs: {len(resultJs)} 个")
    #     print(f"endUrl: {len(endUrl)} 个")
    #     print(f"置空")
    resultUrl=[]
    resultJs = []
    endUrl=[]

    return lst

def apiToUrlRearrange(origionUrl,apiList):
    cleanurl=getCleanUrl(origionUrl)
    apiList=[{"url":api,"tag":"httpx","api":api} for api in apiList]
    # urlListWithTag=[cleanurl+ele["url"] for ele in apiList]
    urlListWithTag=[]
    for ele in apiList:
        ele["url"]=cleanurl+ele["url"]
        urlListWithTag.append(ele)
    if urlListWithTag:
        return urlListWithTag
    else:
        return

#废弃
def getApiFromUrlList(origionUrl,urlList):
    """从输入的url列表中获取api接口列表

    Args:
        origionUrl (_type_): _description_
        urlList (_type_): _description_
    """
    cleanUrl=getCleanUrl(origionUrl)
    if DEBUG:
        print()
        print("接口处理")
        print(f"cleanUrl: {cleanUrl}")
    #排除某些特殊情况，api结尾存在反斜杠
    # 这里的逻辑在修改gethost函数之后就需要改变了
    interfaceList=[x.replace(cleanUrl,"").strip("\\") for x in urlList]
    # 修正gethost逻辑变化之后导致的api净化问题
    for x in range(len(interfaceList)):
        if "http://" in interfaceList[x] or "https://" in interfaceList[x]:
            interfaceList[x]=urlparse(interfaceList[x]).path
    mydicc={}
    for x in interfaceList:
        mydicc[x]=None
    interfaceList=list(set(mydicc.keys()))
    if DEBUG and Verbose:
        print("接口为: ")
        for line in interfaceList:
            print(line)
    return interfaceList
def urlToInterface(origionUrl,urlList,interfaceDicc):
    """分离功能，本函数主要用来过渡，api获取由上面的getApiFromUrlList函数实现

    Args:
        origionUrl (_type_): _description_
        urlFilename (_type_): _description_
        interfaceDicc (_type_): _description_
    """
    # urlList=readFileIntoList(urlFilename)
    interfaceList=getApiFromUrlList(origionUrl,urlList)
    writeLinesIntoFile(interfaceList,interfaceDicc)
    print(f"输出接口到文件完毕: {interfaceDicc}, 总数: {len(interfaceList)}")
    if interfaceList:
        return interfaceList
    else:
        return

def removeDangerousApi(urlList):
    """移除url列表中包含危险关键字的url
    del delete remove drop update shutdown restart

    Args:
        urlList (_type_): _description_
    """
    cleanUrlList=[url for url in urlList if not any(api in url.lower() for api in dangerApiList)]
    dangerUrlList=[url for url in urlList if any(api in url.lower() for api in dangerApiList)]
    filename=".js_dangerous.txt"
    if len(dangerUrlList)!=0:
        writeLinesIntoFile(dangerUrlList,filename)
        print(f"危险接口总数: {len(dangerUrlList)} 个,已输出到 {filename} ,如下：")
        if len(dangerUrlList)!=0:
            print("随机展示危险接口")
            for i in range(len(dangerUrlList)):
                if i%10==0:
                    print(dangerUrlList[i])
    else:
        print(f"未发现危险接口")
    return cleanUrlList

def getParseJsFromUrl(origionUrl):
    if DEBUG:
        print(f"初始url为: {origionUrl}")
        print()
    # urlList=getJsWithoutPaperWork(origionUrl)
    # urls=[]
    # urlList=[]
    urlList=somehowreplaceUrlfinder(origionUrl)
    # urls.append(origionUrl)
    # cleanurl=getCleanUrl(origionUrl)
    # if cleanurl!=origionUrl.strip("/"):
    #     urls.append(cleanurl)
    # for url in urls:
    #     # urlList+=getJsWithoutPaperWork(url)
    #     # urlList+=getJsWithoutPaperWorkUsingJSFinder(url)
    #     urlList+=somehowreplaceUrlfinder(url)
    #*爬取origionurl和cleanurl
    # if cleanurl!=origionUrl.strip("/"):
    #     # urlList+=getJsWithoutPaperWork(cleanurl)
    #     urlList+=getJsWithoutPaperWorkUsingJSFinder(cleanurl)
    urlList=list(set(urlList))
    if DEBUG:
        print(f"爬取发包次数: {len(countspider)} 次")
    if urlList:
        return urlList
    else:
        return
def getJsWithoutPaperWork(origionUrl):
    """通过subprocess获取urlfinder输出并进行过滤

    Args:
        origionUrl (_type_): _description_

    Returns:
        _type_: _description_
    """
    arg1 = f"-u"
    arg2 = origionUrl
    result = subprocess.run(['urlfinder', arg1, arg2],
                            capture_output=True, text=True)
    output = result.stdout
    error = result.stderr
    return_code = result.returncode
    if return_code == 0:
        urlListFromSpider=urlExcludeJs(output.split("\n"),origionUrl)
        if DEBUG:
            print(f"爬取链接过滤后共: {len(urlListFromSpider)} 个")
        return urlListFromSpider
    else:
        return
def getJsWithoutPaperWorkUsingJSFinder(origionUrl):
    """通过subprocess获取urlfinder输出并进行过滤

    Args:
        origionUrl (_type_): _description_

    Returns:
        _type_: _description_
    """
    arg0 = "JSFinder.py"
    arg1 = f"-u"
    arg2 = origionUrl
    result = subprocess.run(['python3', arg0,arg1, arg2],
                            capture_output=True, text=True)
    output = result.stdout
    error = result.stderr
    return_code = result.returncode
    if return_code == 0:
        urlListFromSpider=urlExcludeJs(output.split("\n"),origionUrl)
        if DEBUG:
            print(f"爬取链接过滤后共: {len(urlListFromSpider)} 个")
        return urlListFromSpider
    else:
        return
#这两个为原始排序算法，根据字符串长度排序
def compare_strings(a, b):
    if len(a) == len(b):
        return 0
    elif len(a) < len(b):
        return -1
    else:
        return 1

def selection_sort(lst):
    for i in range(len(lst)):
        min_idx = i
        for j in range(i+1, len(lst)):
            if compare_strings(lst[j], lst[min_idx]) < 0:
                min_idx = j
        lst[i], lst[min_idx] = lst[min_idx], lst[i]

def urlToFile(mode,origionUrl,filename):
    """调用urlfinder输出url到指定文件

    Args:
        origionUrl (_type_): 初始url
        filename (_type_): 保存url
    """
    # if DEBUG:
    #     print(f"初始url为: {origionUrl}")
    #     print()
    rawFilename=".js_raw_result.txt"
    filename=".js_result.txt"
    # urlList=getJsWithoutPaperWork(origionUrl)
    # #*爬取origionurl和cleanurl
    # cleanurl=getCleanUrl(origionUrl)
    # if cleanurl!=origionUrl.strip("/"):
    #     urlList+=getJsWithoutPaperWork(cleanurl)
    urlList=getParseJsFromUrl(origionUrl)
    if not urlList:
        # sys.exit("爬取结果为空")
        print("爬取结果为空")
        print()
        return
    print()
    # if len(urlList)==0:
    #     sys.exit("爬取结果为空")

    print(f"url爬取完毕，原始结果输出到 {rawFilename}, url总数: {len(urlList)}")
    writeLinesIntoFile(urlList,rawFilename)

    print()
    if DEBUG:
        print(f"移除危险接口: {dangerApiList}")
    else:
        print(f"移除危险接口")
    urlListRemovedDangerous=removeDangerousApi(urlList)
    # writeLinesIntoFile(removeDangerousApi(urlList),filename=filename)
    writeLinesIntoFile(urlListRemovedDangerous,filename=filename)
    print()
    # 优化httpx输出位置到底部
    #输出爬取结果
    # urlList=readFileIntoList(filename)
    # for line in urlList:
    #     print(line)
    # for line in urlListRemovedDangerous:
    #     # print(line)
    #     print(f"{line}         api: {urlparse(line).path}")
    #输出接口字典到文件
    print()
    interfaceDicc=".js.txt"
    myspider=apiFuzz()
    apiList=urlToInterface(origionUrl,urlListRemovedDangerous,interfaceDicc)
    outputUrlList=myspider.fastUniqListWithTagDicc(apiToUrlRearrange(origionUrl,apiList))
    print(f"输出爬取结果: {len(outputUrlList)} 个")
    if outputUrlList:
        outputUrlList=sorted(outputUrlList,key=lambda item: item["api"])
        for line in outputUrlList:
            print(f"{line['url']}         api: {line['api']}")
    else:
        print(f"处理结果为空")
    # print()
    # if apiList:
    #     print(f"输出锚点#链接: {len(apiList)} 个")
    # else:
    #     print(f"锚点#链接: 0 个")
    # apiList=sorted(getApiFromUrlList(origionUrl,urlList))#全排序会干扰判断，这里不完全排序
    # getAnchor=apiFuzz()
    # apiList=sorted(getAnchor.fastUniqList(apiList))#全排序会干扰判断，这里不完全排序
    # anchorList=getAnchor.mergePathPure(anchorUserInterface,apiList)
    # for line in anchorList:
    #     print(line)
    # print("httpx 验证开始")
    print()
    print("爬取结果验证开始")
    # requestWithHttpx(filename)
    somehowreplaceHttpx(mode,origionUrl,apiList)
    # print("爬取结果验证结束")
    # print("httpx 访问结束")
    return True

def singleSpider(mode,origionUrl):
    print(f"开始处理: {origionUrl}")
    print()
    filename=".js_result.txt"
    # mode=""
    urlToFile(mode,origionUrl=origionUrl,filename=filename)

def batchSpider(mode,urlList):
    for url in urlList:
        print()
        print(f"处理URL: {url}")
        singleSpider(mode,url)
# 接受新内容输入
def read_newline():
    print()
    print("请输入API(api或url形式)：")
    line = input().strip()
    new_line=line
    return new_line
#用户输入处理
def singleUserInputApi(mode,origionUrl,apiPaths):
    # urlList=getJsWithoutPaperWork(origionUrl)
    # #*爬取origionurl和cleanurl
    # cleanurl=getCleanUrl(origionUrl)
    # if cleanurl!=origionUrl.strip("/"):
    #     urlList+=getJsWithoutPaperWork(cleanurl)
    global configdomainurlroot
    urlList=getParseJsFromUrl(origionUrl)
    if not urlList:
        # sys.exit("爬取结果为空")
        print("爬取结果为空")
        return
    #去除危险接口
    urlList=removeDangerousApi(urlList)
    #获取接口
    apiList=getApiFromUrlList(origionUrl,urlList)
    myFuzz=apiFuzz()
    anchorRespList=myFuzz.getAnchorResponse(mode,origionUrl)
    # 取消手动输入api情况下的对比 不取消
    #todo 或者留下锚点，但是依然输出
    print("")
    singlestatus=userInputApi(mode,origionUrl,apiPaths,apiList,anchorRespList)
    configdomainurlroot=[]#单次结束置空
    if DEBUG:
        print(f"单输入:发包次数: {len(countspider)} 次")
    return singlestatus
def batchUserInputApi(mode,urlList,apiPaths):
    batchTaskStatus=[]
    for url in urlList:
        print()
        print(f"处理URL: {url}")
        singlestatus=singleUserInputApi(mode,url,apiPaths)
        if singlestatus:
            batchTaskStatus.append(singlestatus)
        else:
            singlestatus={"target":url,"juicyApiList":[],"sensitivInfoList":[],"sensitiveFileList":[],"apiFigureout":{"inputApis":[],"validApis":[],"suspiciousAPis":[]},"fingerprint":[],"tag":"default","dead":"dead"}
            batchTaskStatus.append(singlestatus)
    #输出批任务状态
    printer=apiFuzz()
    printer.batchTaskStatusOutput(mode,batchTaskStatus)
    #*[{"target":origionUrl,"juicyApiList":juicyApiList,"sensitivInfoList":sensitivInfoList,"sensitiveFileList":sensitiveFileList,"apiFigureout":{"validApis":validApis,"suspiciousApis":suspiciousApis},}]
    if DEBUG:
        print(f"批输入:发包次数: {len(countspider)} 次")
def userInputApi(mode,origionUrl,apiPaths,apiList,anchorRespList):
    """用户指定api路径的情况，支持api和完整api URL的情况

    Args:
        apiPath (_type_): _description_
    """
    apiGen=apiFuzz()
    singlestatus=apiGen.apiFuzzForUserInputApiInAction(mode,origionUrl,apiPaths,apiList,anchorRespList)
    # singlestatus["apiFigureout"]["inputApis"]=[apiPaths]
    singlestatus["apiFigureout"]["inputApis"]=apiPaths
    return singlestatus

def jsonRespOutput(resp,respstatus):
    """返回body为json时打印body内容
    body超大时打印前300字符，输出提示

    Returns:
        _type_: _description_
    """
    # if "application/json" in respstatus["type"]:
    if "json" in respstatus["type"]:#*修复content-type库连锁问题
        if not respstatus["size"] > 300:
            printer=resp.text
        else:
            printer=f"{resp.text[0:300]} ------->数据过大"
        return printer
    else:
        return

# resultJs=[]
# resultUrl=[]
# endUrl=[]
# ua="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
# domainblacklist=[
#                 "www.w3.org", "example.com", "github.com","example.org",
#             ]
# urlblacklist=[".js?", ".css?", ".jpeg?", ".jpg?", ".png?", ".gif?", "github.com", "www.w3.org", "example.com","example.org", "<", ">", "{", "}", "[", "]", "|", "^", ";", "/js/", "location.href", "javascript:void"]
# urlextblacklist=[".js",",",".css",".jpeg",".jpg",".png",".gif",".ico",".svg",".less",".svga"]
# countspider=[]
#js爬取实现
#爬取功能来自大佬项目https://github.com/pingc0y/URLFinder，用python进行了实现
class jsSpider():
    #todo 实施多线程爬取
    def Spider(self,url,isdeep=True):
        requests.packages.urllib3.disable_warnings()
        url =urllib.parse.unquote(url)
        if self.getEndUrl(url):
            return
        self.appendEndUrl(url)
        headers={
            "User-Agent": ua,
            "Accept": "",
        }
        try:
            resp=requests.get(url,headers=headers,timeout=(5,10), verify=False)
        except Exception as e:
            print(f"请求出错, {e}")
            return
        respurl = resp.request.url
        parsed_url=urlparse(respurl)
        path = parsed_url.path
        host = parsed_url.hostname
        port=parsed_url.port
        if port:
            host=host+":"+str(port)
        scheme = parsed_url.scheme
        #提取js
        countspider.append(1)
        self.jsFind(resp.text, host, scheme, path,isdeep)
        #提取url
        self.urlFind(resp.text, host, scheme, path,isdeep)

    def jsFind(self,res,host,scheme,path,isdeep=False):
        rootregex=re.compile(r'/.*/{1}|/')
        rootresult=rootregex.findall(path)
        if rootresult:
            root=rootresult[0]
        else:
            root="/"
        host=scheme+"://"+host
        # jsregs=[
        #     "http[^\\s,^',^’,^\",^>,^<,^:,^(,^),^\\[]{1,250}?[.]js",
        #     "[\",']/[^\\s,^',^’,^\",^>,^<,^:,^(,^),^\\[]1,250}?[.]js",
        #     "=[^\\s,^',^’,^\",^>,^<,^:,^(,^),^\\[]{1,250}?[.]js", "" +
        #     "=[\",'][^\\s,^',^’,^\",^>,^<,^:,^(,^),^\\[]{1,250}?[.]js",
        # ]
        jsregs=[
            r'http[^\s\'’"\>\<\:\(\)\[]{1,250}?[.]js',
            r'["\']/[^\s\'’"\>\<\:\(\)\[]{1,250}?[.]js',
            r'=[^\s\'’"\>\<\:\(\)\[]{1,250}?[.]js',
            r'=["\'][^\s\'’"\>\<\:\(\)\[]{1,250}?[.]js',
        ]
        # jsregs=[
        #     r'http[^\s\'’"\>\<\:\(\)\[]{1,250}?[\.]js',
        #     r'["\']/[^\s\'’"\>\<\:\(\)\[]{1,250}?[\.]js',
        #     r'=[^\s\'’"\>\<\:\(\)\[]{1,250}?[\.]js',
        #     r'=["\'][^\s\'’"\>\<\:\(\)\[]{1,250}?[\.]js',
        # ]

        for jsreg in jsregs:
            jss=re.findall(jsreg,res)
            jss=["".join(x) for x in jss]#元组已处理
            jss = self.jsFilter(jss)
            jss=[x.rstrip("\\") if x.endswith("\\") else x for x in jss]
            for js in jss:
                if js=="":
                    continue
                if js.startswith("https:") or js.startswith("http:"):
                    self.appendJs(js)
                    if isdeep:
                        self.Spider(js,False)
                elif js.startswith("//"):
                    self.appendJs(scheme+":"+js)
                    if isdeep:
                        self.Spider(scheme+":"+js,False)
                elif js.startswith("/"):
                    self.appendJs(host+js)
                    if isdeep:
                        self.Spider(host+js,False)
                else:
                    self.appendJs(host+root+js)
                    if isdeep:
                        self.Spider(host+root+js,False)
    def urlFind(self,res,host,scheme,path,isdeep=False):
        root=""
        rootregex=re.compile(r'/.*/{1}|/')
        roots=rootregex.findall(path)
        if roots:
            root=roots[0]
        else:
            root="/"
        host=scheme+"://"+host
        # urlregexs=[
        #     "[\",']http[^\\s,^',^’,^\",^>,^<,^),^(]{2,250}?[\",']",
        #     "=http[^\\s,^',^’,^\",^>,^<,^),^(]{2,250}",
        #     "[\",']/[^\\s,^',^’,^\",^>,^<,^\\:,^),^(]{2,250}?[\",']",
        #     "(href|action).{0,3}=.{0,3}[\",'][^\\s,^',^’,^\",^>,^<,^),^(]{2,250}",
        #     "(href|action).{0,3}=.{0,3}[^\\s,^',^’,^\",^>,^<,^),^(]{2,250}",
        # ]
        #爬根配置
        domainurlregex=r'window\._CONFIG\[\'domianURL\'\]\s=\s\'(https{0,1}://.*)\''
        domain=re.findall(domainurlregex,res)
        if domain:
            configdomainurlroot.append("/"+urlparse(domain[0]).path.strip("/"))
        urlregexs=[
            r'["\']http[^\s\'’"\>\<\)\(]{2,250}?[\"\']',
            r'=http[^\s\'’"\>\<\)\(]{2,250}',
            r'[\"\']/[^\s\'’"\>\<\:\)\(]{2,250}?["\']',
            r'(href|action).{0,3}=.{0,3}[\"\'][^\s\'’"\>\<\)\(]{2,250}',
            r'(href|action).{0,3}=.{0,3}[^\s\'’"\>\<\)\(]{2,250}',
        ]

        for urlregex in urlregexs:
            pattern=re.compile(urlregex)
            urls=pattern.findall(res)
            urls=["".join(x) for x in urls]#元组已处理
            urls=self.urlFilter(urls)
            urls=[x.rstrip("\\") if x.endswith("\\") else x for x in urls]
            for url in urls:
                if url=="":
                    continue
                if url.startswith("https:") or url.startswith("http:"):
                    self.appendUrl(url)
                    if isdeep:
                        self.Spider(url,False)
                elif url.startswith("//"):
                    self.appendUrl(scheme+":"+url)
                    if isdeep:
                        self.Spider(scheme+":"+url,False)
                elif url.startswith("/"):
                    self.appendUrl(host+url)
                    if isdeep:
                        self.Spider(host+url,False)
                elif url.endswith(".js"):
                    self.appendUrl(host+root+url)
                    if isdeep:
                        self.Spider(host+root+url,False)

    def jsFilter(self,lst):
        tmp=[]
        for line in lst:
            line = line.replace("\\/", "/")
            line = line.replace(" ", "")
            line = line.replace("\"", "")
            line = line.replace("%3A", ":")
            line = line.replace("%2F", "/")
            #新增排除\\
            line = line.replace("\\\\", "")
            if line.endswith("\\"):
                line=line.replace("\\","")
            if line.startswith("="):
                line=line.replace("=","",1)
            for x in domainblacklist:
                if x in line:
                    line=""
                    break
            tmp.append(line)
        return tmp
    def urlFilter(self,lst):
        tmp=[]
        for line in lst:
            line = line.replace(" ", "")
            line = line.replace("\\/", "/")
            line = line.replace("\"", "")
            line = line.replace("'", "")
            line = line.replace("href=\"", "", 1)
            line = line.replace("href='", "", 1)
            line = line.replace("%3A", ":")
            line = line.replace("%2F", "/")
            #新增排除\\
            line = line.replace("\\\\", "")
            if line.endswith("\\"):
                line=line.replace("\\","")
            if line.startswith("="):
                line=line.replace("=","",1)
            if line.startswith("href="):
                line=line.replace("href=","",1)
            for x in urlblacklist:
                if x in line:
                    line=""
                    break
            for x in urlextblacklist:
                if line.endswith(x):
                    line=""
                    break
            tmp.append(line)
        return tmp
    def getEndUrl(self,url):#判断url是否已经爬取
        # for x in endUrl:
        #     if url==x:
        if url in endUrl:
            return True
        return False
    def appendEndUrl(self,url):
        # for x in endUrl:
        #     if url==x:
        if url in endUrl:
            return
        endUrl.append(url)
    def appendUrl(self,url):
        # for x in resultUrl:
        #     if x==url:
        if url in resultUrl:
            return
        resultUrl.append(url)
    def appendJs(self,js):
        # for x in resultJs:
        #     if x==js:
        if js in resultJs:
            return
        resultJs.append(js)
    def RemoveRepeatElement(self,lst):
        mydicc={}
        tmp=[]
        for line in lst:
            if len(line)>10:
                # regex=re.compile(r'([a-z0-9\\-]+\\.)*([a-z0-9\\-]+\\.[a-z0-9\\-]+)(:[0-9]+)?')
                regex=re.compile(r'([a-z0-9\-]+\.)*([a-z0-9\-]+\.[a-z0-9\-]+)(:[0-9]+)?')
                hosts=regex.findall(line)#元组已处理
                hosts=["".join(x) for x in hosts]
                if hosts:
                    if line not in mydicc:
                        mydicc[line]=None
                        tmp.append(line)
        return tmp

class apiFuzz:
    #todo 建立项目文件，每个目标生成不同结果文件？低优先级

    #? 智能区分有效接口返回特征 springboot 404  常规404或200但无效
    # 由于站点种类太复杂，没有绝对的方式来 根据响应内容 区分有效和无效接口
    # 可以使用锚点，访问大量绝对不存在的路径获得参照点 已处理
    #* 目前只排除404响应，其他全部输出
    # 需要考虑springboot404界面和500界面 与accept的值有关 已处理
    def uniqRoot(self,lst):
        """输出根为唯一的api
        最短公共前缀

        Args:
            lst (_type_): _description_

        Returns:
            _type_: _description_
        """
        lst = sorted(lst)
        common_prefixes = []

        for i in range(len(lst)):
            foots=lst[i]
            for j in range(len(lst)):
                if i!=j and lst[i]!=lst[j]:
                    delimiter="/"
                    footb=self.footSize(lst[i],lst[j],delimiter)
                    if footb:
                        if foots < footb:
                            pass
                        else:
                            foots=footb
            if foots not in common_prefixes:
                common_prefixes.append(foots)
        common_prefixes.sort(key=len)
        return common_prefixes
    def uniqRootImplement2(self,lst):
        """输出根为唯一的api
        最短公共前缀

        Args:
            lst (_type_): _description_

        Returns:
            _type_: _description_
        """
        common_prefixs=[]
        splitList=list(set([x.strip("/").split("/")[0] for x in lst]))
        tmp=[]
        for i in range(len(splitList)):
            tmp.append([x for x in lst if x.strip("/").split("/")[0]==splitList[i]])
        for i in range(len(tmp)):
            if len(tmp[i])==1:
                common_prefixs.append(tmp[i][0])
            else:
                delimiter="/"
                tmp[i].sort(key=len)
                foota=self.footSize(tmp[i][0],tmp[i][1],delimiter)
                footb=self.footSize(tmp[i][-1],tmp[i][-2],delimiter)
                common_prefixs.append(self.footSize(foota,footb,delimiter).rstrip("/"))
        common_prefixs.sort(key=len)
        return common_prefixs
    def uniqRootImplement3(self,lst):
        """输出根为唯一的api
        最短公共前缀
        第三种实现方式

        Args:
            lst (_type_): _description_

        Returns:
            _type_: _description_
        """
        common_prefixs=[]
        splitList=list(set([x.strip("/").split("/")[0] for x in lst]))
        delimiter="/"
        for uniq in splitList:
            count=0
            for i in range(len(lst)):
                if self.footSize(lst[i],uniq,delimiter):
                    count+=1
                if count==2:
                    common_prefixs.append("/"+uniq)
                    break
            if count==1:
                common_prefixs.append(["/"+x.strip("/") for x in lst if x.strip("/").startswith(uniq)][0])
        common_prefixs.sort(key=len)
        return common_prefixs
    def uniqRootImplement4(self,lst):
        """输出根为唯一的api
        最短公共前缀
        第三种实现方式
        --->公共前缀唯一，在原始数据中找唯一值替换公共前缀
        Args:
            lst (_type_): _description_

        Returns:
            _type_: _description_
        """
        common_prefixs=[]
        splitList=[x.strip("/").split("/")[0] for x in lst]
        uniques = [item for item, count in Counter(splitList).items() if count == 1]
        delimiter="/"
        if uniques:
            for i in range(len(lst)):
                for y in uniques:
                    if self.footSize(lst[i],y,delimiter):
                        splitList[splitList.index(y)]=lst[i].strip("/")
        common_prefixs=list(set(splitList))
        common_prefixs=["/"+x for x in common_prefixs]
        common_prefixs.sort(key=len)
        return common_prefixs

    def uniqRootImplement5(self,lst):
        """输出根为唯一的api
        最短公共前缀

        Args:
            lst (_type_): _description_

        Returns:
            _type_: _description_
        """
        common_prefixs=[]
        splitList=list(set([x.strip("/").split("/")[0] for x in lst]))
        delimiter="/"
        tmp=[]
        for i in range(len(splitList)):
            tmp.append([x for x in lst if x.strip("/").split("/")[0]==splitList[i]])
        for i in range(len(tmp)):
            if len(tmp[i])==1:
                common_prefixs.append(tmp[i][0].strip("/"))
            else:
                for x in splitList:
                    if  self.footSize(tmp[i][0],x,delimiter):
                        common_prefixs.append(x)
        common_prefixs=["/"+x for x in common_prefixs]
        common_prefixs.sort(key=len)
        return common_prefixs
    def uniqRootImplement6(self,lst):
        """输出根为唯一的api
        最短公共前缀

        Args:
            lst (_type_): _description_

        Returns:
            _type_: _description_
        """
        common_prefixs=[]
        splitList=list(set([x.strip("/").split("/")[0] for x in lst]))
        tmp=[]
        for i in range(len(splitList)):
            tmp.append([x for x in lst if x.strip("/").split("/")[0]==splitList[i]])
        delimiter="/"
        for i in range(len(tmp)):
            if len(tmp[i])==1:
                common_prefixs.append(tmp[i][0].strip("/"))
                for x in splitList:
                    if self.footSize(tmp[i][0],x,delimiter):
                        splitList.pop(splitList.index(x))
        common_prefixs+=splitList
        common_prefixs=["/"+x for x in common_prefixs]
        common_prefixs.sort(key=len)
        return common_prefixs

    def uniqPathWithNoCommonRoot(self,lst):
        """#*输出列表中唯一且无公共根的path
        Args:
            lst (_type_): _description_

        Returns:
            _type_: _description_
        """
        uniqpath=[]
        splitList=list(set([x.strip("/").split("/")[0] for x in lst]))
        tmp=[]
        for i in range(len(splitList)):
            tmp.append([x for x in lst if x.strip("/").split("/")[0]==splitList[i]])
        for i in range(len(tmp)):
            if len(tmp[i])==1:
                uniqpath.append(tmp[i][0])
        if len(uniqpath)!=0:
            uniqpath.sort(key=len)
            return uniqpath
        else:
            return
    def footSize(self,str1,str2,delimiter=""):
        """找str1和str2最大相同值
        #存在界定符时，只能以界定符为界进行比较，不会以字符递增进行比较
        Args:
            str1 (_type_): _description_
            str2 (_type_): _description_
        """
        common_prefix = ""
        if delimiter=="":
            for i in range(min(len(str1), len(str2))):
                if str1[i] != str2[i]:
                    break
                common_prefix += str1[i]
        else:
            lst1=str1.strip(delimiter).split(delimiter)
            lst2=str2.strip(delimiter).split(delimiter)
            for i in range(min(len(lst1), len(lst2))):
                if lst1[i] != lst2[i]:
                    break
                common_prefix += lst1[i] +delimiter
        common_prefix=delimiter+common_prefix.strip(delimiter)
        if common_prefix!=delimiter:
            return common_prefix
        else:
            return
    def oneDirectionfootSize(self,str1,str2,delimiter=""):
        """str1是否是str2的公共根
        #存在界定符时，只能以界定符为界进行比较，不会以字符递增进行比较
        Args:
            str1 (_type_): _description_
            str2 (_type_): _description_
        """
        common_prefix = ""
        if len(str1) <= len(str2):
            if delimiter=="":
                if str2.startswith(str1):
                    common_prefix = str1
            else:
                lst1=str1.strip(delimiter).split(delimiter)
                lst2=str2.strip(delimiter).split(delimiter)
                for i in range(len(lst1)):
                    if lst1[i] != lst2[i]:
                        break
                    common_prefix += lst1[i] +delimiter
            common_prefix=delimiter+common_prefix.strip(delimiter)
            if common_prefix!=delimiter:
                return common_prefix
            else:
                return
        else:
            return

    def findLongestCommonPrefix(self,lst):
        """公共前缀寻找
        不包含最长元素值（如果最长元素唯一）

        Args:
            lst (_type_): _description_

        Returns:
            _type_: _description_
        """
        #* 公共前缀是为了定位长api  /api/health
        #* 不是为了寻找最短相同值
        lst = sorted(lst)
        common_prefixes = []
        delimiter="/"
        for i in lst:
            for j in lst:
                if i != j and i.strip("/")!="" and j.strip("/")!="":
                    foot=self.footSize(i.strip("/"),j.strip("/"),delimiter)
                    if foot and foot not in common_prefixes:
                        # common_prefixes.append(foot)
                        common_prefixes.append(delimiter+foot)
        common_prefixes.sort(key=len)
        return common_prefixes

    def findSameElem(self,lst):
        """寻找列表中所有重复值

        Args:
            lst (_type_): _description_

        Returns:
            _type_: _description_
        """
        duplicates = sorted(list(set([x for x in lst if lst.count(x) > 1])))
        # 输出所有相同的值
        return duplicates
    def stairsSplitAndStitch(self,apiList):
        """阶梯切割
        逐级分解api，返回1级、2级、3级。。。api列表
        /api/home/worker/worklist------>/api /api/home /api/home/worker /api/home/worker/worklist
        包含初始元素！

        Args:
            apiList (_type_): _description_
        """
        #!考虑api末尾的/问题，当前去除末尾/ 有些情况必须有根/才能访问
        lst=[]
        for api in apiList:
            tmp=[]
            tmp=api.strip("/").split("/")
            if len(tmp)!=0:
                tmpApi="/"
                for i in range(len(tmp)):
                    if tmp[i]!="":
                        tmpApi+=tmp[i]+"/"
                        lst.append(tmpApi)
        mydicc={}
        for x in lst:
            mydicc[x.rstrip("/")]=None
        lst=list(mydicc.keys())
        return lst
    def fastUniqDicList(self,lst):
        df = pd.DataFrame(lst)
        unique_df = df.drop_duplicates()
        unique_list = unique_df.to_dict('records')
        return unique_list
    def fastUniqList(self,lst):
        """列表快速去重

        Args:
            lst (_type_): _description_

        Returns:
            _type_: _description_
        """
        mydic={}
        for element in lst:
            mydic[element]=None
        resultList=list(mydic.keys())
        #去除包含api黑名单中元素的url
        resultList=[url for url in resultList if not any(c in url for c in apiBlackList)]
        return resultList
    def fastUniqListWithTagDicc(self,lst):
        """对tag列表进行去重

        Args:
            lst (_type_): _description_

        Returns:
            _type_: _description_
        """
        #todo 增加基准点
        # [{"url":url,"tag":"completeApi","api":api}]
        unique_api_list = []
        seen_apis = set()
        for item in lst:
            api = item["api"]
            if api not in seen_apis:
                unique_api_list.append(item)
                seen_apis.add(api)
        return unique_api_list
    def fastExcludeNoneApiFromListWithTagDicc(self,lst, noneApis):
        """排除用户输入的指定api，仅根api，不考虑中间值

        Args:
            lst (_type_): _description_
            noneApi (_type_): _description_

        Returns:
            _type_: _description_
        """
        # [{"url":url,"tag":"completeApi","api":api}]

        noneApis=[x.strip("/") for x in noneApis]
        #todo 这里的逻辑需要修复 更改为uniqRoot实现 noneApi 可能为/sys/list
        filtered_data_list = [item for item in lst if item["api"].strip("/").split("/")[0] not in noneApis]
        if DEBUG:
            print(f"排除指定api后数量: {len(filtered_data_list)}")
        return filtered_data_list
    #fuzz判断实现
    def genTestUrlBatchFromMassList(self,mode,origionUrl,apiList,anchorRespList,noneApiPaths=[]):
        """将大量fuzz目标分批成较小的批次，减少请求量，参照arjun
        函数做的事情与 apiFuzzMode 相似
        """
        #! 探测waf 和网站稳定度 减少线程数
        #! 响应状态记录中记录connection reset的数量 判断waf
        #todo 考虑/ 为根的情况
        singlestatus={"target":origionUrl,"juicyApiList":[],"sensitivInfoList":[],"sensitiveFileList":[],"apiFigureout":{"inputApis":[],"validApis":[],"suspiciousAPis":[]},"fingerprint":[],"tag":"default","dead":"alive"}
        #* 指纹识别逻辑在本函数之前执行
        if "nobody" in mode:#禁用body输出
            noOutput=True
        else:
            noOutput=False
        cleanUrl=getCleanUrl(origionUrl)
        commonApiListProcessed=["/"+x.strip("/") for x in commonApiList]
        apiCommenListWithTag=self.fastUniqDicList([{"url":url,"tag":"commonapi","api":url} for url in commonApiListProcessed])
        directApiListWithTag=self.fastUniqDicList([{"url":url,"tag":"directapi","api":url} for url in apiList])
        bruteApiListWithTag=self.fastUniqDicList([{"url":url,"tag":"bruteApi","api":url} for url in self.bruteForceMerge(apiList)])
        #
        completeApiListWithTag=self.fastUniqDicList([dicc for dicc in self.completeMergeWithTag(apiList)])
        splitApiListWithTag=self.fastUniqDicList([dicc for dicc in self.splitAndFirstMergeWithTag(apiList)])
        commonPrefixApiListWithTag=self.commonPrefixMergeWithTag(apiList)
        stairSplitApiListWithTag=self.stairSplitMergeWithTag(apiList)

        fuzzingList=apiCommenListWithTag+directApiListWithTag+bruteApiListWithTag
        bigList=completeApiListWithTag+splitApiListWithTag+commonPrefixApiListWithTag+stairSplitApiListWithTag
        # random.shuffle(bigList)
        fuzzingList+=bigList
        #去重
        if DEBUG:
            print(f"api总量: {len(fuzzingList)}")
        fuzzingList=self.fastUniqListWithTagDicc(fuzzingList)

        # print(f"过滤去重:api总量: {len(fuzzingList)}")
        print(f"待测试:api总量: {len(fuzzingList)}")
        #排除指定api
        if len(noneApiPaths)!=0:
            if DEBUG:
                print()
                print(f"排除指定api: {noneApiPaths}")
            fuzzingList=self.fastExcludeNoneApiFromListWithTagDicc(fuzzingList,noneApiPaths)
            print(f"排除指定api:api总量: {len(fuzzingList)}")
        random.shuffle(fuzzingList)#*全列表洗牌，2000 正确api数量大概5个，不需要优先顺序
        fuzzingUrlList=fuzzingList.copy()
        for i in range(len(fuzzingUrlList)):#[{"url":url,"tag":"completeApi","api":api}]
            fuzzingUrlList[i]["url"]=cleanUrl+fuzzingUrlList[i]["url"]
        # 去重
        fuzzingUrlList=self.fastUniqDicList(fuzzingUrlList)
        start = 0
        end = 1000
        step = 1000
        loop=0#*控制nofuzz模式下fuzz次数封顶3次,常规15次封顶
        count=0
        #! 未处理多次fuzz未获得有效api的情况，会发送超大量数据包
        while start < len(fuzzingUrlList):
            sublist = fuzzingUrlList[start:end]
            print()
            print(f"第 {count+1} 批次fuzz: 数量: {len(sublist)} 个")
            respList=[]
            threads=200
            #todo 目前发现api必须在所有线程结束后才能匹配，需要即时匹配或者减少间隔
            #sublist[{"url":url,"tag":"completeApi","api":api}]

            self.taskUsingThread(self.getRespWithTagUsingRequests,mode,origionUrl,sublist,respList,threads)
            # 对于springboot来说，只要一个路径出现springboot 404界面则可能为根api
            # 往下一层/api/xxxx/yyy 继续出现404不能作为判断依据
            # 但网上1层404消失了或者出现非springboot404界面则当前路径为api
            apiSpottedList=[]#todo 增加对于任何情况都返回json响应 且内部为404的情况的判断
            for res in respList:#res的值{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title},"resp":resp,"tag":tag,"api":api}
                #* 当前仅比较size
                #! 仅从响应分析是否是api存在非常大的茶艺，目前仅保存响应为json的形式为有效api
                #! 忽略掉api根路径访问响应为接口文档页面的情况
                for anchor in anchorRespList:#anchor的值{"code":code,"size":content_size,"type":contentType,"title":page_title}
                    if res["status"]["code"] !=404 and res["status"]["size"] != anchor["size"] and res["status"]["size"]!=0:
                        # if "application/json" in res["status"]["type"]:
                        if "json" in res["status"]["type"]:#contenttype库实现
                            apiSpottedList.append(res)

            if len(apiSpottedList)!=0:#从这一批fuzz结果中发现
                print()
                tags=[]
                apis=[]#url列表
                for api in apiSpottedList:#{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title},"resp":resp,"tag":tag}
                    if DEBUG:
                        if not noOutput:
                            if api['status']['size'] < 300:
                                print(f"{api['url']} |tag: {api['tag']} |api: {api['api']} :\n{api['resp'].text}")
                            else:
                                print(f"{api['url']} |tag: {api['tag']} |api: {api['api']} :\n{api['resp'].text[0:300]}")
                    if api["tag"] not in tags:
                        tags.append(api["tag"])
                    if api["api"] not in apis:#从响应中获取独立api，从独立api定位tags，从tag定位url进行fuzz
                        apis.append(api["api"])

                print()
                if DEBUG:
                    print(f"定位到疑似api, tags: {tags}")
                print(f"定位到疑似api, apis: {apis}")
                print()
                if "nofuzz" not in mode:
                    #*额外增加api相同的部分，/api  /api/home---->/api
                    #* 公共前缀是为了定位长api  /api/health
                    commonPrefixs=self.findLongestCommonPrefix(apis)
                    if DEBUG:
                        print(f"公共前缀 {len(commonPrefixs)} 个: {commonPrefixs}")
                    #* 这里公共前缀是多余的，阶梯切割会覆盖公共前缀，但是那又怎么样呢o_0
                    #阶梯切割
                    stairs=self.stairsSplitAndStitch(apis)
                    if DEBUG:
                        print(f"阶梯切割 {len(stairs)} 个: {stairs}")
                    #合并所有api
                    apis=apis+commonPrefixs+stairs
                    apis=sorted(self.fastUniqList(apis))
                    print()
                    print(f"api总计 {len(apis)} 个: {apis}")
                    print()

                    fullListFromTags=[x for x in fuzzingUrlList if x["tag"] in tags]
                    if DEBUG:
                        print(f"tag命中url: {len(fullListFromTags)} 个")
                    #* 目前没有使用api定位tag，tag定位url的形式，直接从api定位url
                    #[{"url":url,"tag":"completeApi","api":api}]
                    fullListFromPath=[x for x in fuzzingUrlList if any(x["api"].startswith(api) for api in apis)]
                    if DEBUG:
                        print(f"api命中url: {len(fullListFromPath)} 个")
                    fullListFromTagAndPath=fullListFromTags+fullListFromPath
                    #
                    fullUrlList=self.fastUniqList([x["url"] for x in fullListFromTagAndPath])

                    print(f"根据api tags进行fuzz, 总数量: {len(fullUrlList)} 个")
                    if DEBUG and Verbose:
                        for line in fullUrlList:
                            print(line)
                    #bigList中元素tag未分离，导致命中之后fuzz时数量巨大 已处理
                    # 命中tag的原始数量还是比较大1k多，可以采用命中后取100左右样本进行匹配确认  二次确认无意义 废弃
                    # 根据正确率进行判断正确api，然后完整fuzz？ 既然最后都需要完整fuzz好像没意义
                    # 增加用户输入非根api功能，手动排除某个api，在程序误判后进行手动纠正 已处理
                    # 判断存在问题，如tagA的api为/api，拼接后/api/health/worker 为正确api 全列表阶梯切割 已处理
                    # 但正确api是/api/health，并不是/api，此时对tagA进行fuzz结果中大部分应该都是错误的 全列表阶梯切割 已处理
                    # 如果首次fuzz获得的spottedApiList中存在多个结果，可以通过对比相同的值获得正确api 阶梯切割 已处理
                    # 也可以通过二次样本探测确定是否准确，错误api的样本应该保持大量的错误而非命中 不对 废弃
                    # 也可以通过建立常见api响应页面库首先进行比对确定正确api，大大减少fuzz时间
                    if DEBUG:#不进行有效api列表fuzz
                        print()
                        print("随机展示待测试列表内容")
                        for i in range(0,len(fullUrlList),int(len(fullUrlList)/5)):
                            print(fullUrlList[i])
                        # break
                    singlestatus=self.taskUsingThread(self.getFuzzUrlResultUsingRequests,mode,origionUrl,fullUrlList,anchorRespList,threads)
                    # 输出有效api
                    break#*不继续进行fuzz，此处未考虑多个根api情况
                    #todo 排除已发现有效api进行二次测试，确定是否存在多个根api未被发现
                else:
                    #*返回{"inputApis":[inputApis],"validApis":[validApis],"suspiciousAPis":[suspiciousAPis]}
                    apidicc=self.isApiValid(mode,origionUrl,apis,apiList,[],noneApiPaths,anchorRespList)
                    #nofuzz 状态输出实现
                    #*返回#{"target":origionUrl,"juicyApiList":juicyApiList,"sensitivInfoList":sensitivInfoList,"sensitiveFileList":sensitiveFileList,"apiFigureout":{"inputApis":[inputApis],"validApis":[validApis],"suspiciousAPis":[suspiciousAPis]},"fingerprint":[{"url":url,"tag":"fingerprint","api":api}],"tag":"nofuzz"}
                    if apidicc:
                        singlestatus["tag"]="nofuzz"
                        singlestatus["target"]=origionUrl
                        singlestatus["apiFigureout"]=apidicc
                    else:
                        singlestatus["dead"]="dead"
                    # singlestatus["fingerprint"]=pulses
                    # if apidicc:
                    #     print(f"输入api: {apidicc['inputApis']}")
                    #     print(f"识别api: {apidicc['validApis']}")
                    #     print(f"疑似api: {apidicc['suspiciousAPis']}")
                    # else:
                    #     print("nofuzz: 未识别到有效api")
                    break
            else:
                # 获取新的fuzzingList进行重复 已处理
                # print("重复fuzz 正在开发")
                start = end
                end += step
                count+=1
                loop+=1
                if "nofuzz" in mode:
                    # if loop==3:
                    if loop==4:#*放开host限制后，增加上限
                        print(f"nofuzz模式: fuzz {loop} 次未获得有效api，自动放弃")
                        break
                else:
                    # if loop==15:
                    if loop==8:#*削弱fuzz模式封顶次数
                        print(f"fuzz {loop} 次未获得有效api，自动放弃")
                        break
        if len(apiSpottedList)==0:
            if "nofuzz" in mode:
                print(f"nofuzz模式:fuzz结束，未发现有效api")
            else:
                print(f"fuzz结束，未发现有效api")
            # singlestatus=[]
            singlestatus["dead"]="dead"#*统一输出
        return singlestatus
    #敏感信息发现
    # 输出附加 size
    #todo 根据响应大小 排除锚点 高亮标记大型数据包
    # 获取有效api后 再次获取锚点 过滤需要认证的接口，输出未授权/敏感信息接口
    # 这个锚点直接从fuzzrespList中获取即可
    # 增加相应contenttype
    def getSuspiciousFileFromFuzzResult(self,fuzzResultList):
        """#* 从响应中获取结果
        根据有效文件后缀 或者文件大小 匹配敏感文件泄露
        #fuzzResultList的值{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title},"resp":resp,"tag":tag,"api":api}
        #返回 [{"url": "url", "api": "api", "tag": "xlsx", "desc": "xlsx","code":"code","size":"size","type":contentType,"count": 1}]
        Args:
            fuzzResultList (_type_): _description_
        """
        suspiciousFileList=[]
        for res in fuzzResultList:
            # ext=res["api"].split(".")[-1]
            # if ext:
            #     for fileext in juicyFileExtList:
            #         if ext==fileext:
            #             suspiciousFileList.append({"url": res["url"], "api": res["api"], "tag": ext, "desc": ext,"code":res["status"]["code"],"size":res["status"]["size"],"type":res["status"]["type"],"count": 1})
            info=self.getSuspiciousFileFromRespdicc(res)
            if info:
                suspiciousFileList.append(info)
        if suspiciousFileList:
            return suspiciousFileList
        else:
            return
    def getSuspiciousFileFromRespdicc(self,respdicc):
        """#* 从api列表中直接判断
        根据有效文件后缀 或者文件大小 匹配敏感文件泄露
        #{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title},"resp":resp,"tag":tag,"api":api}
        #返回 [{"url": "url", "api": "api", "tag": "xlsx", "desc": "xlsx","code":"code","size":"size","type":contentType,"count": 1}]
        Args:
            fuzzResultList (_type_): _description_
        """
        suspiciousFileList={"url": "", "api": "", "tag": "", "desc": "","code":0,"size":0,"type":"","count": 1}
        ext=respdicc["api"].split(".")[-1]
        if ext:
            for fileext in juicyFileExtList:
                if ext==fileext:
                    suspiciousFileList={"url": respdicc["url"], "api": respdicc["api"], "tag": ext, "desc": ext,"code":respdicc["status"]["code"],"size":respdicc["status"]["size"],"type":respdicc["status"]["type"],"count": 1}
        if suspiciousFileList["url"]!="":
            return suspiciousFileList
        else:
            return
    #todo 根据状态码进行过滤  500 401
    def getSuspiciousApiFromFuzzResult(self,anchors,fuzzResultList):
        """从fuzz结果中发现可疑的响应 根据juicyApiListKeyWords 发现高可用接口
        #fuzzResultList的值{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title},"resp":resp,"tag":tag,"api":api}
        #返回 [{"url": "url", "api": "api", "tag": "upload", "desc": "upload","code":"code","size":"size","type":contentType,"count": 1}]
        Args:
            fuzzResultList (_type_): _description_
        """
        #todo 返回附加大小
        #todo 从正确api中获得有效api
        #todo 从大量错误api中获得不同的响应内容 可能为正确的api
        apiList=[]
        #合并juicyFileExtList
        juicykeywords=juicyApiListKeyWords.copy()
        juicykeywords+=juicyFileExtList
        for respdicc in fuzzResultList:
            info={}
            tag=""
            count=0
            for key in juicykeywords:
                # if key in respdicc["api"].lower():#todo 这里的判断逻辑需要优化
                if key in respdicc["api"].lower() and respdicc["status"]["size"] not in range(anchors["small"],anchors["big"]):#todo 这里的判断逻辑需要优化
                    tag+=key+","
                    count+=1
            if tag!="":
                tag=tag.strip(",")
                info={"url": respdicc["url"], "api": respdicc["api"], "tag": tag, "desc": tag,"code":respdicc["status"]["code"],"size":respdicc["status"]["size"],"type":respdicc["status"]["type"],"count": count}
            if list(info.keys()):
                apiList.append(info)
        if apiList:
            return apiList
        else:
            return
    def getSuspiciousApiFromApiList(self,origionurl,ApiList):
        """从api列表中结果中发现可疑api 根据juicyApiListKeyWords 发现高可用接口
        #返回 [{"url": "url", "api": "api", "tag": "upload", "desc": "upload","code":"code","size":"size","type":contentType,"count": 1}]
        Args:
            fuzzResultList (_type_): _description_
        """
        resList=[]
        cleanurl=getCleanUrl(origionurl)
        #*ApiList实际是urlList
        ApiList=[x.replace(cleanurl,"") for x in ApiList]
        for api in ApiList:
            url=cleanurl+api
            for key in juicyApiListKeyWords:
                if key in api:#todo 这里的判断逻辑需要优化
                    resList.append({"url": url, "api": api, "tag": key, "desc": key,"code":"code","size":"size","type":"contentType","count": 1})
        if resList:
            return resList
        else:
            return

    def getWonderfulRespFromFuzzResult(self,fuzzResultList):
        """敏感信息发现
        #返回 [{"url": "url", "api": "api", "tag": "idcard", "desc": "身份证","code":"code","size":"size","type":contentType, "count": 1}]
        #fuzzResultList的值{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title},"resp":resp,"tag":tag,"api":api}
        Args:
            fuzzresult (_type_): _description_

        Returns:
            _type_: _description_
        """
        #[{"url": "url", "api": "api", "tag": "idcard", "desc": "身份证","code":"code","size":"size", "count": 1}]
        #{"url": "url", "api": "api", "tag": "idcard", "desc": "身份证","code":"code","size":"size", "count": 1} 计数匹配的次数
        infolist=[]
        for respdicc in fuzzResultList:
            info=self.getWonderfulInfoFromSingleResult(respdicc)
            if info:
                infolist.append(info)
        if infolist:
            return infolist
        else:
            return
    def getWonderfulInfoFromSingleResult(self,respdicc):
        """敏感信息发现
        #返回 {"url": "url", "api": "api", "tag": "idcard", "desc": "身份证","code":"code","size":"size","type":contentType, "count": 1}
        #fuzzResultList的值{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title},"resp":resp,"tag":tag,"api":api}
        Args:
            fuzzresult (_type_): _description_

        Returns:
            _type_: _description_
        """
        #[{"url": "url", "api": "api", "tag": "idcard", "desc": "身份证","code":"code","size":"size", "count": 1}]
        #{"url": "url", "api": "api", "tag": "idcard", "desc": "身份证","code":"code","size":"size", "count": 1} 计数匹配的次数
        infolist={"url": "", "api": "", "tag": "", "desc": "","code":0,"size":0,"type":"","count": 1}
        for regex in sensitiveInfoRegex:
            matches=re.findall(regex["regex"],respdicc["resp"].text)
            if matches:
                infolist={"url":respdicc["url"],"api":respdicc["api"],"tag":regex["tag"],"desc":regex["desc"],"code":respdicc["status"]["code"],"size":respdicc["status"]["size"],"type":respdicc["status"]["type"],"count":len(matches)}
        if infolist["url"]!="":
            return infolist
        else:
            return
    #高亮标记
    def colorOutput(self,respstatus):
        """高亮标记

        Args:
            respstatus (_type_): _description_
        """
        pass

    #用户输入识别
    def feelUserInputApiPulse(self,mode,origionUrl,inputApis):
        apiList=inputApis.copy()
        apiList=["/"+x.strip("/") for x in apiList]
        cleanurl=getCleanUrl(origionUrl)
        apiList=[x for x in apiList if not any(x.strip("/").startswith(y) for y in apiRootBlackList)]
        #合并常见api根
        commonprefixs=self.findLongestCommonPrefix(apiList)#挂件
        if DEBUG and Verbose:
            print(f"公共前缀: {len(commonprefixs)} 个")
            for i in commonprefixs:
                print(i)
        stairstiches=self.stairsSplitAndStitch(apiList)
        if DEBUG and Verbose:
            print(f"阶梯切割: {len(stairstiches)} 个")
            for i in stairstiches:
                print(i)
        fullApilist=self.fastUniqList(apiList+commonprefixs+stairstiches)
        #打tag
        directApiListWithTag=self.fastUniqDicList([{"url":url,"tag":"directapi","api":url} for url in fullApilist])
        print(f"输入指纹识别: 总请求量: {len(directApiListWithTag)} 个")
        if DEBUG and Verbose:
            for line in directApiListWithTag:
                print(f"{line}")
        #生成url
        for i in range(len(directApiListWithTag)):#[{"url":url,"tag":"completeApi","api":api}]
            directApiListWithTag[i]["url"]=cleanurl+directApiListWithTag[i]["url"]
        #排序 按照api长度
        directApiListWithTag=sorted(directApiListWithTag, key=lambda item: len(item["api"]))
        respList=[]
        threads=10
        #请求
        self.taskUsingThread(self.getRespWithTagUsingRequestsWithHeaders,mode,origionUrl,directApiListWithTag,respList,threads)
        #ele {"url":url,"tag":"completeApi","api":api}
        #[res的值{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title},"resp":resp,"tag":tag,"api":api}]
        if DEBUG:
            print(f"response count: {len(respList)}")
        suspiciousApi=[]
        for resp in respList:
            for fingerprint in apiFingerprintWithTag:
                if fingerprint["fingerprint"].lower() in resp["resp"].text[:1000].lower():#tag转换为指纹的tag
                    suspiciousApi.append({"url":resp["url"],"tag":fingerprint["tag"],"api":resp["api"]})
                    break
        suspiciousApi=self.fastUniqListWithTagDicc(suspiciousApi)
        tmp=[x["api"] for x in suspiciousApi]
        uniqrootapi=self.uniqRootImplement2(tmp)
        suspiciousApi=[x for x in suspiciousApi if x["api"] in uniqrootapi]
        if suspiciousApi:
            print()
            print(f"输入模式:指纹识别到有效api:")
            for finger in suspiciousApi:
                print(f"命中api: {finger['api']} 命中指纹: {finger['tag']} 命中url: {finger['url']}")
                print()
            #[{"url":url,"tag":"fingerprint","api":api}]
            return suspiciousApi
        if not suspiciousApi:
            print("输入模式:指纹识别结束，未发现有效api")
            print()
            # if "nofuzz" not in mode:
            #     print("指纹识别结束，未发现有效api")
            # else:
            #     print("nofuzz模式:指纹识别结束，未发现有效api")
        return
    #配置根识别
    def feelRootPulse(self,mode,origionUrl,rootConfigApi):
        configRootUrl=getCleanUrl(origionUrl)+rootConfigApi
        suspiciousApi=[]
        #ele {"url":url,"tag":"default","api":api}
        #列表形式
        #*[{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title,"locationcode":[],"location":[],"locationtimes":0},"resp":resp,"tag":tag,"api":"api"}]
        ele={"url":configRootUrl,"tag":"rootConfigApi","api":rootConfigApi}
        resp=self.universalGetRespWithTagNopbarNolst(ele)
        for fingerprint in apiFingerprintWithTag:
            if fingerprint["fingerprint"].lower() in resp["resp"].text[:1000].lower():#tag转换为指纹的tag
                suspiciousApi.append({"url":resp["url"],"tag":fingerprint["tag"],"api":resp["api"]})
                break
        if suspiciousApi:
            print(f"配置根识别到有效Api:")
            for finger in suspiciousApi:
                print(f"命中api: {finger['api']} 命中指纹: {finger['tag']} 命中url: {finger['url']}")
            #[{"url":url,"tag":"fingerprint","api":api}]
            return suspiciousApi
        else:
            print(f"配置根未识别到有效Api")
        return
    #指纹识别
    def feelPulse(self,mode,origionUrl,apiList,excludedApis=[]):
        """把脉 cool 返回有效api或none
        before big guns just ask if someone is the golden api nicely
        #*[{"url":url,"tag":"fingerprint","api":api}]
        Args:
            result (_type_): _description_
        """
        #输入模式优先识别
        if mode.replace("batch","").startswith("api"):
            inputfinger=self.feelUserInputApiPulse(mode,origionUrl,apiList)
            if inputfinger:
                return inputfinger
            else:
                print(f"输入api未识别到有效api")
                print()
        #优先网站配置根识别
        if configdomainurlroot:
            rootApi=configdomainurlroot[0]
            rootfinger=self.feelRootPulse(mode,origionUrl,rootApi)
            if rootfinger:
                return rootfinger
        #todo 用户输入模式 实施指纹识别之后，要修正这里的逻辑，增加输入api模式
        cleanurl=getCleanUrl(origionUrl)
        #去除api根黑名单
        #todo 考虑指纹识别到其中一个根 另一个没识别到的情况
        # 增加访问优先级 优先访问短api 排序取100
        #todo 增加敏感信息发现，定义敏感信息regex 为敏感信息url 打tag
        #! 增加总表api根的尾 / 重复请求1次
        #todo 增加accept */*的请求 1次进行比对
        # 融合锚点判断 不需要锚点 去除锚点
        # 增加排除指定api
        apiList=[x for x in apiList if not any(x.strip("/").startswith(y) for y in apiRootBlackList)]
        #合并常见api根
        commonApiListProcessed=["/"+x.strip("/") for x in commonApiList]
        commonprefixs=self.findLongestCommonPrefix(apiList)#挂件
        if DEBUG and Verbose:
            print(f"公共前缀: {len(commonprefixs)} 个")
            for i in commonprefixs:
                print(i)
        stairstiches=self.stairsSplitAndStitch(apiList)
        if DEBUG and Verbose:
            print(f"阶梯切割: {len(stairstiches)} 个")
            for i in stairstiches:
                print(i)
        fullApilist=self.fastUniqList(apiList+commonApiListProcessed+commonprefixs+stairstiches)
        #打tag
        directApiListWithTag=self.fastUniqDicList([{"url":url,"tag":"directapi","api":url} for url in fullApilist])
        #排除指定api
        if len(excludedApis)!=0:
            print(f"指纹识别: 排除指定api: {excludedApis}")
            directApiListWithTag=self.fastExcludeNoneApiFromListWithTagDicc(directApiListWithTag,excludedApis)
        print(f"指纹识别: 总请求量: {len(directApiListWithTag)} 个")
        #生成url
        for i in range(len(directApiListWithTag)):#[{"url":url,"tag":"completeApi","api":api}]
            directApiListWithTag[i]["url"]=cleanurl+directApiListWithTag[i]["url"]
        #排序 按照api长度
        directApiListWithTag=sorted(directApiListWithTag, key=lambda item: len(item["api"]))
        #循环识别指纹
        start = 0
        end = 100
        step=100
        loop=0
        count=0
        suspiciousApi=[]
        while start < len(directApiListWithTag):
            sublist = directApiListWithTag[start:end]
            print()
            if "nofuzz" in mode:
                print(f"nofuzz模式:第 {count+1} 批次指纹探测: 数量: {len(sublist)} 个")
            else:
                print(f"第 {count+1} 批次指纹探测: 数量: {len(sublist)} 个")
            respList=[]
            threads=100
            #请求
            # mode=""
            self.taskUsingThread(self.getRespWithTagUsingRequestsWithHeaders,mode,origionUrl,sublist,respList,threads)
            #ele {"url":url,"tag":"completeApi","api":api}
            #[res的值{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title},"resp":resp,"tag":tag,"api":api}]
            # 指纹增加tag
            #对于springboot 404 500 界面 对于多层级api 必须进行逐级访问（应用已经完成） 对比所有具有公共前缀的有效api 取最短值
            if DEBUG:
                print(f"response count: {len(respList)}")
            for resp in respList:
                for fingerprint in apiFingerprintWithTag:
                    if fingerprint["fingerprint"].lower() in resp["resp"].text[:1000].lower():#tag转换为指纹的tag
                        suspiciousApi.append({"url":resp["url"],"tag":fingerprint["tag"],"api":resp["api"]})
                        break
            suspiciousApi=self.fastUniqListWithTagDicc(suspiciousApi)
            tmp=[x["api"] for x in suspiciousApi]
            uniqrootapi=self.uniqRootImplement2(tmp)
            suspiciousApi=[x for x in suspiciousApi if x["api"] in uniqrootapi]
            if len(suspiciousApi)!=0:
                print()
                print(f"指纹识别到有效api:")
                for finger in suspiciousApi:
                    print(f"命中api: {finger['api']} 命中指纹: {finger['tag']} 命中url: {finger['url']}")
                #[{"url":url,"tag":"fingerprint","api":api}]
                return suspiciousApi
            else:
                start = end
                end += step
                count+=1
                loop+=1
                if "nofuzz" in mode:
                    # if loop==5:
                    if loop==10:#*放开host限制后，增加上限
                        print(f"nofuzz模式: 指纹识别 {loop} 次未获得有效api，自动放弃")
                        break
                else:
                    # if loop==10:
                    if loop==15:#*放开host限制后，增加上线
                        print(f"指纹识别 {loop} 次未获得有效api，自动放弃")
                        break
        if len(suspiciousApi)==0:
            if "nofuzz" not in mode:
                print("指纹识别结束，未发现有效api")
            else:
                print("nofuzz模式:指纹识别结束，未发现有效api")
        return

    def generate_random_string(self,length):
        """打tag

        Args:
            length (_type_): _description_

        Returns:
            _type_: _description_
        """
        letters = string.ascii_letters
        result_str = ''.join(random.choice(letters) for i in range(length))
        return result_str
    #锚点
    def getAnchorResponse(self,mode,origionUrl,threads=10):
        """请求10个绝对不存在的路径 /xxx 5个 /xxx/yyy 5个
        增加到40个
        请求原始url
        请求cleanurl

        Args:
            origionUrl (_type_): _description_
        """
        #todo 可以借鉴sqlmap对于初始url的稳定性探测
        #!目前未考虑用户输入api正好是正确api的情况，默认全部是错误的响应
        # 收集主流webpack站点的正确/错误api响应 springboot 已处理
        #已处理 收集常见api 响应形式 例如：token不能为空
        # 分类设置不同的锚点  没有必要
        #todo 一个站可能有不同的根api对应不同功能
        rootUrl=getCleanUrl(origionUrl)
        apiNoneExistList=["/"+self.generate_random_string(12) for x in range(5)]
        apiNoneExistList+=[x+"/"+self.generate_random_string(12) for x in apiNoneExistList]
        apiNoneExistList+=[x+"/"+self.generate_random_string(12) for x in apiNoneExistList]
        apiNoneExistList+=[x+"/"+self.generate_random_string(12) for x in apiNoneExistList]
        urlNoneExistList=[rootUrl+api for api in apiNoneExistList]
        #增加origionUrl
        urlNoneExistList.append(origionUrl)
        #增加cleanUrl
        urlNoneExistList.append(getCleanUrl(origionUrl))
        print()
        print("Anchor in action")
        if DEBUG:
            print(f"总计锚点: {len(urlNoneExistList)} 个")
            # print(f"urlNoneExistList总计:: {len(urlNoneExistList)} 个")
            if Verbose:
                for line in urlNoneExistList:
                    print(line)
        # print()
        respList=[]
        threads=20#anchor threads 20
        self.taskUsingThread(self.getRespUsingRequests,mode,origionUrl,urlNoneExistList,respList,threads)
        if DEBUG and Verbose:
            print(f"respList: {respList}")
            print()
        # return urlNoneExistList
        #去除列表中重复的元素
        unique_list = list({tuple(sorted(d.items())): d for d in respList}.values())
        if DEBUG:
            print(f"过滤后，锚点总数: {len(unique_list)} 个")
            print(unique_list)
        return unique_list

    #二次验证实现 用于nofuzz模式实现
    def isApiValid(self,mode,origionUrl,inputApis,apiList,origionInputApis=[],noneApiPaths=[],anchorRespList=[]):
        """根据疑似api或输出的api，组合请求（少量数据包）判断是否是真实api
        #*返回{"inputApis":[inputApis],"validApis":[validApis],"suspiciousAPis":[suspiciousAPis]}
        Args:
            apiList (_type_): _description_
        """
        cleanUrl=getCleanUrl(origionUrl)
        if mode.replace("batch","").startswith("fuzz"):#fuzz模式
            inputApis=self.uniqRootImplement2(inputApis)
            mergeApis=self.inputApisMerge(inputApis,apiList)
        else:#api模式
            mergeApis=self.inputApisMerge(inputApis,apiList)
        mergeApisListWithTag=self.fastUniqDicList([{"url":url,"tag":"mergeApis","api":url} for url in mergeApis])
        fuzzingList=mergeApisListWithTag
        #去重
        if DEBUG:
            if "nofuzz" in mode:
                print(f"nofuzz:api总量: {len(fuzzingList)}")
            else:
                print(f"二次验证:api总量: {len(fuzzingList)}")
        fuzzingList=self.fastUniqListWithTagDicc(fuzzingList)

        # print(f"过滤去重:api总量: {len(fuzzingList)}")
        if "nofuzz" in mode:
            print(f"nofuzz:待测试:api总量: {len(fuzzingList)}")
        else:
            print(f"二次验证:待测试:api总量: {len(fuzzingList)}")
        #排除指定api
        if len(noneApiPaths)!=0:
            if DEBUG:
                print()
                print(f"排除指定api: {noneApiPaths}")
            fuzzingList=self.fastExcludeNoneApiFromListWithTagDicc(fuzzingList,noneApiPaths)
            print(f"排除指定api:api总量: {len(fuzzingList)}")
        random.shuffle(fuzzingList)#*全列表洗牌，2000 正确api数量大概5个，不需要优先顺序
        #排序 按照api长度
        # fuzzingList=sorted(fuzzingList, key=lambda item: len(item["api"]))
        fuzzingUrlList=fuzzingList.copy()
        for i in range(len(fuzzingUrlList)):#[{"url":url,"tag":"completeApi","api":api}]
            fuzzingUrlList[i]["url"]=cleanUrl+fuzzingUrlList[i]["url"]
        # 去重
        fuzzingUrlList=self.fastUniqDicList(fuzzingUrlList)
        start = 0
        end = 100
        step = 100
        count=0
        #! 未处理多次fuzz未获得有效api的情况，会发送超大量数据包
        while start < len(fuzzingUrlList):
            sublist = fuzzingUrlList[start:end]
            print()
            if "nofuzz" in mode:
                print(f"nofuzz:第 {count+1} 批次fuzz: 数量: {len(sublist)} 个")
            else:
                print(f"二次验证:第 {count+1} 批次fuzz: 数量: {len(sublist)} 个")
            respList=[]
            threads=100
            #sublist[{"url":url,"tag":"completeApi","api":api}]

            self.taskUsingThread(self.getRespWithTagUsingRequests,mode,origionUrl,sublist,respList,threads)
            apiSpottedList=[]
            if anchorRespList:
                for res in respList:#res的值{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title},"resp":resp,"tag":tag,"api":api}
                    #* 当前仅比较size
                    if res["status"]["code"] !=404 and not any(res["status"]["size"] == anchor["size"] for anchor in anchorRespList) and res["status"]["size"]!=0:#todo 这里有效api的size是有可能为0的
                        # if "application/json" in res["status"]["type"]:
                        if "json" in res["status"]["type"]:#*修复content-type库连锁问题
                            apiSpottedList.append(res)
            else:
                for res in respList:#res的值{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title},"resp":resp,"tag":tag,"api":api}
                    #* 当前仅比较size
                    if res["status"]["code"] !=404 and res["status"]["size"]!=0:#todo 这里有效api的size是有可能为0的
                        # if "application/json" in res["status"]["type"]:
                        if "json" in res["status"]["type"]:#启用contentType库
                            apiSpottedList.append(res)
            if len(apiSpottedList)!=0:#从这一批fuzz结果中发现
                print()
                apis=[]#url列表
                for api in apiSpottedList:#{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title},"resp":resp,"tag":tag}
                    if api["api"] not in apis:#从响应中获取独立api，从独立api定位tags，从tag定位url进行fuzz
                        apis.append(api["api"])
                print()
                validApis=self.uniqRootImplement2(apis)#有效api
                suspiciousApis=[]#疑似api
                if validApis:
                    print()
                    uniques = [item for item, count in Counter(apis).items() if count == 1]
                    uniqPaths= self.uniqPathWithNoCommonRoot(uniques)
                    if uniqPaths:
                        # print("疑似api:")
                        suspiciousApis=self.stairsSplitAndStitch(uniqPaths)
                        for api in suspiciousApis:
                            if api in uniqPaths:
                                suspiciousApis.pop(suspiciousApis.index(api))
                # 输出有效api
                # if "fuzz" not in mode:
                apiResult={"inputApis":inputApis,"validApis":validApis,"suspiciousAPis":suspiciousApis}
                #兼容指纹识别传入api进行二次验证
                if origionInputApis:
                    apiResult["inputApis"]=origionInputApis
                # else:
                #     inputApis=[]
                #     apiResult={"inputApis":inputApis,"validApis":validApis,"suspiciousAPis":suspiciousApis}
                if apiResult["validApis"]:
                    if not mode.replace("batch","").startswith("fuzz"):
                        print(f"输入api: {apiResult['inputApis']}")
                    else:
                        print(f"输入api: fuzz模式无输入api")
                    print(f"识别api: {apiResult['validApis']}")
                    print(f"疑似api: {apiResult['suspiciousAPis']}")
                else:
                    if "nofuzz" in mode:
                        print("nofuzz: 未识别到有效api")
                    else:
                        print("二次验证: 未识别到有效api")
                return apiResult
                # break#*不继续进行fuzz，此处未考虑多个根api情况
                #todo 排除已发现有效api进行二次测试，确定是否存在多个根api未被发现
            else:
                start = end
                end += step
                count+=1
        if len(apiSpottedList)==0:
            if "nofuzz" in mode:
                print(f"nofuzz: fuzz结束，未发现有效api")
            else:
                print(f"二次验证: fuzz结束，未发现有效api")
            return
    #二次锚点
    def getApiWithoutTokenAnchor(self,fuzzRespList):
        """获取正确api后 第二次锚点 用于去除需要认证的api
        #fuzzResultList的值{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title},"resp":resp,"tag":tag,"api":api}
        #*定位未授权api 响应大小
        Args:
            fuzzrespList (_type_): _description_
        """
        #todo 未考虑状态码 仅处理size
        #todo 未考虑 500时 响应中包含api的情况 会导致响应变化 可以考虑范围值 但是会增加误判
        #todo 需要拟合函数 解决这里的锚点判断问题 输出异常值、屏蔽无效/常规值
        #todo 考虑极端情况 无效api不是最多值的情况，直接从中间值排除大于中间值的情况，然后逼近无效锚点
        anchorList={"small":None,"big":None}
        if fuzzRespList:
            tmp=[x["status"]["size"] for x in fuzzRespList]
        else:
            return
        #取其中出现最多的值 而且响应体 < 250 查看多个404/500/401响应估值250
        counted = Counter(tmp)
        most_common = counted.most_common(1)
        medium=most_common[0][0]
        if medium < 250:
            anchorList["small"]=medium-35
            anchorList["big"]=medium+35
            # anchorList["small"]=medium-20
            # anchorList["big"]=medium+20
        if anchorList:
            if DEBUG:
                print(f"二次锚点: {anchorList}")
            return anchorList
        else:
            return

    def getRightInterfaceFromWrong():
        """获取有效api，暂未启用
        """
        #todo 使用一系列不存在的api请求，获得锚点，必须包含多层级不存在api 例如/apiiiii和/apiiiii/interface
        #todo 访问初始url，获得基础锚点
        #todo 逐级访问初始url的api层级获得锚点
        #todo 考虑前端不会自动转发接口请求到后端的情况，需要手动输入后端API接口地址
        pass

    #任务调度
    def singleApiFuzzInAction(self,mode,origionUrl,noneApis):
        # urlList=getJsWithoutPaperWork(origionUrl)
        # #*爬取origionurl和cleanurl
        # cleanurl=getCleanUrl(origionUrl)
        # if cleanurl!=origionUrl.strip("/"):
        #     urlList+=getJsWithoutPaperWork(cleanurl)
        global configdomainurlroot
        urlList=getParseJsFromUrl(origionUrl)
        # if len(urlList)==0:
        if not urlList:
            # sys.exit("爬取结果为空")
            print("爬取结果为空")
            return
        #去除危险接口
        urlList=removeDangerousApi(urlList)
        apiList=getApiFromUrlList(origionUrl,urlList)
        myFuzz=apiFuzz()
        singlestatus=myFuzz.apiFuzzInAction(mode,origionUrl,apiList,noneApis)
        configdomainurlroot=[]#单次结束置空
        if DEBUG:
            print(f"单fuzz:发包次数: {len(countspider)} 次")
        return singlestatus
    # batch模式下增加结果统计
    def batchApiFuzzInAction(self,mode,urlList,noneApis):
        batchTaskStatus=[]#批量任务状态统计
        for url in urlList:
            print()
            print(f"处理URL: {url}")
            singlestatus=self.singleApiFuzzInAction(mode,url,noneApis)
            if singlestatus:
                batchTaskStatus.append(singlestatus)
            else:
                singlestatus={"target":url,"juicyApiList":[],"sensitivInfoList":[],"sensitiveFileList":[],"apiFigureout":{"inputApis":[],"validApis":[],"suspiciousAPis":[]},"fingerprint":[],"tag":"default","dead":"dead"}
                batchTaskStatus.append(singlestatus)
        #输出批任务状态
        self.batchTaskStatusOutput(mode,batchTaskStatus)
        # #*[{"target":origionUrl,"juicyApiList":juicyApiList,"sensitivInfoList":sensitivInfoList,"sensitiveFileList":sensitiveFileList,"apiFigureout":{"validApis":validApis,"suspiciousApis":suspiciousApis},"fingerprint":[{"url":url,"tag":"fingerprint","api":api}]}]
        if DEBUG:
            print(f"批fuzz:发包次数: {len(countspider)} 次")
    #批处理任务状态输出
    def batchTaskStatusOutput(self,mode,batchTaskStatus):
        #输出批任务状态
        #*返回#{"target":origionUrl,"juicyApiList":juicyApiList,"sensitivInfoList":sensitivInfoList,"sensitiveFileList":sensitiveFileList,"apiFigureout":{"inputApis":[inputApis],"validApis":[validApis],"suspiciousAPis":[suspiciousAPis]},"fingerprint":[{"url":url,"tag":"fingerprint","api":api}],"tag":"default","dead":"alive"}
        print()
        print()
        print(f"多任务结果:")
        #todo 统一结果输出中的内容
        for status in batchTaskStatus:
            print(f"目标: {status['target']}")
            if status["dead"]=="alive":
                if status["juicyApiList"]:
                        print()
                        print(f"发现敏感接口如下(不包含危险接口): {len(status['juicyApiList'])} 个")
                        for info in status["juicyApiList"]:
                            print(f"[{info['desc']}]: 命中次数: {info['count']} 状态码: [{info['code']}] 响应大小: [{info['size']}] type: [{info['type']}] url: {info['url']} api: {info['api']}")
                #敏感文件发现
                #返回 [{'url': 'url', 'api': 'api', 'tag': 'xlsx', 'desc': 'xlsx', 'count': 1}]
                # suspiciousFiles=self.getSuspiciousFileFromFuzzResult(fuzzResultList)
                if status["sensitiveFileList"]:
                    print()
                    print(f"发现疑似敏感文件如下:")
                    for info in status["sensitiveFileList"]:
                        print(f"[{info['desc']}]: 命中次数: {info['count']} 状态码: [{info['code']}] 响应大小: [{info['size']}] type: [{info['type']}] url: {info['url']} api: {info['api']}")
                else:
                    if DEBUG:
                        print()
                        print(f"未发现敏感文件")
                #敏感信息输出
                #todo 转移到apiFuzzInAction中输出
                if status["sensitivInfoList"]:
                    print()
                    print("敏感信息发现如下:")
                    for info in status["sensitivInfoList"]:
                        print(f"[{info['desc']}]: 命中次数: {info['count']} 状态码: [{info['code']}] 响应大小: [{info['size']}] type: [{info['type']}] url: {info['url']} api: {info['api']}")
                else:
                    if DEBUG:
                        print()
                        print("未发现敏感信息")
                #接口输出
                print()
                print("接口识别结果")
                if status["apiFigureout"]["validApis"]:
                        if not mode.replace("batch","").startswith("fuzz"):
                            print(f"输入api: {status['apiFigureout']['inputApis']}")
                        else:
                            print(f"输入api: fuzz模式无输入api")
                        print(f"识别api: {status['apiFigureout']['validApis']}")
                        print(f"疑似api: {status['apiFigureout']['suspiciousAPis']}")
                else:
                    print("未识别到有效api")
                print()
                if status["fingerprint"]:
                    for finger in status["fingerprint"]:
                            print(f"命中api: {finger['api']} 命中指纹: {finger['tag']} 命中url: {finger['url']}")
                print()
                print()
            else:
                print(f"未发现有效api")
                print()
    #*apiFuzzInAction 加入指纹识别后 重新启用
    def apiFuzzInAction(self,mode,origionUrl,apiFuzzList,noneApis):
        """优先指纹识别，失败则进行fuzz
        #*返回#{"target":origionUrl,"juicyApiList":juicyApiList,"sensitivInfoList":sensitivInfoList,"sensitiveFileList":sensitiveFileList,"apiFigureout":{"inputApis":[inputApis],"validApis":[validApis],"suspiciousAPis":[suspiciousAPis]},"fingerprint":[{"url":url,"tag":"fingerprint","api":api}],"tag":"default","dead":"alive"}

        Args:
            apiList (_type_): _description_
        """
        print()
        # print("Fuzzing in action")
        #[{"url":url,"tag":"completeApi","api":api}]
        #*返回#{"target":origionUrl,"juicyApiList":[],"sensitivInfoList":[],"sensitiveFileList":[],"apiFigureout":{"inputApis":[],"validApis":[],"suspiciousAPis":[]},"fingerprint":[],"tag":"default","dead":"alive"}
        singlestatus={"target":origionUrl,"juicyApiList":[],"sensitivInfoList":[],"sensitiveFileList":[],"apiFigureout":{"inputApis":[],"validApis":[],"suspiciousAPis":[]},"fingerprint":[],"tag":"default","dead":"alive"}
        # if configdomainurlroot:#爬取根识别
        #     configroot=configdomainurlroot[0]
        #     print(f"识别到网站配置根: {configroot}, 进行指纹识别")
        #     pulses=self.feelPulse(mode,origionUrl,[configroot],noneApis)
        #     if DEBUG:
        #         if pulses:
        #             print(f"配置根识别成功: {configroot}")
        #         else:
        #             print(f"配置根未识别成功,进行常规指纹识别")
        #     if not pulses:
        #         pulses=self.feelPulse(mode,origionUrl,apiFuzzList,noneApis)
        # else:
        #     pulses=self.feelPulse(mode,origionUrl,apiFuzzList,noneApis)
        pulses=self.feelPulse(mode,origionUrl,apiFuzzList,noneApis)
        # pulses=None
        if pulses:
            # anchorRespList=[]
            anchorRespList=self.getAnchorResponse(mode,origionUrl,10)
            if "nofuzz" not in mode:#nofuzz实现
                #组合有效api
                validApis=[x["api"] for x in pulses]
                print(f"根据指纹命中api进行结果获取: {validApis}")
                #todo 响应信息增加指纹信息
                #todo 用户输入实施指纹识别和二次验证之后 需要修正这里的逻辑，避免二次指纹验证
                singlestatus=self.apiFuzzForUserInputApiInAction(mode,origionUrl,validApis,apiFuzzList,anchorRespList)
                singlestatus["fingerprint"]=pulses
                #输出命中指纹信息
                if DEBUG:
                    print()
                    for pulse in pulses:
                        print(f"命中api: {pulse['api']} 命中指纹: {pulse['tag']} 命中url: {pulse['url']}")
                else:
                    print()
                    for pulse in pulses:
                        print(f"命中api: {pulse['api']} 命中指纹: {pulse['tag']} 命中url: {pulse['url']}")
            else:
                apidiccs={"inputApis":[],"validApis":[],"suspiciousAPis":[]}
                for pulse in pulses:
                    #{"inputApis":[inputApis],"validApis":[validApis],"suspiciousAPis":[suspiciousAPis]}
                    apidicc=self.isApiValid(mode,origionUrl,[pulse['api']],apiFuzzList,[],noneApis,anchorRespList)
                    if apidicc:
                        apidiccs["inputApis"]+=apidicc["inputApis"]
                        apidiccs["validApis"]+=apidicc["validApis"]
                        apidiccs["suspiciousAPis"]+=apidicc["suspiciousAPis"]
                #nofuzz 状态输出实现
                #*返回#{"target":origionUrl,"juicyApiList":juicyApiList,"sensitivInfoList":sensitivInfoList,"sensitiveFileList":sensitiveFileList,"apiFigureout":{"inputApis":[inputApis],"validApis":[validApis],"suspiciousAPis":[suspiciousAPis]},"fingerprint":[{"url":url,"tag":"fingerprint","api":api}],"tag":"nofuzz"}
                singlestatus["tag"]="nofuzz"
                singlestatus["target"]=origionUrl
                singlestatus["apiFigureout"]=apidiccs
                singlestatus["fingerprint"]=pulses
                #输出命中指纹信息
                if DEBUG:
                    print()
                    for pulse in pulses:
                        print(f"命中api: {pulse['api']} 命中指纹: {pulse['tag']} 命中url: {pulse['url']}")
                else:
                    print()
                    for pulse in pulses:
                        print(f"命中api: {pulse['api']} 命中指纹: {pulse['tag']} 命中url: {pulse['url']}")
        else:
            print(f"指纹未识别到有效api，进行fuzz")
            anchorRespList=self.getAnchorResponse(mode,origionUrl)
            #*返回#{"target":origionUrl,"juicyApiList":juicyApiList,"sensitivInfoList":sensitivInfoList,"sensitiveFileList":sensitiveFileList,"apiFigureout":{"inputApis":[inputApis],"validApis":[validApis],"suspiciousAPis":[suspiciousAPis]},"fingerprint":[{"url":url,"tag":"fingerprint","api":api}],"tag":"default","dead":"alive"}
            tmp=self.genTestUrlBatchFromMassList(mode,origionUrl,apiFuzzList,anchorRespList,noneApis)
            if tmp:
                singlestatus=tmp
            else:
                singlestatus["dead"]="dead"
        return singlestatus
    #用户输入
    #todo 用户输入 实施二次验证有效api 不打算实施但需要实施？以免输入为疑似api的情况
    def apiFuzzForUserInputApiInAction(self,mode,origionUrl,apiPaths,apiFuzzList,anchorRespList=[],threads=200):
        """根据生成的api接口列表调用httpx进行请求

        Args:
            apiList (_type_): _description_
        """
        #*返回#{"target":origionUrl,"juicyApiList":juicyApiList,"sensitivInfoList":sensitivInfoList,"sensitiveFileList":sensitiveFileList,"apiFigureout":{"inputApis":[inputApis],"validApis":[validApis],"suspiciousAPis":[suspiciousAPis]},"fingerprint":[{"url":url,"tag":"fingerprint","api":api}],"tag":"default","dead","alive"}
        singlestatus={"target":origionUrl,"juicyApiList":[],"sensitivInfoList":[],"sensitiveFileList":[],"apiFigureout":{"inputApis":[],"validApis":[],"suspiciousAPis":[]},"fingerprint":[],"tag":"default","dead":"alive"}
        print()
        #前后端分离情况的后端地址输入实现 不考虑输入多个不同IP的情况
        tmpinputapipaths=apiPaths.copy()
        for i in range(len(tmpinputapipaths)):
            if isUrlValid(tmpinputapipaths[i]):
                origionUrl=tmpinputapipaths[i]
                cleanurl=getCleanUrl(origionUrl)
                tmpinputapipaths[i]=tmpinputapipaths[i].replace(cleanurl,"")
        if "nofuzz" not in mode:
            #*[{"url":url,"tag":"fingerprint","api":api}]
            # 这里没有考虑用户输入为url形式的api
            #! 对用户输入进行指纹识别或二次验证，但用户输入会覆盖指纹识别和二次验证结果
            if not mode.replace("batch","").startswith("fuzz"):#兼容fuzz模式指纹识别成功
                pulses=self.feelPulse(mode,origionUrl,tmpinputapipaths)
                #适配配置根识别模式
                # if configdomainurlroot:#爬取根识别
                #     configroot=configdomainurlroot[0]
                #     print(f"识别到网站配置根: {configroot}, 进行指纹识别")
                #     pulses=self.feelPulse(mode,origionUrl,[configroot])
                #     if DEBUG:
                #         if pulses:
                #             print(f"配置根识别成功: {configroot}")
                #         else:
                #             print(f"配置根未识别成功,进行常规指纹识别")
                #     if not pulses:
                #         pulses=self.feelPulse(mode,origionUrl,tmpinputapipaths)
                # else:
                #     pulses=self.feelPulse(mode,origionUrl,tmpinputapipaths)

                # pulses=self.feelPulse(mode,origionUrl,tmpinputapipaths)
                if pulses:#指纹识别
                    tmpinputapipaths+=[x["api"] for x in pulses]
                    # tmpinputapipaths=self.fastUniqList(tmpinputapipaths)

                #* 用户输入有可能是一个大概的范围，不是准确api，因此实施二次验证
                else:#二次验证
                    #用户输入模式，不获取锚点响应进行匹配，可能需要优化
                    #*返回{"inputApis":[inputApis],"validApis":[validApis],"suspiciousAPis":[suspiciousAPis]}
                    valid=self.isApiValid(mode,origionUrl,tmpinputapipaths,apiFuzzList,apiPaths)
                    if valid:
                        tmpinputapipaths+=valid["validApis"]+valid["suspiciousAPis"]
                        # tmpinputapipaths=self.fastUniqList(tmpinputapipaths)
            cleanurl=getCleanUrl(origionUrl)
            for i in range(len(tmpinputapipaths)):
                if not isUrlValid(tmpinputapipaths[i]):
                    tmpinputapipaths[i]=cleanurl+"/"+tmpinputapipaths[i].strip("/")
            tmpinputapipaths=self.fastUniqList(tmpinputapipaths)
            if DEBUG:
                print(f"待处理api {len(tmpinputapipaths)} 个:")
                for i in tmpinputapipaths:
                    print(i)
            mydicc={}
            for url in tmpinputapipaths:
                for api in apiFuzzList:
                    #需要处理/jeecg/jeecg/sys/list 的问题 排除相同根
                    mydicc[url.rstrip("/")+api]=None#api一定存在开始的/，不用额外处理
            urlFuzzList=list(mydicc.keys())
            if DEBUG:
                print(f"指定api待处理数量: {len(urlFuzzList)}")
                for x in urlFuzzList:
                    if "jeecg-boothttp:" in x:
                        print(f"----<x>----{x}")

            filename=".js_fuzz_url.txt"
            writeLinesIntoFile(urlFuzzList,filename)
            #httpx有bug，不会请求完 可能行数太多？7w+行，只请求了前1k+左右的数量就停止

            if DEBUG:
                print(f"fuzz目标总数: {len(urlFuzzList)}")
            #todo 测试中 大量的访问会导致后续访问全部timeout
            singlestatus=self.taskUsingThread(self.getFuzzUrlResultUsingRequests,mode,origionUrl,urlFuzzList,anchorRespList,threads)
            # singlestatus["apiFigureout"]["inputApis"]=[x.replace(cleanurl,"") for x in apiPaths]
            # return singlestatus
            try:
                if valid:
                    singlestatus["apiFigureout"]=valid
            except:
                pass
            try:
                if pulses:
                    singlestatus["fingerprint"]=pulses
                    print()
                    for pulse in pulses:
                        print(f"命中api: {pulse['api']} 命中指纹: {pulse['tag']} 命中url: {pulse['url']}")
            except:
                pass
        else:
            noneApiPaths=[]
            pulses=self.feelPulse(mode,origionUrl,tmpinputapipaths)
            #适配配置根识别模式
            # if configdomainurlroot:#爬取根识别
            #     configroot=configdomainurlroot[0]
            #     print(f"识别到网站配置根: {configroot}, 进行指纹识别")
            #     pulses=self.feelPulse(mode,origionUrl,[configroot])
            #     if DEBUG:
            #         if pulses:
            #             print(f"配置根识别成功: {configroot}")
            #         else:
            #             print(f"配置根未识别成功,进行常规指纹识别")
            #     if not pulses:
            #         pulses=self.feelPulse(mode,origionUrl,tmpinputapipaths)
            # else:
            #     pulses=self.feelPulse(mode,origionUrl,tmpinputapipaths)
            
            #*[{"url":url,"tag":"fingerprint","api":api}]
            # pulses=self.feelPulse(mode,origionUrl,tmpinputapipaths)
            if pulses:
                apidiccs={"inputApis":[],"validApis":[],"suspiciousAPis":[]}
                for pulse in pulses:
                    #{"inputApis":[inputApis],"validApis":[validApis],"suspiciousAPis":[suspiciousAPis]}
                    apidicc=self.isApiValid(mode,origionUrl,[pulse['api']],apiFuzzList,apiPaths)
                    if apidicc:
                        apidiccs["inputApis"]+=apidicc["inputApis"]
                        apidiccs["validApis"]+=apidicc["validApis"]
                        apidiccs["suspiciousAPis"]+=apidicc["suspiciousAPis"]
                #nofuzz 状态输出实现
                #*返回#{"target":origionUrl,"juicyApiList":juicyApiList,"sensitivInfoList":sensitivInfoList,"sensitiveFileList":sensitiveFileList,"apiFigureout":{"inputApis":[inputApis],"validApis":[validApis],"suspiciousAPis":[suspiciousAPis]},"fingerprint":[{"url":url,"tag":"fingerprint","api":api}],"tag":"nofuzz"}
                singlestatus["tag"]="nofuzz"
                singlestatus["target"]=origionUrl
                singlestatus["apiFigureout"]=apidiccs
                singlestatus["fingerprint"]=pulses
                #*兼容api模式，修改inputApis为输入的api
                singlestatus["apiFigureout"]["inputApis"]=tmpinputapipaths
                #输出命中指纹信息
                print()
                for pulse in pulses:
                    print(f"命中api: {pulse['api']} 命中指纹: {pulse['tag']} 命中url: {pulse['url']}")
            else:
                #*返回{"inputApis":[inputApis],"validApis":[validApis],"suspiciousAPis":[suspiciousAPis]}
                apidicc=self.isApiValid(mode,origionUrl,tmpinputapipaths,apiFuzzList,apiPaths,noneApiPaths,anchorRespList)
                #{"target":origionUrl,"juicyApiList":juicyApiList,"sensitivInfoList":sensitivInfoList,"sensitiveFileList":sensitiveFileList,"apiFigureout":{"inputApis":[inputApis],"validApis":[validApis],"suspiciousAPis":[suspiciousAPis]},"fingerprint":[],"tag":"nofuzz"}
                # print(singlestatus)
                if apidicc:
                    singlestatus["tag"]="nofuzz"
                    singlestatus["target"]=origionUrl
                    singlestatus["apiFigureout"]=apidicc
                else:
                    singlestatus["dead"]="dead"
                    # print(f"{mode}: 未发现有效api")
            # print(f"debuuuuuuuuging-------------->: {singlestatus['apiFigureout']}")
            # return singlestatus
            # if apidicc:
            #     print(f"输入api: {apidicc['inputApis']}")
            #     print(f"识别api: {apidicc['validApis']}")
            #     print(f"疑似api: {apidicc['suspiciousAPis']}")
            # else:
            #     print("nofuzz: 未识别到有效api")
        return singlestatus
    #多线程任务发布
    def taskUsingThread(self,Method,mode,origionUrl,apiFuzzList,anchorRespList=[],threads=10,taskStatusCount=[]):
        #*返回#{"target":origionUrl,"juicyApiList":juicyApiList,"sensitivInfoList":sensitivInfoList,"sensitiveFileList":sensitiveFileList,"apiFigureout":{"inputApis":[inputApis],"validApis":[validApis],"suspiciousAPis":[suspiciousAPis]},"fingerprint":[{"url":url,"tag":"fingerprint","api":api}],"tag":"default","dead":"alive"}
        # 创建线程池对象
        print("Fuzzing in action")
        if DEBUG:
            threads=300
            print(f"debugging threads: {threads}")
        else:
            print(f"threads: {threads}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            # 向线程池提交任务
            futures = []
            # for url in apiFuzzList:
            pbar=tqdm(total=len(apiFuzzList),desc="fuzz进度",unit="个")#进度条显示
            #敏感文件发现
            #返回 [{"url": "url", "api": "api", "tag": "xlsx", "desc": "xlsx","code":"code","size":"size","count": 1}]
            # sensitiveFileList=[]
            #响应结果集
            fuzzResultList=[]
            #结果统计
            statusCount={"rightCount":[],"outputBodyCount":[],"timeoutCount":[],"connectErrorCount":[],"connectResetCount":[],"blockCount":[]}
            for url in apiFuzzList:
                # f = executor.submit(Method,url,pbar,anchorRespList,timeoutCount,connectErrorCount)
                if Method==self.getFuzzUrlResultUsingRequests:
                    # f = executor.submit(Method,mode,url,pbar,anchorRespList,timeoutCount,connectErrorCount,rightCount,outputBodyCount,connectResetCount,blockCount)
                    f = executor.submit(Method,mode,url,pbar,fuzzResultList,anchorRespList,statusCount)
                elif Method==self.universalGetRespWithTagUsingRequests:
                    f=executor.submit(Method,url,pbar,fuzzResultList,statusCount)
                else:
                    # f = executor.submit(Method,url,pbar,anchorRespList,timeoutCount,connectErrorCount,rightCount,outputBodyCount,connectResetCount,blockCount)
                    f = executor.submit(Method,url,pbar,anchorRespList,statusCount)
                # f = executor.submit(Method,url,pbar,q)
                futures.append(f)
            # 等待所有任务执行完毕
            for f in concurrent.futures.as_completed(futures):
                f.result()
            pbar.close()#结束进度条
            # print(f"总请求: {len(apiFuzzList)}, 错误总数: {timeoutCount+connectErrorCount}, 超时数量: {timeoutCount}, 连接错误: {connectErrorCount}")
            wrongCount=statusCount["timeoutCount"]+statusCount["connectErrorCount"]+statusCount["connectResetCount"]
            # print(f"总请求: {len(apiFuzzList)} 响应次数: {len(rightCount)} 输出次数: {len(outputBodyCount)} 错误总数: {len(wrongCount)} connection reset数量: {len(connectResetCount)} 超时数量: {len(timeoutCount)}  连接错误: {len(connectErrorCount)}")
            # print(f"总请求: {len(apiFuzzList)} 响应次数: {len(rightCount)} 输出次数: {len(outputBodyCount)} 屏蔽次数: {len(blockCount)} 错误总数: {len(wrongCount)} connection reset数量: {len(connectResetCount)} 超时数量: {len(timeoutCount)}  连接错误: {len(connectErrorCount)}")
            print(f"总请求:{len(apiFuzzList)} 屏蔽:{len(statusCount['blockCount'])} 命中:{len(statusCount['rightCount'])} 输出:{len(statusCount['outputBodyCount'])} 错误:{len(wrongCount)} connection reset:{len(statusCount['connectResetCount'])} 超时:{len(statusCount['timeoutCount'])}  连接错误:{len(statusCount['connectErrorCount'])}")
            #! 存在识别到有效api后 fuzz结果时 网站不稳定导致有效api全部访问出错导致有效api判断失败
            if Method==self.getFuzzUrlResultUsingRequests:
                #* 其他Method也有可能传入apiList为字典，只能在这里判断敏感端口
                #敏感端口发现 从fuzzResultList
                #返回[{"url": "url", "api": "api", "tag": "upload", "desc": "upload","code":"code","size":"size","count": 1}]
                anchors=self.getApiWithoutTokenAnchor(fuzzResultList)
                juicyApiList=self.getSuspiciousApiFromFuzzResult(anchors,fuzzResultList)
                #敏感信息发现
                #返回 [{"url": "url", "api": "api", "tag": "idcard", "desc": "身份证","code":"code","size":"size", "count": 1}]
                sensitivInfoList=self.getWonderfulRespFromFuzzResult(fuzzResultList)
                #敏感文件发现
                #返回 [{"url": "url", "api": "api", "tag": "xlsx", "desc": "xlsx","code":"code","size":"size","count": 1}]
                sensitiveFileList=self.getSuspiciousFileFromFuzzResult(fuzzResultList)
                #敏感接口输出
                if juicyApiList:
                    print()
                    print(f"发现敏感接口如下(不包含危险接口): {len(juicyApiList)} 个")
                    for info in juicyApiList:
                        print(f"[{info['desc']}]: 命中次数: {info['count']} 状态码: [{info['code']}] 响应大小: [{info['size']}] type: [{info['type']}] url: {info['url']} api: {info['api']}")
                else:
                    # if DEBUG:
                    print()
                    print("未发现敏感接口")
                #敏感文件发现
                #返回 [{'url': 'url', 'api': 'api', 'tag': 'xlsx', 'desc': 'xlsx', 'count': 1}]
                # suspiciousFiles=self.getSuspiciousFileFromFuzzResult(fuzzResultList)
                if sensitiveFileList:
                    print()
                    print(f"发现疑似敏感文件如下:")
                    for info in sensitiveFileList:
                        print(f"[{info['desc']}]: 命中次数: {info['count']} 状态码: [{info['code']}] 响应大小: [{info['size']}] type: [{info['type']}] url: {info['url']} api: {info['api']}")
                else:
                    # if DEBUG:
                    print()
                    print(f"未发现敏感文件")
                #敏感信息输出
                #todo 转移到apiFuzzInAction中输出
                #返回 [{"url": "url", "api": "api", "tag": "idcard", "desc": "身份证","code":"code","size":"size", "count": 1}]
                if sensitivInfoList:
                    print()
                    print("敏感信息发现如下:")
                    for info in sensitivInfoList:
                        print(f"[{info['desc']}]: 命中次数: {info['count']} 状态码: [{info['code']}] 响应大小: [{info['size']}] type: [{info['type']}] url: {info['url']} api: {info['api']}")
                else:
                    # if DEBUG:
                    print()
                    print("未发现敏感信息")
                #有效api输出
                cleanurl=getCleanUrl(origionUrl)
                statusCount['rightCount']=[x.replace(cleanurl,"") for x in statusCount['rightCount']]
                validApis=statusCount['rightCount']
                validApis=self.uniqRootImplement2(validApis)#有效api
                suspiciousApis=[]#疑似api
                if validApis:
                    print()
                    print("有效api:")
                    for api in validApis:
                        print(api)
                    uniques = [item for item, count in Counter(statusCount['rightCount']).items() if count == 1]
                    uniqPaths= self.uniqPathWithNoCommonRoot(uniques)
                    if uniqPaths:
                        print("疑似api:")
                        suspiciousApis=self.stairsSplitAndStitch(uniqPaths)
                        for api in suspiciousApis:
                            if api in uniqPaths:
                                suspiciousApis.pop(suspiciousApis.index(api))
                        for api in suspiciousApis:
                            print(api)
                else:
                    print()
                    print(f"未发现有效api")
                #任务结果统计
                #*返回#{"target":origionUrl,"juicyApiList":juicyApiList,"sensitivInfoList":sensitivInfoList,"sensitiveFileList":sensitiveFileList,"apiFigureout":{"inputApis":[inputApis],"validApis":[validApis],"suspiciousAPis":[suspiciousAPis]},"fingerprint":[{"url":url,"tag":"fingerprint","api":api}],"tag":"default"}
                #! 键值大小写让我掉泪
                taskStatusCount={"target":origionUrl,"juicyApiList":juicyApiList,"sensitivInfoList":sensitivInfoList,"sensitiveFileList":sensitiveFileList,"apiFigureout":{"inputApis":[],"validApis":validApis,"suspiciousAPis":suspiciousApis},"fingerprint":[],"tag":"default","dead":"alive"}
                if not validApis:
                    taskStatusCount["dead"]="dead"
                return taskStatusCount
            elif Method==self.universalGetRespWithTagUsingRequests:
                return fuzzResultList
        return
    def getFuzzUrlResultUsingRequests(self,mode,url,pbar,fuzzResultList=[],anchorRespList=[],statusCount={}):
        """此函苏用于获取单url fuzz结果 通过锚定结果列表 判断正确api 过滤输出
        httpx有大病，用requests加多线程完成这里的匹配
        #* json响应会输出
        #* html响应会屏蔽
        这个函数用在获取api后的最终fuzz并输出json body
        #* fuzzResultList的值{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title},"resp":resp,"tag":tag,"api":api}
        #*敏感信息[{'url': 'url', 'api': 'api', 'tag': 'idcard', 'desc': '身份证', 'count': 1}]
        """
        countspider.append(1)#统计发包次数
        if "nobody" in mode:#禁用body输出
            noOutput=True
        else:
            noOutput=False
        #todo 增加randomAgent
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36",
            "Accept-Charset": "utf-8",
            "Accept": "",
        }
        try:
            #todo 这里没有处理响应超大的情况
            #todo 处理url为下载二进制等大型文件的情况 屏蔽？exe mp4 mp3等内容 融合在危险端口判断内
            resp=requests.get(url,headers=headers,timeout=(5,10), verify=False)#请求/读取超时5,10s，增大读取超时，有些响应很慢
            #todo 增加颜色输出
            try:
                code=resp.status_code
            except:
                code=0
            try:
                content_size = len(resp.content)
            except:
                content_size = 0
            try:#防止返回body为空或者没有title关键字，例如springboot404
                page_title = resp.text.split('<title>')[1].split('</title>')[0]
            except:
                page_title=""
            try:
                contentType=resp.headers['content-type']
                for type in contentTypeList:
                    if type["key"] in contentType:
                        contentType=type["tag"]
            except:#resp出错或响应中无content-type，跳过打印body和屏蔽html
                contentType=""
            respstatus={"code":code,"size":content_size,"type":contentType,"title":page_title}
            cleanurl=getCleanUrl(url)
            api=url.replace(cleanurl,"")
            # fuzzResultList.append({"url":url,"status":respstatus,"resp":resp,"tag":"default","api":api})
            #===============
            # content_size = len(resp.content)
            # try:#防止返回body为空或者没有title关键字，例如springboot404
            #     page_title = resp.text.split('<title>')[1].split('</title>')[0]
            # except:
            #     page_title=""
            # #todo 增加颜色输出
            # try:
            #     contentType=resp.headers['content-type']
            # except:#resp出错或响应中无content-type，跳过打印body和屏蔽html
            #     contentType=""
            # respstatus={"code":resp.status_code,"size":content_size,"type":contentType,"title":page_title}
            # if respstatus["code"]!=404 and "text/html" not in respstatus["type"]:#屏蔽html响应
            if respstatus["code"]!=404 and "html" not in respstatus["type"]:#*修复content-type库连锁问题
                #todo 增加智能识别常见响应文件类型，简化content-type输出
                #todo 通过accept字段控制resp中的content-type，不加控制
                #todo 会有不同的响应content-type内容
                #*对比锚定响应，过滤输出，size不同时输出
                # isDiff=True if respstatus["size"] in anchorRespList.values() else False
                isDiff=True
                if len(anchorRespList)!=0:#*指纹识别模式不需要锚点匹配
                    for x in anchorRespList:#屏蔽锚点响应
                        if x["size"]==respstatus["size"]:
                            isDiff=False
                            statusCount["blockCount"].append(1)
                            if DEBUG:
                                if len(statusCount["blockCount"])%10==0:
                                    print(f"屏蔽 {len(statusCount['blockCount'])} 次: {url}")
                            break
                if isDiff:
                    # 即使是上下的关系，在多线程情况下也会被插队输出，导致不同步 已处理
                    statusCount["rightCount"].append(url)
                    #响应结果附加
                    respdicc={"url":url,"status":respstatus,"resp":resp,"tag":"default","api":api}
                    fuzzResultList.append(respdicc)
                    #敏感文件匹配
                    #返回 [{"url": "url", "api": "api", "tag": "xlsx", "desc": "xlsx","code":"code","size":"size","count": 1}]
                    # infos=self.getSuspiciousFileFromRespdicc(respdicc)
                    # if infos:
                    #     sensitiveFileList+=infos
                    printer=jsonRespOutput(resp,respstatus)#打印json响应,判断是否是json
                    if printer:
                        statusCount["outputBodyCount"].append(1)
                        #开头留一个空格，防止与进度条重合，无法双击复制
                        if not noOutput:
                            print(f" {url} : [{respstatus['code']}] [{respstatus['size']}] [{respstatus['type']}] [{respstatus['title']}]\n{printer}")
                    else:
                        if not noOutput:
                            print(f" {url} : [{respstatus['code']}] [{respstatus['size']}] [{respstatus['type']}] [{respstatus['title']}]")
            else:
                statusCount["blockCount"].append(1)
                if DEBUG:
                    if len(statusCount["blockCount"])%10==0:
                        print(f"屏蔽 {len(statusCount['blockCount'])} 次: {url}")
            # if resp.status_code!=404 :
            #     print(f"{url} : [{resp.status_code}] [{content_size}] [] [{page_title}]")
        except requests.exceptions.Timeout as e:
            # timeoutCount+=1
            statusCount["timeoutCount"].append(1)
            if DEBUG:
                if len(statusCount["timeoutCount"])%10==0:
                    print(f"TIMEOUT {len(statusCount['timeoutCount'])} : {url}")
        except requests.exceptions.ConnectionError as e:
            try:
                if "Connection reset by peer" in e:
                    statusCount["connectResetCount"].append(1)
                    if DEBUG:
                        if len(statusCount["connectResetCount"])%10==0:
                            print(f"Connection reset {len(statusCount['connectResetCount'])} : {url}")
                else:
                    statusCount["connectErrorCount"].append(1)
                    if DEBUG:
                        if len(statusCount["connectErrorCount"])%10==0:
                            print(f"Connection error occurred {len(statusCount['connectErrorCount'])} : {url}")
            except:
                statusCount["connectErrorCount"].append(1)
                if DEBUG:
                    if len(statusCount["connectErrorCount"])%10==0:
                        print(f"Connection error occurred {len(statusCount['connectErrorCount'])} : {url}")
        except requests.exceptions.RequestException as e:
            statusCount["connectErrorCount"].append(1)
            if DEBUG:
                # print(f"{url} : 错误信息:  {e}")
                if len(statusCount["connectErrorCount"])%10==0:
                    print(f"其他连接错误 {len(statusCount['connectErrorCount'])} : {url}")
        finally:
            # 更新进度条
            pbar.update(1)
    def getRespUsingRequests(self,url,pbar,lst=[],statusCount={}):
        """用于获取锚点
        #* 不会过滤响应，所有相应都会输出
        返回响应体列表
        [{"code":code,"size":content_size,"type":contentType,"title":page_title}]
        """
        countspider.append(1)#统计发包次数
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36",
            "Accept": "",
            "Accept-Charset": "utf-8",
        }
        try:
            resp=requests.get(url,headers=headers,timeout=(5,10), verify=False)#请求/读取超时5,10s，增大读取超时，有些响应很慢
            try:
                code=resp.status_code
            except:
                code=0
            try:
                content_size = len(resp.content)
            except:
                content_size = 0
            try:#防止返回body为空或者没有title关键字，例如springboot404
                page_title = resp.text.split('<title>')[1].split('</title>')[0]
            except:
                page_title=""
            try:
                contentType=resp.headers['content-type']
                for type in contentTypeList:
                    if type["key"] in contentType:
                        contentType=type["tag"]
            except:#resp出错或响应中无content-type，跳过打印body和屏蔽html
                contentType=""
            respStatus={"code":code,"size":content_size,"type":contentType,"title":page_title}
            statusCount["rightCount"].append(1)
            lst.append(respStatus)
        except requests.exceptions.Timeout as e:
            # timeoutCount+=1
            statusCount["timeoutCount"].append(1)
            if DEBUG:
                if len(statusCount["timeoutCount"])%10==0:
                    print(f"TIMEOUT {len(statusCount['timeoutCount'])} : {url}")
        except requests.exceptions.ConnectionError as e:
            try:
                if "Connection reset by peer" in e:
                    statusCount["connectResetCount"].append(1)
                    if DEBUG:
                        if len(statusCount["connectResetCount"])%10==0:
                            print(f"Connection reset {len(statusCount['connectResetCount'])} : {url}")
                else:
                    statusCount["connectErrorCount"].append(1)
                    if DEBUG:
                        if len(statusCount["connectResetCount"])%10==0:
                            print(f"Connection error occurred {len(statusCount['connectErrorCount'])} : {url}")
            except:
                statusCount["connectErrorCount"].append(1)
                if DEBUG:
                    if len(statusCount["connectResetCount"])%10==0:
                        print(f"Connection error occurred {len(statusCount['connectErrorCount'])} : {url}")
        except requests.exceptions.RequestException as e:
            statusCount["connectErrorCount"].append(1)
            if DEBUG:
                # print(f"{url} : 错误信息:  {e}")
                if len(statusCount["connectErrorCount"])%10==0:
                    print(f"其他连接错误 {len(statusCount['connectErrorCount'])} : {url}")
        finally:
            # 更新进度条
            pbar.update(1)
        # if respStatus not in lst:#这个判断转移到调用它的位置，注释将这个函数变成通用函数（获取响应）
        #     lst.append(respStatus)
        # print(respStatus)
    def getRespUsingRequestsWithHeaders(self,url,pbar,lst=[],statusCount={}):
        """
        #* 不会过滤响应，所有相应都会输出
        返回响应体列表
        [{"code":code,"size":content_size,"type":contentType,"title":page_title}]
        """
        countspider.append(1)#统计发包次数
        headers = {#获取text/html响应
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            # "Accept": "*/*"
        }
        try:
            resp=requests.get(url,headers=headers,timeout=(5,10), verify=False)#请求/读取超时5,10s，增大读取超时，有些响应很慢
            try:
                code=resp.status_code
            except:
                code=0
            try:
                content_size = len(resp.content)
            except:
                content_size = 0
            try:#防止返回body为空或者没有title关键字，例如springboot404
                page_title = resp.text.split('<title>')[1].split('</title>')[0]
            except:
                page_title=""
            try:
                contentType=resp.headers['content-type']
                for type in contentTypeList:
                    if type["key"] in contentType:
                        contentType=type["tag"]
            except:#resp出错或响应中无content-type，跳过打印body和屏蔽html
                contentType=""
            respStatus={"code":code,"size":content_size,"type":contentType,"title":page_title}
            statusCount["rightCount"].append(1)
            lst.append(respStatus)
        except requests.exceptions.Timeout as e:
            # timeoutCount+=1
            statusCount["timeoutCount"].append(1)
            if DEBUG:
                if len(statusCount["timeoutCount"])%10==0:
                    print(f"TIMEOUT {len(statusCount['timeoutCount'])} : {url}")
        except requests.exceptions.ConnectionError as e:
            try:
                if "Connection reset by peer" in e:
                    statusCount["connectResetCount"].append(1)
                    if DEBUG:
                        if len(statusCount["connectResetCount"])%10==0:
                            print(f"Connection reset {len(statusCount['connectResetCount'])} : {url}")
                else:
                    statusCount["connectErrorCount"].append(1)
                    if DEBUG:
                        if len(statusCount["connectResetCount"])%10==0:
                            print(f"Connection error occurred {len(statusCount['connectErrorCount'])} : {url}")
            except:
                statusCount["connectErrorCount"].append(1)
                if DEBUG:
                    if len(statusCount["connectResetCount"])%10==0:
                        print(f"Connection error occurred {len(statusCount['connectErrorCount'])} : {url}")
        except requests.exceptions.RequestException as e:
            statusCount["connectErrorCount"].append(1)
            if DEBUG:
                # print(f"{url} : 错误信息:  {e}")
                if len(statusCount["connectErrorCount"])%10==0:
                    print(f"其他连接错误 {len(statusCount['connectErrorCount'])} : {url}")
        finally:
            # 更新进度条
            pbar.update(1)
    def getRespWithTagUsingRequests(self,ele,pbar,lst,statusCount={}):
        """#*专用于判断有效api
        #* 不会过滤响应，所有相应都会输出
        ele {"url":url,"tag":"completeApi","api":api}
        列表形式
        [{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title},"resp":resp,"tag":tag}]
        """
        countspider.append(1)#统计发包次数
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36",
            "Accept-Charset": "utf-8",
            "Accept": "",
        }
        try:#ele {"url":url,"tag":"completeApi","api":api}
            resp=requests.get(ele["url"],headers=headers,timeout=(5,10), verify=False)#请求/读取超时5,10s，增大读取超时，有些响应很慢
            try:
                code=resp.status_code
            except:
                code=0
            try:
                content_size = len(resp.content)
            except:
                content_size = 0
            try:#防止返回body为空或者没有title关键字，例如springboot404
                page_title = resp.text.split('<title>')[1].split('</title>')[0]
            except:
                page_title=""
            try:
                contentType=resp.headers['content-type']
                for type in contentTypeList:
                    if type["key"] in contentType:
                        contentType=type["tag"]
            except:#resp出错或响应中无content-type，跳过打印body和屏蔽html
                contentType=""
            respStatus={"code":code,"size":content_size,"type":contentType,"title":page_title}
            statusCount["rightCount"].append(1)#命中
            #{"url":url,"status":respStatus,"resp":resp,"tag":tag}
            #{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title},"resp":resp,"tag":tag}
            lst.append({"url":ele['url'],"status":respStatus,"resp":resp,"tag":ele['tag'],"api":ele["api"]})
        except requests.exceptions.Timeout as e:
            # timeoutCount+=1
            statusCount["timeoutCount"].append(1)
            if DEBUG:
                if len(statusCount["timeoutCount"])%10==0:
                    print(f"TIMEOUT {len(statusCount['timeoutCount'])} : {ele['url']}")
        except requests.exceptions.ConnectionError as e:
            try:
                if "Connection reset by peer" in e:
                    statusCount["connectResetCount"].append(1)
                    if DEBUG:
                        if len(statusCount["connectResetCount"])%10==0:
                            print(f"Connection reset {len(statusCount['connectResetCount'])} : {ele['url']}")
                else:
                    statusCount["connectErrorCount"].append(1)
                    if DEBUG:
                        if len(statusCount["connectResetCount"])%10==0:
                            print(f"Connection error occurred {len(statusCount['connectErrorCount'])} : {ele['url']}")
            except:
                statusCount["connectErrorCount"].append(1)
                if DEBUG:
                    if len(statusCount["connectResetCount"])%10==0:
                        print(f"Connection error occurred {len(statusCount['connectErrorCount'])} : {ele['url']}")
        except requests.exceptions.RequestException as e:
            statusCount["connectErrorCount"].append(1)
            if DEBUG:
                # print(f"{url} : 错误信息:  {e}")
                if len(statusCount["connectErrorCount"])%10==0:
                    print(f"其他连接错误 {len(statusCount['connectErrorCount'])} : {ele['url']}")
        finally:
            # 更新进度条
            pbar.update(1)
    def getRespWithTagUsingRequestsWithHeaders(self,ele,pbar,lst,statusCount={}):
        """#*专用于指纹判断
        #* 不会过滤响应，所有相应都会输出
        ele {"url":url,"tag":"completeApi","api":api}
        列表形式
        [{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title},"resp":resp,"tag":tag}]
        """
        countspider.append(1)#统计发包次数
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            # "Accept": "*/*"
            "Accept-Charset": "utf-8",
        }
        try:#ele {"url":url,"tag":"completeApi","api":api}
            resp=requests.get(ele["url"],headers=headers,timeout=(5,10), verify=False)#请求/读取超时5,10s，增大读取超时，有些响应很慢
            try:
                code=resp.status_code
            except:
                code=0
            try:
                content_size = len(resp.content)
            except:
                content_size = 0
            try:#防止返回body为空或者没有title关键字，例如springboot404
                page_title = resp.text.split('<title>')[1].split('</title>')[0]
            except:
                page_title=""
            try:
                contentType=resp.headers['content-type']
                for type in contentTypeList:
                    if type["key"] in contentType:
                        contentType=type["tag"]
            except:#resp出错或响应中无content-type，跳过打印body和屏蔽html
                contentType=""
            respStatus={"code":code,"size":content_size,"type":contentType,"title":page_title}
            statusCount["rightCount"].append(1)#命中
            #{"url":url,"status":respStatus,"resp":resp,"tag":tag}
            #{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title},"resp":resp,"tag":tag}
            singlestatus={"url":ele['url'],"status":respStatus,"resp":resp,"tag":ele['tag'],"api":ele["api"]}
            lst.append(singlestatus)
        except requests.exceptions.Timeout as e:
            # timeoutCount+=1
            statusCount["timeoutCount"].append(1)
            if DEBUG:
                if len(statusCount["timeoutCount"])%10==0:
                    print(f"TIMEOUT {len(statusCount['timeoutCount'])} : {ele['url']}")
        except requests.exceptions.ConnectionError as e:
            try:
                if "Connection reset by peer" in e:
                    statusCount["connectResetCount"].append(1)
                    if DEBUG:
                        if len(statusCount["connectResetCount"])%10==0:
                            print(f"Connection reset {len(statusCount['connectResetCount'])} : {ele['url']}")
                else:
                    statusCount["connectErrorCount"].append(1)
                    if DEBUG:
                        if len(statusCount["connectResetCount"])%10==0:
                            print(f"Connection error occurred {len(statusCount['connectErrorCount'])} : {ele['url']}")
            except:
                statusCount["connectErrorCount"].append(1)
                if DEBUG:
                    if len(statusCount["connectResetCount"])%10==0:
                        print(f"Connection error occurred {len(statusCount['connectErrorCount'])} : {ele['url']}")
        except requests.exceptions.RequestException as e:
            statusCount["connectErrorCount"].append(1)
            if DEBUG:
                # print(f"{url} : 错误信息:  {e}")
                if len(statusCount["connectErrorCount"])%10==0:
                    print(f"其他连接错误 {len(statusCount['connectErrorCount'])} : {ele['url']}")
        finally:
            # 更新进度条
            pbar.update(1)
    #通用请求实现
    def universalGetRespWithTagUsingRequests(self,ele,pbar,lst,statusCount={},headers={},redirect=True):
        """#*专用于响应获取
        #* 不会过滤响应，所有相应都会输出
        ele {"url":url,"tag":"default","api":api}
        列表形式
        #*[{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title,"locationcode":[],"location":[],"locationtimes":0},"resp":resp,"tag":tag,"api":"api"}]
        """
        countspider.append(1)#统计发包次数
        if not headers:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36",
                "Accept-Charset": "utf-8",
                "Accept": "",#覆盖requests默认Accept值，'Accept': '*/*' 否则会导致全部200响应
            }
        try:#ele {"url":url,"tag":"default","api":api}
            if redirect:#重定向默认
                resp=requests.get(ele["url"],headers=headers,timeout=(5,10), verify=False)#请求/读取超时5,10s，增大读取超时，有些响应很慢
            else:
                resp=requests.get(ele["url"],headers=headers,timeout=(5,10),allow_redirects=False, verify=False)#请求/读取超时5,10s，增大读取超时，有些响应很慢
            try:
                code=resp.status_code
            except:
                code=0
            try:
                content_size = len(resp.content)
            except:
                content_size = 0
            try:#防止返回body为空或者没有title关键字，例如springboot404
                page_title = resp.text.split('<title>')[1].split('</title>')[0]
            except:
                page_title=""
            try:
                contentType=resp.headers['content-type']
                for type in contentTypeList:
                    if type["key"] in contentType:
                        contentType=type["tag"]
            except:#resp出错或响应中无content-type，跳过打印body和屏蔽html
                contentType=""
            #location
            #{"code":code,"size":content_size,"type":contentType,"title":page_title,"locationcode":[],"location":[],"locationtimes":0}
            respStatus={"code":code,"size":content_size,"type":contentType,"title":page_title,"locationcode":[],"location":[],"locationtimes":0}
            if resp.history:#重定向实施
                for res in resp.history:
                    respStatus["locationcode"].append(res.status_code)
                    respStatus["location"].append(res.url)
                    respStatus["locationtimes"]+=1
                respStatus["locationcode"].append(code)
                respStatus["location"].append(resp.url)
            statusCount["rightCount"].append(1)#命中
            #{"url":url,"status":respStatus,"resp":resp,"tag":tag}
            #{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title,"locationcode":[],"location":[],"locationtimes":0},"resp":resp,"tag":tag,"api":"api"}
            singlestatus={"url":ele['url'],"status":respStatus,"resp":resp,"tag":ele['tag'],"api":ele["api"]}
            lst.append(singlestatus)
        except requests.exceptions.Timeout as e:
            # timeoutCount+=1
            statusCount["timeoutCount"].append(1)
            if DEBUG:
                if len(statusCount["timeoutCount"])%10==0:
                    print(f"TIMEOUT {len(statusCount['timeoutCount'])} : {ele['url']}")
        except requests.exceptions.ConnectionError as e:
            try:
                if "Connection reset by peer" in e:
                    statusCount["connectResetCount"].append(1)
                    if DEBUG:
                        if len(statusCount["connectResetCount"])%10==0:
                            print(f"Connection reset {len(statusCount['connectResetCount'])} : {ele['url']}")
                else:
                    statusCount["connectErrorCount"].append(1)
                    if DEBUG:
                        if len(statusCount["connectResetCount"])%10==0:
                            print(f"Connection error occurred {len(statusCount['connectErrorCount'])} : {ele['url']}")
            except:
                statusCount["connectErrorCount"].append(1)
                if DEBUG:
                    if len(statusCount["connectResetCount"])%10==0:
                        print(f"Connection error occurred {len(statusCount['connectErrorCount'])} : {ele['url']}")
        except requests.exceptions.RequestException as e:
            statusCount["connectErrorCount"].append(1)
            if DEBUG:
                # print(f"{url} : 错误信息:  {e}")
                if len(statusCount["connectErrorCount"])%10==0:
                    print(f"其他连接错误 {len(statusCount['connectErrorCount'])} : {ele['url']}")
        finally:
            # 更新进度条
            pbar.update(1)
            # singlestatus={}
        if singlestatus:
            return singlestatus
        return
    #通用请求实现
    def universalGetRespWithTagNopbarNolst(self,ele,statusCount={},headers={},redirect=True):
        """#*专用于响应获取
        #* 不会过滤响应，所有相应都会输出
        ele {"url":url,"tag":"default","api":api}
        列表形式
        #*[{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title,"locationcode":[],"location":[],"locationtimes":0},"resp":resp,"tag":tag,"api":"api"}]
        """
        if not statusCount:
            statusCount={"rightCount":[],"outputBodyCount":[],"timeoutCount":[],"connectErrorCount":[],"connectResetCount":[],"blockCount":[]}
        countspider.append(1)#统计发包次数
        if not headers:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36",
                "Accept-Charset": "utf-8",
                "Accept": "",#覆盖requests默认Accept值，'Accept': '*/*' 否则会导致全部200响应
            }
        try:#ele {"url":url,"tag":"default","api":api}
            if redirect:#重定向默认
                resp=requests.get(ele["url"],headers=headers,timeout=(5,10), verify=False)#请求/读取超时5,10s，增大读取超时，有些响应很慢
            else:
                resp=requests.get(ele["url"],headers=headers,timeout=(5,10),allow_redirects=False, verify=False)#请求/读取超时5,10s，增大读取超时，有些响应很慢
            try:
                code=resp.status_code
            except:
                code=0
            try:
                content_size = len(resp.content)
            except:
                content_size = 0
            try:#防止返回body为空或者没有title关键字，例如springboot404
                page_title = resp.text.split('<title>')[1].split('</title>')[0]
            except:
                page_title=""
            try:
                contentType=resp.headers['content-type']
                for type in contentTypeList:
                    if type["key"] in contentType:
                        contentType=type["tag"]
            except:#resp出错或响应中无content-type，跳过打印body和屏蔽html
                contentType=""
            #location
            #{"code":code,"size":content_size,"type":contentType,"title":page_title,"locationcode":[],"location":[],"locationtimes":0}
            respStatus={"code":code,"size":content_size,"type":contentType,"title":page_title,"locationcode":[],"location":[],"locationtimes":0}
            if resp.history:#重定向实施
                for res in resp.history:
                    respStatus["locationcode"].append(res.status_code)
                    respStatus["location"].append(res.url)
                    respStatus["locationtimes"]+=1
                respStatus["locationcode"].append(code)
                respStatus["location"].append(resp.url)
            statusCount["rightCount"].append(1)#命中
            #{"url":url,"status":respStatus,"resp":resp,"tag":tag}
            #{"url":url,"status":{"code":code,"size":content_size,"type":contentType,"title":page_title,"locationcode":[],"location":[],"locationtimes":0},"resp":resp,"tag":tag,"api":"api"}
            singlestatus={"url":ele['url'],"status":respStatus,"resp":resp,"tag":ele['tag'],"api":ele["api"]}
        except requests.exceptions.Timeout as e:
            # timeoutCount+=1
            statusCount["timeoutCount"].append(1)
            if DEBUG:
                if len(statusCount["timeoutCount"])%10==0:
                    print(f"TIMEOUT {len(statusCount['timeoutCount'])} : {ele['url']}")
        except requests.exceptions.ConnectionError as e:
            try:
                if "Connection reset by peer" in e:
                    statusCount["connectResetCount"].append(1)
                    if DEBUG:
                        if len(statusCount["connectResetCount"])%10==0:
                            print(f"Connection reset {len(statusCount['connectResetCount'])} : {ele['url']}")
                else:
                    statusCount["connectErrorCount"].append(1)
                    if DEBUG:
                        if len(statusCount["connectResetCount"])%10==0:
                            print(f"Connection error occurred {len(statusCount['connectErrorCount'])} : {ele['url']}")
            except:
                statusCount["connectErrorCount"].append(1)
                if DEBUG:
                    if len(statusCount["connectResetCount"])%10==0:
                        print(f"Connection error occurred {len(statusCount['connectErrorCount'])} : {ele['url']}")
        except requests.exceptions.RequestException as e:
            statusCount["connectErrorCount"].append(1)
            if DEBUG:
                # print(f"{url} : 错误信息:  {e}")
                if len(statusCount["connectErrorCount"])%10==0:
                    print(f"其他连接错误 {len(statusCount['connectErrorCount'])} : {ele['url']}")
        # finally:#有毒
        #     singlestatus={}
        #     print(f"finally:singlestatus:{singlestatus}")
        if singlestatus:
            return singlestatus
        return
    #废弃
    def apiFuzzMode(self,apiList):
        """拼接fuzz获得正确链接
        """
        print()
        print("接口fuzz开始")
        #将所有api直接拼接在其他api前，避免长api根路径误判，例如根为/api/health
        #将所有api分解取第一个路径作为根路径拼接
        #爬取结果为url访问的情况 暂时不做处理
        # 优化fuzz逻辑，可以采用生成一批探测一批，发现正确api直接停止
        # 或者加入随机逻辑，随机探测一批，存在正确的，则针对性测试该api模式确定是否正确
        # 加入正确率概念，达到一定正确率可判断为正确api 输出可信度 废弃
        # 可以采用分批发包，发现正确api直接停止 参照arjun
        # 增加初始api列表 逐级访问 列表 /api/health/catorgory/foodlist---->
        #* /api/health/catorgory/
        #* /api/health/
        #* /api/

        tmpList=[]
        apiAndCommonApiList=apiList+commonApiList
        tmpList+=self.mergePath("",apiAndCommonApiList)#原始apiList附带常见api添加一次
        tmpList+=self.completeMerge(apiList)
        tmpList+=self.splitAndFirstMerge(apiList)
        tmpList+=self.bruteForceMerge(apiList)
        resultList=[]
        if DEBUG:
            print("进行去重")
        # for x in tmpList:#去重
        #     if x not in resultList:
        #         resultList.append(x)
        #优化去重方法
        #您可以遍历列表中的元素，并将每个元素作为字典的键插入到字典中。由于字典的键是唯一的，如果元素已经存在于字典中，则插入操作将被忽略。最后，您可以将字典的键转换为列表并返回。
        mydic={}
        for element in tmpList:
            mydic[element]=None
        resultList=list(mydic.keys())
        #去除包含api黑名单中元素的url
        resultList=[url for url in resultList if not any(c in url for c in apiBlackList)]
        if DEBUG:
            print(f"净化拼接逻辑完成, 总计: {len(resultList)} 个待处理接口")
            if Verbose:
                for line in resultList:
                    print(line)
                print(f"净化拼接逻辑完成, 总计: {len(resultList)} 个待处理接口")
        return resultList
    #! 所有api的形式为 /api/xxx   非：/api/xxx/   api/xxx  api/xxx/
    def mergePath(self,rootPath,apiList):
        """专用于拼接根路径和apilist 返回 /abcd  不会出现/abcd/
        去重
        移除空api路径例如 /

        Args:
            rootPath (_type_): _description_
            apiList (_type_): _description_
        """
        tmpList=[]
        delimiter="/"
        if not any(rootPath.strip("/").startswith(x) for x in apiRootBlackList):
            for api in apiList:
                #排除/aaa/aaa和/aaa/aaa拼接的情况
                #*不排除/aaa 和/aaa拼接的情况 ----> /sys/sys/query/list
                foot=self.oneDirectionfootSize(rootPath,api,delimiter)
                if not foot or len(foot.strip("/").split("/"))!=1:
                    tmpApi=rootPath.strip("/")
                    # if DEBUG:
                    #     print(f"api: {api}")
                    #     print(f"tmpApi: {tmpApi}")
                    if tmpApi!="":
                        fullApi="/"+tmpApi+"/"+api.strip("/")
                    else:
                        fullApi="/"+api.strip("/")
                    if fullApi not in tmpList:#去重
                        # if DEBUG:
                        #     print(f"fullApi: {fullApi}")
                        tmpList.append(fullApi)
                    else:
                        if DEBUG and Verbose:
                            print(f"fullApi重复: {fullApi}")
                else:
                    tmpList.append("/"+api.strip("/"))
        else:
            if DEBUG:
                print(f"命中黑名单api: {rootPath}")
        tmpList=self.fastUniqList(tmpList)
        return tmpList
    def mergePathPure(self,rootPath,apiList):
        """#*不考虑黑名单api，
        专用于拼接根路径和apilist
        去重
        移除空api路径例如 /

        Args:
            rootPath (_type_): _description_
            apiList (_type_): _description_
        """
        tmpList=[]
        for api in apiList:
            tmpApi=rootPath.strip("/")
            # if DEBUG:
            #     print(f"api: {api}")
            #     print(f"tmpApi: {tmpApi}")
            if tmpApi!="":
                fullApi="/"+tmpApi+"/"+api.lstrip("/")
            else:
                fullApi="/"+api.lstrip("/")
            if fullApi not in tmpList:#去重
                # if DEBUG:
                #     print(f"fullApi: {fullApi}")
                tmpList.append(fullApi)
            else:
                if DEBUG:
                    print(f"fullApi重复: {fullApi}")
    
        return tmpList
    def inputApisMerge(self,inputApis,apiList):
        """以输入的api 对apiList进行参加

        Args:
            inputApis (_type_): _description_
            apiList (_type_): _description_
        """
        lst=[]
        for api in inputApis:
            lst+=self.mergePath(api,apiList)
        return lst
    def completeMerge(self,apiList):
        """所有接口完全拼接，考虑到绝大部分情况下根api会出现在接口中，完全拼接即可实现根发现

        Args:
            apiList (_type_): _description_
        """
        tmpList=[]
        for api in apiList:
            tmpList+=self.mergePath(api,apiList)
        if DEBUG:
            print(f"完全拼接，拼接总数为: {len(tmpList)}")
        return tmpList
    def completeMergeWithTag(self,apiList):

        """所有接口完全拼接，考虑到绝大部分情况下根api会出现在接口中，完全拼接即可实现根发现

        Args:
            apiList (_type_): _description_
        """
        apiWithTagList=[]
        for api in apiList:
            tmpList=[]
            tmpList+=self.mergePath(api,apiList)
            tag=self.generate_random_string(3)
            #{"url":url,"tag":"completeApi-xxx"}
            #{"url":url,"tag":"completeApi-tag"}
            for i in range(len(tmpList)):
                tmpList[i]={"url":tmpList[i],"tag":f"completeApi-{tag}","api":tmpList[i]}
            apiWithTagList+=tmpList
        if DEBUG:
            print(f"完全拼接，拼接总数为: {len(apiWithTagList)}")
        return apiWithTagList

    def commonPrefixMerge(self,apiList):
        """公共前缀api列表  完全拼接

        Args:
            apiList (_type_): _description_
        """
        fullList=[]
        tmpList=self.findLongestCommonPrefix(apiList)
        for t in tmpList:
            fullList+=self.mergePath(t,apiList)
        fullList=self.fastUniqList(fullList)
        if DEBUG:
            print(f"公共前缀，总数为: {len(fullList)}")
        return fullList
    def commonPrefixMergeWithTag(self,apiList):
        """公共前缀api列表  完全拼接 with tag

        Args:
            apiList (_type_): _description_
        """
        fullList=[]
        lst=self.findLongestCommonPrefix(apiList)
        for t in lst:
            tag=self.generate_random_string(3)
            tmp=self.fastUniqList([url for url in self.mergePath(t,apiList)])
            fullList+=[{"url":url,"tag":f"commonPrefix-{tag}","api":url} for url in tmp]
        if DEBUG:
            print(f"公共前缀，总数为: {len(fullList)}")
        return fullList

    def stairSplitMerge(self,apiList):
        """阶梯切割api列表  完全拼接

        Args:
            apiList (_type_): _description_
        """
        fullList=[]
        tmpList=self.stairsSplitAndStitch(apiList)
        for t in tmpList:
            fullList+=self.mergePath(t,apiList)
        fullList=self.fastUniqList(fullList)
        if DEBUG:
            print(f"阶梯切割，总数为: {len(fullList)}")
        return fullList

    def stairSplitMergeWithTag(self,apiList):
        """阶梯切割api列表  完全拼接 with tag

        Args:
            apiList (_type_): _description_
        """
        fullList=[]
        # lst=self.stairsSplitAndStitch(apiList)
        lst=apiList
        for t in lst:
            tag=self.generate_random_string(3)
            tmp=self.fastUniqList([url for url in self.mergePath(t,apiList)])
            fullList+=[{"url":url,"tag":f"stairSplit-{tag}","api":url} for url in tmp]
        if DEBUG:
            print(f"阶梯切割，总数为: {len(fullList)}")
        return fullList

    def splitAndFirstMerge(self,apiList):
        """分解所有api，取第一个路径进行完全拼接

        Args:
            apiList (_type_): _description_
        """
        #分解api获取根api列表
        rootApiList=[]
        for api in apiList:
            splitRoot=api.strip("/").split("/")[0]
            if splitRoot not in rootApiList:
                rootApiList.append(splitRoot)
        # rootApiList=[api.strip("/").split("/")[0] for api in apiList if api not in rootApiList]
        if DEBUG:
            print(f"分解拼接：分解后根api总数为: {len(rootApiList)},拼接总数为: {len(rootApiList)*len(apiList)}")
        tmpList=[]
        #拼接所有根api列表
        for root in rootApiList:
            tmpList+=self.mergePath(root,apiList)
        return tmpList
    def splitAndFirstMergeWithTag(self,apiList):
        """分解所有api，取第一个路径进行完全拼接

        Args:
            apiList (_type_): _description_
        """
        #分解api获取根api列表
        rootApiList=[]
        for api in apiList:
            #todo 应该不需要取后面的对象吧？ 对吧
            splitRoot=api.strip("/").split("/")[0]
            if splitRoot not in rootApiList:
                rootApiList.append(splitRoot)
        # rootApiList=[api.strip("/").split("/")[0] for api in apiList if api not in rootApiList]
        
        #拼接所有根api列表
        apiWithTagList=[]
        for root in rootApiList:
            tmpList=[]
            tmpList+=self.mergePath(root,apiList)
            tag=self.generate_random_string(3)
            #{"url":url,"tag":"completeApi-xxx"}
            #{"url":url,"tag":"completeApi-tag"}
            for i in range(len(tmpList)):
                tmpList[i]={"url":tmpList[i],"tag":f"splitApi-{tag}","api":tmpList[i]}
            apiWithTagList+=tmpList
        if DEBUG:
            print(f"分解拼接：分解后根api总数为: {len(rootApiList)},拼接总数为: {len(apiWithTagList)}")
        return apiWithTagList
    def bruteForceMerge(self,apiList):
        """取常见根api路径进行拼接

        Args:
            apiList (_type_): _description_
        """
        tmpList=[]
        for root in commonApiList:
            tmpList+=self.mergePath(root,apiList)
        if DEBUG:
            print(f"常见根APi，拼接总数为: {len(tmpList)}")
        return tmpList

def modeParse(args):
    """通过参数判断程序运行模式 爬取|fuzz|api|noapi

    Args:
        args (_type_): _description_
    """
    #todo 增加列表模式
    if len(args)>1:
        if isFileValidTxt(args[1]):
            isBatch=True
        elif isUrlValid(args[1]):
            isBatch=False
        else:
            return
        if len(args)>5 or len(sys.argv)<2:
            return
        elif len(args)==2:
            if not isBatch:
                return "spider"
            else:
                return "batchspider"
        elif len(args)==3:
            if not isBatch:
                if args[2].lower()=="fuzz":
                    return "fuzz"
                elif args[2].lower()=="api":
                    return "api"
                else:
                    return
            else:
                if args[2].lower()=="fuzz":
                    return "batchfuzz"
                elif args[2].lower()=="api":
                    return "batchapi"
                else:
                    return
        elif len(args)==4:
            if not isBatch:
                if args[2].lower()!="api":
                        if args[2].lower()=="fuzz":
                            if args[3].lower()=="noapi":
                                return "fuzznoapi"
                            elif args[3].lower()=="nobody":
                                return "fuzznobody"
                            elif args[3].lower()=="nofuzz":
                                return "fuzznofuzz"
                            else:
                                return
                        else:
                            return
                elif args[3].lower()=="nobody":
                    return "apinobody"
                elif args[3].lower()=="nofuzz":
                    return "apinofuzz"
                else:
                    return
            else:#batch
                if args[2].lower()!="api":
                        if args[2].lower()=="fuzz":
                            if args[3].lower()=="noapi":
                                return "batchfuzznoapi"
                            elif args[3].lower()=="nobody":
                                return "batchfuzznobody"
                            elif args[3].lower()=="nofuzz":
                                return "batchfuzznofuzz"
                            else:
                                return
                        else:
                            return
                elif args[3].lower()=="nobody":
                    return "batchapinobody"
                elif args[3].lower()=="nofuzz":
                    return "batchapinofuzz"
                else:
                    return
        elif len(args)==5:
            if not isBatch:
                if args[2].lower()=="fuzz" and args[3].lower()=="noapi" and args[4].lower()=="nobody":
                    return "fuzznoapinobody"
                elif args[2].lower()=="fuzz" and args[3].lower()=="noapi" and args[4].lower()=="nofuzz":
                    return "fuzznoapinofuzz"
                else:
                    return
            else:#batch
                if args[2].lower()=="fuzz" and args[3].lower()=="noapi" and args[4].lower()=="nobody":
                    return "batchfuzznoapinobody"
                elif args[2].lower()=="fuzz" and args[3].lower()=="noapi" and args[4].lower()=="nofuzz":
                    return "batchfuzznoapinofuzz"
                else:
                    return
        else:
            return
    else:
        return
def main():
    #new mode
    #增加仅发现根api模式 不进行根请求 区分nobody模式 修改模式识别功能 取消固定顺序 仅url位置固定
    args=sys.argv
    mode=modeParse(args)

    if mode:
        if "spider" in mode:
            print(f"mode: {mode}")
            if  mode=="spider":
                origionUrl=args[1]
                singleSpider(mode,origionUrl)
            elif mode=="batchspider":
                urlList=readFileIntoList(args[1])
                #todo 输出非有效url信息
                urlList=[x for x in urlList if isUrlValid(x)]
                batchSpider(mode,urlList)
            else:
                sys.exit(ErrorClass.usageTips)
        elif mode.replace("batch","").startswith("fuzz"):#fuzz
            print(f"mode: {mode}")
            print("处理中")
            if "batch" not in mode:
                noneApis=[]
                if "nobody" in mode:
                    print(f"禁用body输出")
                elif "nofuzz"in mode:
                    print(f"仅获取有效api")
                if mode=="fuzznoapi" or mode=="fuzznoapinobody" or mode=="fuzznoapinofuzz":
                    noneApis=read_newline().split()
                    print(f"排除的api为: {noneApis}")
                elif mode=="fuzz" or mode=="fuzznobody" or mode=="fuzznofuzz":
                    pass
                else:
                    sys.exit(ErrorClass.usageTips)
                origionUrl=args[1]
                myFuzz=apiFuzz()
                myFuzz.singleApiFuzzInAction(mode,origionUrl,noneApis)
                # #*爬取origionurl和cleanurl
            else:#batchfuzz
                noneApis=[]
                if "nobody" in mode:
                    print(f"禁用body输出")
                elif "nofuzz"in mode:
                    print(f"仅获取有效api")
                if mode=="batchfuzznoapi" or mode=="batchfuzznoapinobody" or mode=="batchfuzznoapinofuzz":
                    noneApis=read_newline().split()
                    print(f"排除的api为: {noneApis}")
                elif mode=="batchfuzz" or mode=="batchfuzznobody" or mode=="batchfuzznofuzz":
                    pass
                else:
                    sys.exit(ErrorClass.usageTips)
                filename=args[1]
                urlList=readFileIntoList(filename)
                urlList=[x for x in urlList if isUrlValid(x)]
                myFuzz=apiFuzz()
                myFuzz.batchApiFuzzInAction(mode,urlList,noneApis)
                # #*爬取origionurl和cleanurl
        elif mode.replace("batch","").startswith("api"):#api
            if "batch" not in mode:
                print(f"mode: {mode}")
                if "nobody" in mode:
                    print(f"禁用body输出")
                elif "nofuzz"in mode:
                    print(f"仅获取有效api")
                if mode == "api" or mode == "apinobody" or mode == "apinofuzz":
                    pass
                else:
                    sys.exit(ErrorClass.usageTips)
                apiPath=read_newline()
                apiPaths=apiPath.split()
                print(f"输入的api为: {apiPaths}")
                print()
                print("处理中")
                origionUrl=args[1]
                singleUserInputApi(mode,origionUrl,apiPaths)
                # #*爬取origionurl和cleanurl
                #todo 或者留下锚点，但是依然输出
            else:#batchapi
                print(f"mode: {mode}")
                if "nobody" in mode:
                    print(f"禁用body输出")
                elif "nofuzz"in mode:
                    print(f"仅获取有效api")
                if mode in ["batchapi","batchapinobody","batchapinofuzz"]:
                    pass
                else:
                    sys.exit(ErrorClass.usageTips)
                filename=args[1]
                apiPath=read_newline()
                apiPaths=apiPath.split()
                print(f"输入的api为: {apiPaths}")
                print()
                print("处理中")
                urlList=readFileIntoList(filename)
                urlList=[x for x in urlList if isUrlValid(x)]
                batchUserInputApi(mode,urlList,apiPaths)
                # #*爬取origionurl和cleanurl
                # 取消手动输入api情况下的对比 不取消
                # #todo 或者留下锚点，但是依然输出
        else:
            sys.exit(ErrorClass.usageTips)
    else:
        sys.exit(ErrorClass.usageTips)



if __name__=="__main__":
    main()


