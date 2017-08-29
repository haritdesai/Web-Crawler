import logging
from datamodel.search.datamodel import ProducedLink, OneUnProcessedGroup, robot_manager
from spacetime_local.IApplication import IApplication
from spacetime_local.declarations import Producer, GetterSetter, Getter
from lxml import html,etree
import re, os
from time import time
import urlparse

try:
    # For python 2
    from urlparse import urlparse, parse_qs
except ImportError:
    # For python 3
    from urllib.parse import urlparse, parse_qs


logger = logging.getLogger(__name__)
LOG_HEADER = "[CRAWLER]"
url_count = (set() 
    if not os.path.exists("successful_urls.txt") else 
    set([line.strip() for line in open("successful_urls.txt").readlines() if line.strip() != ""]))
MAX_LINKS_TO_DOWNLOAD = 3000
seen = set()

subdomains = dict()
invalidLinks = 0
pageWithMostOutLinks = ()
downloadTime = []
previousDownloadTime = time()

@Producer(ProducedLink)
@GetterSetter(OneUnProcessedGroup)
class CrawlerFrame(IApplication):

    def __init__(self, frame):
        self.starttime = time()
        # Set app_id <student_id1>_<student_id2>...
        self.app_id = "90879392_13995582"
        # Set user agent string to IR W17 UnderGrad <student_id1>, <student_id2> ...
        # If Graduate studetn, change the UnderGrad part to Grad.
        self.UserAgentString = "IR W17 Undergrad 90879392, 13995582"
		
        self.frame = frame
        assert(self.UserAgentString != None)
        assert(self.app_id != "")
        if len(url_count) >= MAX_LINKS_TO_DOWNLOAD:
            self.done = True

    def initialize(self):
        self.count = 0
        l = ProducedLink("http://www.ics.uci.edu", self.UserAgentString)
        print l.full_url
        self.frame.add(l)

    def update(self):
        for g in self.frame.get_new(OneUnProcessedGroup):
            print "Got a Group"
            outputLinks, urlResps = process_url_group(g, self.UserAgentString)
            for urlResp in urlResps:
                if urlResp.bad_url and self.UserAgentString not in set(urlResp.dataframe_obj.bad_url):
                    urlResp.dataframe_obj.bad_url += [self.UserAgentString]
            for l in outputLinks:
                if is_valid(l) and robot_manager.Allowed(l, self.UserAgentString):
                    lObj = ProducedLink(l, self.UserAgentString)
                    self.frame.add(lObj)
        if len(url_count) >= MAX_LINKS_TO_DOWNLOAD:
            self.done = True

    def shutdown(self):
        print "downloaded ", len(url_count), " in ", time() - self.starttime, " seconds."
        analytics = open('analytics.txt', 'w')
        analytics.write("-------Subdomains-------\n")
        for key in subdomains:
            analytics.write("%s: %d URLs\n" % (key, subdomains[key]))
        analytics.write("-------Subdomains-------\n")
        analytics.write("Invalid Links: %d\n" % (invalidLinks))
        analytics.write("Page With Most Out Links: %s with %d links\n" % (pageWithMostOutLinks[0], pageWithMostOutLinks[1]))
        totalDownloadTime = 0
        for i in downloadTime:
            totalDownloadTime += i
            print i
        analytics.write("Average Download Time: %f s\n" % (totalDownloadTime/len(downloadTime)))
        pass

def save_count(urls):
    global url_count
    urls = set(urls).difference(url_count)
    url_count.update(urls)
    if len(urls):
        with open("successful_urls.txt", "a") as surls:
            surls.write(("\n".join(urls) + "\n").encode("utf-8"))

def process_url_group(group, useragentstr):
    rawDatas, successfull_urls = group.download(useragentstr, is_valid)
    save_count(successfull_urls)
    return extract_next_links(rawDatas), rawDatas
    
#######################################################################################
'''
STUB FUNCTIONS TO BE FILLED OUT BY THE STUDENT.
'''
def extract_next_links(rawDatas):
    outputLinks = list()
    # rawDatas.url = rawDatas.url.encode('ascii', 'ignore')
    global pageWithMostOutLinks
    global previousDownloadTime
    global downloadTime
    if len(rawDatas) != 0:
        downloadTime.append(time() - previousDownloadTime)
    previousDownloadTime = time()
    '''
    rawDatas is a list of objs -> [raw_content_obj1, raw_content_obj2, ....]
    Each obj is of type UrlResponse  declared at L28-42 datamodel/search/datamodel.py
    the return of this function should be a list of urls in their absolute form
    Validation of link via is_valid function is done later (see line 42).
    It is not required to remove duplicates that have already been downloaded. 
    The frontier takes care of that.

    Suggested library: lxml
    '''
    print "LEN: ", len(rawDatas)
    try:
        if len(rawDatas) != 0:
            numberOfLinks = 0
            for i in range(len(rawDatas)):
                doc = html.document_fromstring(rawDatas[i].content)
                doc.make_links_absolute(rawDatas[i].url)
                for link in doc.iterlinks():
                    numberOfLinks += 1
                    print "LINK: ", link[2]
                    outputLinks.append(link[2].strip(u'\u200b')) #for unicode error
        
            if len(pageWithMostOutLinks) == 0:
                pageWithMostOutLinks = (rawDatas[i].url, numberOfLinks)
            elif (pageWithMostOutLinks[1] < numberOfLinks):
                pageWithMostOutLinks = (rawDatas[i].url, numberOfLinks)
    except:
        print "XML could not be parsed"

    return outputLinks

def is_valid(url):
    '''
    Function returns True or False based on whether the url has to be downloaded or not.
    Robot rules and duplication rules are checked separately.

    This is a great place to filter out crawler traps.
    '''
    url = url.encode('ascii', 'ignore')

    global invalidLinks
    if url in seen:    
        invalidLinks += 1
        return False
    seen.add(url)

    try:
        address = urlparse(url)
        if address.netloc in subdomains:
            subdomains[address.netloc] += 1
        else:
            subdomains[address.netloc] = 1

        if ("calender.ics.uci.edu" in url or "ganglia.ics.uci.edu" in url or "www.ics.uci.edu/~mlearn/" in url or "arrow-webapp" in url
            or "ganglia.ics.uci.edu." in url or "ganglia.ics.uci.edu.." in url or "www.ics.uci.edu/~mlearn/datasets" in url or "http://mlphysics.ics.uci.edu/data/" in url
            or "~mlearn" in url or "http://archive.ics.uci.edu/ml/datasets.html" in url or "http://www.ics.uci.edu/~develop/" in url or ".php" in url
            or "contact/student-affairs" in url):
            invalidLinks += 1
            return False

        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            invalidLinks += 1
            return False

    except:
        print "UNICODE_ERROR"

    try:
        if "@" in parsed.path or "http" in parsed.path:
            invalidLinks += 1
            return False

        if len(parsed[2].split("index")) > 2 or len(parsed[2].split("index/")) > 2:
            invalidLinks += 1
            return False
    except:
        print "PARSE_ERROR"

    try:
        return ".ics.uci.edu" in parsed.hostname \
            and not re.match(".*\.(css|js|bmp|gif|jpe?g|ico|php" + "|png|tiff?|mid|mp2|mp3|mp4"\
            + "|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf" \
            + "|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1" \
            + "|thmx|mso|arff|rtf|jar|csv"\
            + "|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
