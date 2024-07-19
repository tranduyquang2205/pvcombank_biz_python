
import hashlib
import requests
import json
import base64
import random
import string
import base64
import json
import os
import hashlib
import time
import uuid
import base64
from datetime import datetime
import re
from bs4 import BeautifulSoup
from lxml import html
import urllib.parse


class PVCombank:
    def __init__(self, username, password, account_number):
        self.session = requests.Session()
        self.is_login = False
        self.file = f"data/{username}.txt"
        self._IBDeviceId = ""
        self.dse_sessionId = ""
        self.balance = None
        self.referer_url = ""
        self.load_account_url = ""
        self.dse_processorId = ""
        self.account_cif = None
        self.dse_pageId = 0
        self.available_balance = 0
        self.transactions = []
        self.url = {
    "solve_captcha": "https://acbbiz.pay2world.vip/pv/predict",
    "getCaptcha": "https://biz.pvcombank.com.vn/servlet/ImageServlet",
    "login": "https://biz.pvcombank.com.vn/Request",
    "getHistories": "https://efast.vietinbank.vn/api/v1/account/history",
    "getlistAccount": "https://efast.vietinbank.vn/api/v1/account/getUserInfo",
}
        self.lang =  "vi"
        self.request_id = None
        self._timeout = 60
        self.init_guid()
        if not os.path.exists(self.file):
            self.username = username
            self.password = password
            self.account_number = account_number
            self.sessionId = ""
            self.browserId = hashlib.md5(self.username.encode()).hexdigest()
            self.save_data()
            
        else:
            self.parse_data()
            self.username = username
            self.password = password
            self.account_number = account_number
    def save_data(self):
        data = {
            'username': self.username,
            'password': self.password,
            'account_number': self.account_number,
            'sessionId': getattr(self, 'sessionId', '')
        }
        with open(self.file, 'w') as f:
            json.dump(data, f)

    def parse_data(self):
        with open(self.file, 'r') as f:
            data = json.load(f)
        self.username = data.get('username', '')
        self.password = data.get('password', '')
        self.account_number = data.get('account_number', '')
        self.sessionId = data.get('sessionId', '')
        
    def init_guid(self):
        self._IBDeviceId = self.generate_device_id()
        
    def generate_device_id(self):
        # Generate a random UUID
        random_uuid = uuid.uuid4()
        
        # Convert the UUID to a string
        uuid_str = str(random_uuid)
        
        # Create a hash object
        hash_object = hashlib.sha256()
        
        # Update the hash object with the UUID string
        hash_object.update(uuid_str.encode('utf-8'))
        
        # Get the hexadecimal digest of the hash
        hex_digest = hash_object.hexdigest()
        
        # Return the first 32 characters of the hex digest
        return hex_digest[:32]
    
    def curlGet(self, url):
        # print('curlGet')
        headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'en-US,en;q=0.9',
        'Cache-Control': 'max-age=0',
        'Connection': 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://biz.pvcombank.com.vn',
        "Referer": self.referer_url if self.referer_url else "",
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
        'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"'
        }
        response = self.session.get(url, headers=headers,allow_redirects=True)
        self.referer_url = url
        try:
            return response.json()
        except:
            response = response.text
            dse_pageId = self.extract_dse_pageId(response)
            if dse_pageId:
                self.dse_pageId = dse_pageId
            # else:
            #     print('error_page',url)
            return response
        return result
    
    def curlPost(self, url, data ,headers = None):
        # print('curlPost')
        if not headers:
            headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://biz.pvcombank.com.vn',
            "Referer": self.referer_url if self.referer_url else "",
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
            'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
            }

        response = self.session.post(url, headers=headers, data=data)
        self.referer_url = url
        try:
            return response.json()
        except:
            response = response.text
            dse_pageId = self.extract_dse_pageId(response)
            if dse_pageId:
                self.dse_pageId = dse_pageId
            # else:
            #     print('error_page',url)
            return response
        return result

    def generate_request_id(self):
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=12)) + '|' + str(int(datetime.now().timestamp()))
    def check_error_message(self,html_content):
        pattern = r'<span><font class=\'text-err_login\'>(.*?)</font></span>'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def check_error_message_details(self,html_content):
        pattern = r'<span><font class=\'text-err_login__desc\'>(.*?)</font></span>'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def check_exit_login(self,html_content):
        return True if 'để tài khoản đã đăng nhập thoát khỏi hệ thống' in html_content else None
    def check_error_captcha(self,html_content):
        return True if 'Mã xác thực không chính xác' in html_content else None
    def extract_tokenNo(self,html_content):
        pattern = r'src="/IBSRetail/servlet/CmsImageServlet\?attachmentId=1&&tokenNo=([a-f0-9-]+)"'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def extract_account_cif(self,html_content):
        pattern = r'<option value="(.+)" >'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def extract_dse_processorId(self,html_content):
        pattern = r'<input type="hidden" name="dse_processorId" value="(.*)"'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def extract_dse_pageId(self,html_content):
        pattern = r'dse_pageId=(\d+)&'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def extract_account_number(self,html_content):
        pattern = r'<span class="desc">(\d+) <em class="icon-coppy"></em></span>'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def extract_load_account(self,html_content):
        pattern = r'/Request?&dse_sessionId=(.)*&dse_applicationId=-1&dse_pageId=(.)*&dse_operationName=corpUserLoginProc&dse_processorState=initial&dse_nextEventName=loadAccounts'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def extract_balance(self,html_content):
        pattern = r'<span class="desc">([^\s]+)</span>'
        match = re.search(pattern, html_content)
        return match.group(1) if match else None
    def get_total_transaction(self,html_content):
        soup = BeautifulSoup(html_content, 'html.parser')
        h4_element = soup.find('h4')
        if h4_element:
            h4_text = h4_element.get_text(strip=True)
        return int(h4_text.replace('Tổng số bản ghi','').strip()) if h4_element else 0
    def extract_page_url(self,html_content,page):
        soup = BeautifulSoup(html_content, 'html.parser')
        div = soup.find('div', class_='so-trang')
        href = None
        if div:
            a_tag = div.find('a', string=str(page)+' ')
            if a_tag:
                href = a_tag['href']
        return 'https://biz.pvcombank.com.vn'+href if href else None
    def extract_transaction_history(self,html_string):
        # Parse the HTML content
        soup = BeautifulSoup(html_string, 'html.parser')

        # Find the tbody with the specific id
        tbody = soup.find('tbody', id='allResultTableBody')
        if tbody:
            # Find all rows with the class 'bg1'
            rows = tbody.find_all('tr', class_='bg1')
        else:
            rows = []

        # Initialize an empty list to store the records
        history_records = []

        # Process each row
        for row in rows:
            columns = row.find_all('td')
            
            # Ensure there are enough columns
            if len(columns) >= 6:
                # Get debit and credit values, default to '0' if not present
                debit = columns[2].text.strip() if columns[2].text.strip() != '0' else '0'
                credit = columns[3].text.strip() if columns[3].text.strip() != '0' else '0'

                # Convert debit and credit to integers and calculate amount
                amount = int(credit.replace(',', '')) - int(debit.replace(',', ''))
                
                # Create a record dictionary
                record = {
                    "transaction_number": columns[0].text.strip(),
                    "transaction_id": columns[1].text.strip(),
                    "time": columns[4].text.strip(),
                    "amount": amount,
                    "description": columns[5].text.strip()
                }
                # Append the record to the list
                history_records.append(record)

        return history_records
    def createTaskCaptcha(self, base64_img):
        payload = json.dumps({
        "image_base64": base64_img
        })
        headers = {
        'Content-Type': 'application/json'
        }

        response = requests.request("POST", self.url['solve_captcha'], headers=headers, data=payload)
        try:
            return response.json()
        except:
            return response.text
    def solveCaptcha(self):
        url = self.url['getCaptcha']
        response = self.session.get(url)
        base64_captcha_img = base64.b64encode(response.content).decode('utf-8')
        result = self.createTaskCaptcha(base64_captcha_img)
        # captchaText = self.checkProgressCaptcha(json.loads(task)['taskId'])
        if 'prediction' in result and result['prediction']:
            captcha_value = result['prediction']
            return {"status": True, "captcha": captcha_value}
        else:
            return {"status": False, "msg": "Error getTaskResult"}
    def process_redirect(self,response):
        
        pattern = r'dse_sessionId=(.*?)&dse_applicationId=(.*?)&dse_pageId=(.*?)&dse_operationName=(.*?)&dse_errorPage=(.*?)&dse_processorState=(.*?)&dse_nextEventName=(.*?)\';'
        pattern_url = r'window.location.href = \'(.*?)\';'
        match = re.search(pattern, response)
        match_url = re.search(pattern_url, response)
        self.dse_sessionId = str(match.group(1))
        if match_url:
            return 'https://biz.pvcombank.com.vn'+match_url.group(1)
        else:
            return None
    def process_change_session(self,response):
        pattern = r'dse_sessionId=(.*?)&dse_applicationId=(.*?)&dse_pageId=(.*?)&dse_operationName=(.*?)&dse_processorState=(.*?)&dse_nextEventName=(.*?)\';'
        pattern_url = re.compile(r'/Request\?&dse_sessionId=[^&]+&dse_applicationId=-1&dse_pageId=[^&]+&dse_operationName=corpUserLoginProc&dse_processorState=initial&dse_nextEventName=loadAccounts')
        match = re.search(pattern, response)
        match_url = re.search(pattern_url, response)
        self.dse_sessionId = str(match.group(1))
        if match_url:
            return 'https://biz.pvcombank.com.vn'+match_url.group(0)
        else:
            return None
    def doLogin(self):
        self.session = requests.Session()
        response = self.curlGet(self.url['login'])
        redirect_url = self.process_redirect(response)
        if redirect_url:
            url1 = redirect_url
            response = self.curlGet(url1)
            redirect_url = self.process_redirect(response)
            
            url2 = redirect_url
            response = self.curlGet(url2)
            solveCaptcha = self.solveCaptcha()
            if not solveCaptcha["status"]:
                return solveCaptcha
            captchaText = solveCaptcha["captcha"]
            payload = 'dse_sessionId='+self.dse_sessionId+'&dse_applicationId=-1&dse_pageId='+str(self.dse_pageId)+'&dse_operationName=corpUserLoginProc&dse_errorPage=index.jsp&dse_processorState=initial&dse_nextEventName=start&_IBDeviceId='+self._IBDeviceId+'&_userName='+self.username+'&_password='+self.password+'&_verifyCode='+captchaText
            headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'Referer': url2,
            'Content-Type': 'application/x-www-form-urlencoded',
            'Origin': 'https://biz.pvcombank.com.vn',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
            'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"'
            }
            
            response = self.curlPost("https://biz.pvcombank.com.vn/Request",  data=payload,headers=headers)
            # print(response)
            response = response
            
            check_error_captcha = self.check_error_captcha(response)
            if check_error_captcha:
                return {
                            'code': 422,
                            'success': False,
                            'message': 'invalid_captcha!',
                        }
            check_exit_login = self.check_exit_login(response)
            if check_exit_login:
                dse_processorId = self.extract_dse_processorId(response)
                payload = 'dse_sessionId='+self.dse_sessionId+'&dse_applicationId=-1&dse_pageId='+str(self.dse_pageId)+'&dse_operationName=corpUserLoginProc&dse_errorPage=error_page.jsp&dse_processorState=loginConductJSP&dse_nextEventName=ok&_loginedConduct=forceLastLogin&dse_processorId='+dse_processorId
                headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': 'en-US,en;q=0.9',
                'Cache-Control': 'max-age=0',
                'Connection': 'keep-alive',
                'Referer': 'https://biz.pvcombank.com.vn/Request',
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': 'https://biz.pvcombank.com.vn',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-User': '?1',
                'Upgrade-Insecure-Requests': '1',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0',
                'sec-ch-ua': '"Not/A)Brand";v="8", "Chromium";v="126", "Microsoft Edge";v="126"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"'
                }
                
                response = self.curlPost("https://biz.pvcombank.com.vn/Request",  data=payload,headers=headers,)
                redirect_url = self.process_redirect(response)
                # print('url_change_session',redirect_url)
                response = self.curlGet(redirect_url)
                # print(response)

                self.load_account_url = self.process_change_session(response)
                
                # response = self.curlGet(redirect_url)
                # print(response)
                
            check_error_message = self.check_error_message(response)
            if check_error_message:
                check_error_message_details = self.check_error_message_details(response)
                if 'Tài khoản không tồn tại' in check_error_message:
                        return {
                            'code': 404,
                            'success': False,
                            'message': check_error_message,
                            'details': check_error_message_details if check_error_message_details else None
                            }
                if 'Cảnh báo đăng nhập' in check_error_message:
                        return {
                            'code': 444,
                            'success': False,
                            'message': 'Tài khoản hoặc mật khẩu không đúng',
                            'details': check_error_message_details if check_error_message_details else None
                            }
                if 'Mã Tiếp tục không hợp lệ' in check_error_message:
                        return {
                            'code': 422,
                            'success': False,
                            'message': check_error_message,
                            'details': check_error_message_details if check_error_message_details else None
                            }
                if 'Tài khoản của quý khách đã bị khóa' in check_error_message:
                        return {
                            'code': 449,
                            'success': False,
                            'message': 'Blocked account!',
                            'details': check_error_message_details if check_error_message_details else None
                            }
                return {
                    'code': 400,
                    'success': False,
                    'message': check_error_message,
                    'details': check_error_message_details
                }
            else:
                if 'Thông Tin Tài Khoản' in response:

                    # print(response)
                    self.tokenNo = self.extract_tokenNo(response)
                    # if balance_span:
                    #     self.balance = balance_span.get_text(strip=True).replace
                    self.is_login = True
                    return {
                        'code': 200,
                        'success': True,
                        'message': 'Đăng nhập thành công',
                        # 'data':{
                        #     'tokenNo': self.tokenNo
                        # }    
                    }
                else:
                    return {
                    'code': 520,
                    'success': False,
                    'message': "Unknown Error!"
                    }
        else:
            return {
                    'code': 520,
                    'success': False,
                    'message': "Unknown Error!"
            }

    def saveData(self):
        data = {
            'username': self.username,
            'password': self.password,
            'account_number': self.account_number,
            'sessionId': self.sessionId,
            'mobileId': self.mobileId,
            'clientId': self.clientId,
            'cif': self.cif,
            'E': self.E,
            'res': self.res,
            'tranId': self.tranId,
            'browserToken': self.browserToken,
            'browserId': self.browserId,
        }
        with open(f"data/{self.username}.txt", "w") as file:
            json.dump(data, file)

    def parseData(self):
        with open(f"data/{self.username}.txt", "r") as file:
            data = json.load(file)
            self.username = data["username"]
            self.password = data["password"]
            self.account_number = data.get("account_number", "")
            self.sessionId = data.get("sessionId", "")
            self.mobileId = data.get("mobileId", "")
            self.clientId = data.get("clientId", "")
            self.token = data.get("token", "")
            self.accessToken = data.get("accessToken", "")
            self.authToken = data.get("authToken", "")
            self.cif = data.get("cif", "")
            self.res = data.get("res", "")
            self.tranId = data.get("tranId", "")
            self.browserToken = data.get("browserToken", "")
            self.browserId = data.get("browserId", "")
            self.E = data.get("E", "")

    def getE(self):
        ahash = hashlib.md5(self.username.encode()).hexdigest()
        imei = '-'.join([ahash[i:i+4] for i in range(0, len(ahash), 4)])
        return imei.upper()

    def getCaptcha(self):
        captchaToken = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
        url = self.url['getCaptcha'] + captchaToken
        response = requests.get(url)
        result = base64.b64encode(response.content).decode('utf-8')
        return result

    def getlistAccount(self):
        if not self.is_login:
            login = self.doLogin()
            if not login['success']:
                return login
        param = {}
        url = "https://biz.pvcombank.com.vn/Request?&dse_sessionId="+self.dse_sessionId+"&dse_applicationId=-1&dse_pageId="+str(self.dse_pageId)+"&dse_operationName=corpUserLoginProc&dse_processorState=initial&dse_nextEventName=loadAccounts"
        # url = self.load_account_url
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
            'Accept': '*/*',
            'Accept-Language': 'vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'X-Requested-With': 'XMLHttpRequest',
            'Origin': 'https://biz.pvcombank.com.vn',
            'Connection': 'keep-alive',
            'Referer': self.referer_url,
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Content-Length': '0'
            }
        response = self.curlPost(url, headers=headers, data=param)
        # print(response)
        if 'Số dư hiện tại' in response:
            account_number = self.extract_account_number(response)
            balance = self.extract_balance(response)
            
            if account_number and balance:
                balance = balance.replace('.','')
                balance = int(balance)
                if (balance) > 1000000:
                    available_balance = balance - 1000000
                    self.available_balance = available_balance
                if self.account_number == account_number:
                    if int(balance) < 0 :
                        return {'code':448,'success': False, 'message': 'Blocked account with negative balances!',
                                'data': {
                                    'balance':int(balance),
                                    'available_balance':int(available_balance)
                                }
                                }
                    else:
                        return {'code':200,'success': True, 'message': 'Thành công',
                                'data':{
                                    'account_number':self.account_number,
                                    'balance':int(balance),
                                    'available_balance':int(available_balance)
                        }}
                return {'code':404,'success': False, 'message': 'account_number not found!'} 
            return {'code':520 ,'success': False, 'message': 'Unknown Error!'} 
        else: 
            return {'code':520 ,'success': False, 'message': 'Unknown Error!'} 
        
    def getinfoAccount(self):
        param = "_selectedAccType="
        url = "https://biz.pvcombank.com.vn/Request?&dse_sessionId="+self.dse_sessionId+"&dse_applicationId=-1&dse_pageId="+str(self.dse_pageId)+"&dse_operationName=corpQueryTransactionInfomationProc&dse_processorState=firstAndResultPage&dse_processorId="+self.dse_processorId+"&dse_nextEventName=getAccountList"
        
        headers = {
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
  'Accept': '*/*',
  'Accept-Language': 'vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3',
  'Accept-Encoding': 'gzip, deflate, br, zstd',
  'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
  'X-Requested-With': 'XMLHttpRequest',
  'Origin': 'https://biz.pvcombank.com.vn',
  'Connection': 'keep-alive',
  'Referer': 'https://biz.pvcombank.com.vn/Request',
  'Sec-Fetch-Dest': 'empty',
  'Sec-Fetch-Mode': 'cors',
  'Sec-Fetch-Site': 'same-origin'
}
        response = self.curlPost(url,param,headers)
        return (response)

    def getinfoAccountCA(self):
        if not self.is_login:
            login = self.doLogin()
            if not login['success']:
                return login
        param = "_selectedAccType=CA"
        url = "https://biz.pvcombank.com.vn/Request?&dse_sessionId="+self.dse_sessionId+"&dse_applicationId=-1&dse_pageId="+str(self.dse_pageId)+"&dse_operationName=corpQueryTransactionInfomationProc&dse_processorState=firstAndResultPage&dse_processorId="+self.dse_processorId+"&dse_nextEventName=getAccountList"
        
        headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Accept': '*/*',
        'Accept-Language': 'vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://biz.pvcombank.com.vn',
        'Connection': 'keep-alive',
        'Referer': 'https://biz.pvcombank.com.vn/Request',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'Priority': 'u=0'
        }
        response = self.curlPost(url,param,headers)
        return (response)
    
    def get_transactions_by_page(self,url,page,limit):
        response = self.curlGet(url)
        transaction_history = self.extract_transaction_history(response)

        if page*10 < limit:
            if transaction_history:
                self.transactions += transaction_history
            page=page+1
            
            page_url = self.extract_page_url(response,page)
            if page_url:
                return self.get_transactions_by_page(page_url,page,limit)
        else:
            if transaction_history:
                self.transactions += transaction_history[:limit - (page-1)*10]
        return True

    def getHistories(self, fromDate="16/06/2023", toDate="16/06/2023", account_number='',limit = 100):
        self.transactions = []
        if not self.is_login:
            login = self.doLogin()
            if not login['success']:
                return login
        param = {}
        url = "https://biz.pvcombank.com.vn/Request?&dse_sessionId="+self.dse_sessionId+"&dse_applicationId=-1&dse_pageId="+str(self.dse_pageId)+"&dse_operationName=corpQueryTransactionInfomationProc&dse_processorState=initial&dse_nextEventName=start"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
            'Accept': '*/*',
            'Accept-Language': 'vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'X-Requested-With': 'XMLHttpRequest',
            'Origin': 'https://biz.pvcombank.com.vn',
            'Connection': 'keep-alive',
            'Referer': self.referer_url,
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Content-Length': '0'
            }
        response = self.curlGet(url)
        # print(response)
        self.dse_processorId = self.extract_dse_processorId(response)
        param = "dse_sessionId="+self.dse_sessionId+"&dse_applicationId=-1&dse_operationName=corpQueryTransactionInfomationProc&dse_pageId="+str(self.dse_pageId)+"&dse_processorState=autoSubmitOp&dse_processorId="+self.dse_processorId+"&dse_errorPage=%2Fauto_loading.jsp&dse_nextEventName=onLoading"
        url = "https://biz.pvcombank.com.vn/Request"
        
        response = self.curlPost(url,param)
        self.dse_processorId = self.extract_dse_processorId(response)

        # print(response)
        response = self.getinfoAccount()
        
        # response = self.getinfoAccountCA()
        
        # print(response)
        
        if not self.account_cif:
            self.account_cif = self.extract_account_cif(response)
            # print('account_cif',self.account_cif)


        payload = {}
        url = "https://biz.pvcombank.com.vn/Request?&dse_sessionId="+self.dse_sessionId+"&dse_applicationId=-1&dse_pageId="+str(self.dse_pageId)+"&dse_operationName=getBalanceAmountProc&dse_processorState=initial&dse_nextEventName=getBalanceAmount&_selectedAccount="+self.account_number+"&_selectedAccType=CA&cifQuery="+str(self.account_cif.split('||')[1])
        
        headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Accept': '*/*',
        'Accept-Language': 'vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'X-Requested-With': 'XMLHttpRequest',
        'Origin': 'https://biz.pvcombank.com.vn',
        'Connection': 'keep-alive',
        'Referer': 'https://biz.pvcombank.com.vn/Request',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'Priority': 'u=0',
        'Content-Length': '0'
        }
        response = self.curlPost(url,param,headers)
        
        # print(response)

        payload_dict = {
            'dse_sessionId': self.dse_sessionId,
            'dse_applicationId': '-1',
            'dse_operationName': 'corpQueryTransactionInfomationProc',
            'dse_pageId': str(self.dse_pageId),
            'dse_processorState': 'firstAndResultPage',
            'dse_processorId': self.dse_processorId,
            'dse_errorPage': 'error_page.jsp',
            'dse_nextEventName': 'query',
            'vErrorPage': '/accountmanagement/query_transaction_information.jsp',
            'research': 'no',
            'isFee': 'N',
            'tabClick': '',
            '_selectedAccount': self.account_number,
            '_selectedAccType': '',
            '_selectedAccountBalance': str(self.available_balance),
            '_selectedAccountStatus': 'ok',
            '_selectedAccTypeName': 'VND',
            'loadAccType': 'CA',
            'isQuery': 'true',
            'accTypeSubAcc': '',
            '_alert': '',
            '_event': 'onLoading',
            'accountType': '',
            'account': self.account_cif,
            '_subAcc': '',
            'beginDate': fromDate,
            '_endDate': toDate
        }
        # print(payload_dict)
        payload = urllib.parse.urlencode(payload_dict)
        # print(payload)

        url = "https://biz.pvcombank.com.vn/Request"
        # url = self.load_account_url
        headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8',
        'Accept-Language': 'vi-VN,vi;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate, br, zstd',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://biz.pvcombank.com.vn',
        'Connection': 'keep-alive',
        'Referer': 'https://biz.pvcombank.com.vn/Request',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'iframe',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Priority': 'u=4'
        }
        response = self.curlPost(url, headers=headers, data=payload)
        # print(response)
        # with open("111.html", "w", encoding="utf-8") as file:
        #     file.write(response)
        total_transaction = self.get_total_transaction(response)
        if total_transaction > 0:
            self.transactions = self.extract_transaction_history(response)
            if total_transaction > 10:
                page_url = self.extract_page_url(response,2)
                # print(page_url)
                if page_url:
                    self.get_transactions_by_page(page_url,2,limit)
            return {'code':200,'success': True, 'message': 'Thành công',
                    'data':{
                        'transactions':self.transactions,
            }}
        else:
            return {'code':200,'success': True, 'message': 'Thành công',
                    'data':{
                        'message': 'No data',
                        'transactions':[],
            }}

        if 'status' in result and 'code' in result['status'] and result['status']['code'] == "1":
            return {'code':200,'success': True, 'message': 'Thành công',
                            'data':{
                                'transactions':result['transactions'],
                    }}
        else:
            return  {
                    "success": False,
                    "code": 503,
                    "message": "Service Unavailable!"
                }

