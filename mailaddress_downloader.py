import requests
import urllib
import json
from cryptography.fernet import Fernet
import base64
import re
import time
from Crypto.Cipher import AES
import os
from glob import glob
from dataclasses import dataclass
import dask.dataframe as dd
import multiprocessing
import pandas as pd
from pathlib import Path
import csv
import sys

@dataclass 
class SecretInfo:
   cide_api_key: str
   cide_client_id: str
   cide_client_secret: str
   cidx_api_key: str
   cidx_client_id: str
   cidx_client_secret: str 
   mail_decode_key: str

@dataclass 
class ExecuteInfo:
   cide_url: str
   cidx_url: str
   status_regexp: str
   limit_row : int

# エラーハンドリングのため作成したクラス
class ReadFileError(Exception):
    def __init__(self, msg, status):
        self.msg = msg
        self.status = status
class DecodingError(Exception):
    def __init__(self, msg, status):
        self.msg = msg
        self.status = status
class RequestError(Exception):
    def __init__(self, msg, status):
        self.msg = msg
        self.status = status

class GenerateCsvError(Exception):
    def __init__(self, msg, status):
        self.msg = msg
        self.status = status

def load_secret_file(key_file_path,secret_file_path):  
    #秘密情報をjsonファイルで受け取る
    try:
        with open(key_file_path, 'rb') as f:
            key = f.read()
        with open(secret_file_path, 'r') as f:
            data = f.read()
    except :
        raise ReadFileError(
            f"秘密情報のファイルの読み込みに失敗しました。各ファイルのパスが正しいか確認してください。 \n・decodeキーファイルパス:{key_file_path} \n・秘密情報ファイルパス:{secret_file_path}", 
            400
        )
    
    return key ,data    

def load_execute_data(execute_info_path):
    # 必要情報の読み込み
    try:
        with open(execute_info_path, 'r') as f:
            data = json.load(f)
    except :
        raise ReadFileError(
            f"実行情報のファイルの読み込みに失敗しました。各ファイルのパスが正しいか確認してください。 \n・実行情報ファイルパス:{execute_info_path}",
            400
        )

    return ExecuteInfo(
        cide_url = data["cide_url"],    
        cidx_url = data["cidx_url"],   
        status_regexp = data["status_regexp"],
        limit_row = data["limit_row"]    
    )

def decrypt_secret(key,data):
    # 秘密情報の読み込みとdecode
    try:
        fernet = Fernet(key)
        encrypted_data = json.loads(fernet.decrypt(bytes(data,encoding='utf-8')).decode("utf-8"))
    except :
        raise DecodingError("秘密情報のdecodeに失敗しました",400)
    
    return SecretInfo( 
        cide_api_key = encrypted_data["cide_api_key"],
        cide_client_id = encrypted_data["cide_client_id"],
        cide_client_secret = encrypted_data["cide_client_secret"],
        cidx_api_key = encrypted_data["cidx_api_key"],
        cidx_client_id = encrypted_data["cidx_client_id"],
        cidx_client_secret = encrypted_data["cidx_client_secret"],
        mail_decode_key =  encrypted_data["mail_decode_key"]
    )

def request_user_information(execute_info,secret_info):
    #APIをたたき経過確認ファイルのurlを取得
    url = execute_info.cide_url
    headers = {"x-api-key": secret_info.cide_api_key,
               "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
    params = { "client_id" :secret_info.cide_client_id,
            "client_secret" :secret_info.cide_client_secret,
           "format" : "gz"           
    }
    response = requests.post(url,headers = headers,data = urllib.parse.urlencode(params))
    response_json = response.json()
    status_code = response.status_code
    if status_code != 200:
        raise RequestError(f"メール抽出APIのリクエストでエラーが発生しました。\n・リクエストエラーメッセージ{response_json['message']}", status_code)

    status_url = response_json["progress"]

    return status_url 

def download_cdx_user_data(execute_info,secret_info,url_list,gz_file_path):
    #urlを指定してuser_data_fileダウンロード
    url = execute_info.cidx_url
    headers = {"x-api-key": secret_info.cidx_api_key}
    url_list=url_list
    for file_num,file_url in enumerate(url_list):
        params = {
                    "client_id" : secret_info.cidx_client_id,
                    "client_secret" : secret_info.cidx_client_secret,
                    "file_url": file_url,
                    "offset" : "0"
                }
        res_data = []
        while True:
            try:
                response = requests.post(url = url, headers = headers, data = json.dumps(params))
            except :
                raise RequestError("ダウンロードAPIのリクエストでエラーが発生しました",400)
            response_file = response.json()
            res_data.append(response_file["data"])
            params["offset"] = response_file["offset"]["next"]
            if response_file["offset"]["next"] == "-":
                break

        with open(f'{gz_file_path}/cdx_user_data{file_num}.gz', 'wb') as zf:
            for data in res_data:
                res_data_decode = base64.b64decode(data)
                zf.write(res_data_decode)       

def check_download_progress(execute_info,secret_info,status_url):
    headers = {"x-api-key": secret_info.cide_api_key,
               "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
               }
    response_status = requests.get(status_url,headers=headers).text
    if re.search(r'complete',string=response_status):
        url_list = re.findall(execute_info.status_regexp,response_status)

    if re.search(pattern = r'progress',string=response_status):
        #30秒の待機後再リクエスト、待機時間は仮
        time.sleep(30)
        check_download_progress(execute_info,secret_info,status_url)    

    if re.search(pattern = r'error',string=response_status):
        error_message = re.findall(pattern=r"description: (.+)\n", string=response_status)[0]
        #ファイルのdescriptionのエラーメッセージを出力し、処理を終了する 
        raise RequestError(f"ファイル作成時にエラーが発生しました。\n・リクエストエラーメッセージ{error_message}", 400)

    return url_list

def username_decode(secret_info,username):
    #メールアドレスdeocde
    crypted_object= json.loads(base64.b64decode(username).decode())
    key = base64.b64decode(secret_info.mail_decode_key)
    nonce = base64.b64decode(crypted_object["nonce"])
    ciphertext = base64.b64decode(crypted_object["ciphertext"])
    tag = base64.b64decode(crypted_object["tag"])
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        decode_username = cipher.decrypt_and_verify(ciphertext, tag)
    except:
        raise DecodingError(f"メールアドレスのデコードに失敗しました",400)

    return decode_username

def generate_csv(secret_info,limit_row,gz_files,csv_file_path):
    #gzipファイルをcsvに変換、limit_rowにより読み込む行数を制御しメモリ負担を減らす
    for file_num, file in enumerate(gz_files):
        tmp_user_info_df = dd.read_json(file, orient=str)
        
        if len(tmp_user_info_df) == 0:
            continue

        #limit_rowの倍数だとfor文が1反復多く回り、0レコードのcsvが作られてしまうため場合分け        
        loop_count = len(tmp_user_info_df) // limit_row
        if len(tmp_user_info_df) % limit_row > 0:
            loop_count += 1

        for loop_num in range(loop_count): 
            start_row = loop_num * limit_row    
            end_row = (loop_num + 1) * limit_row - 1
            user_info_df = tmp_user_info_df.loc[start_row:end_row].compute(num_workers=multiprocessing.cpu_count())
            decode_username_df = transform_df(secret_info,user_info_df)   
            try:
                decode_username_df.to_csv(f"{csv_file_path}\{file_num}_{loop_num}.csv", index=False)
            except :
                raise GenerateCsvError(f"csvファイルの作成でエラーが発生しました{file_num}",400)
            
            # 一度にすべてのデータを読み込みので、意図とずれてると思う   →1つずつ取りだし、追記していく方法に変える
            with open('output.csv','a',newline='', encoding='utf8') as f:
                f.write(decode_username_df.to_csv(index=False,header = None))
            del decode_username_df

        del tmp_user_info_df
        
def transform_df(secret_info,df):
    #必要カラムを取り出しdataframeを成形、usernameカラムをデコード
    try:
        df["userName"] = df["userName"].apply(lambda x: username_decode(secret_info,x).decode("utf-8"))
    except:
        raise  DecodingError("メールアドレスのデコードに失敗しました",400)
    
    if  "optoutDeny" not in df.columns:
        df["optoutDeny"] = ""

    df = df[["id","userName","ppids","optoutDeny","created","deleted"]]

    return df 

if __name__ == '__main__':
    # 実行環境の定義
    env = sys.argv[1]
    # 必要なpathを定義
    current_dir = os.getcwd()
    gz_file_path = os.path.join(os.path.dirname(current_dir),"all_gzip_files") 
    csv_file_path =  os.path.join(os.path.dirname(current_dir),"all_csv_files")
    decode_key_path = os.path.join(current_dir.parent.parent,f"decode_{env}.key")
    secret_info_path = os.path.join(current_dir.parent.parent,f"enc_secret_file_{env}.text")
    execute_info_path = os.path.join(current_dir.parent.parent,f"execute_{env}.txt")

    #秘密情報ファイルのロード処理 
    try:
        decode_key,data = load_secret_file(decode_key_path,secret_info_path)
    except ReadFileError as e:
        print(f"エラーメッセージ：{e.msg}")
        print(f"エラーステータスコード：{e.status}")
        raise e
 
    # APIキー等のdecode処理
    try:
        secret_info = decrypt_secret(decode_key,data)
    except DecodingError as e:
        print(f"エラーメッセージ：{e.msg}")
        print(f"エラーステータスコード：{e.status}")
        raise e

    # 実行情報のロード処理    
    try:
        execute_info = load_execute_data(execute_info_path)
    except ReadFileError as e:
        print(f"エラーメッセージ：{e.msg}")
        print(f"エラーステータスコード：{e.status}")
        raise e

    # 情報取得APIにリクエストを投げ、作成されたファイルのurlを取得する
    try:
        status_url = request_user_information(execute_info,secret_info)
        url_list = check_download_progress(execute_info,secret_info,status_url)
    except RequestError as e:
        print(f"エラーメッセージ：{e.msg}")
        print(f"エラーステータスコード：{e.status}")
        raise e

    # ダウンロードAPIにリクエストを投げる
    try:
        download_cdx_user_data(execute_info,secret_info,url_list,gz_file_path)
    except RequestError as e:
        print(f"エラーメッセージ：{e.msg}")
        print(f"エラーステータスコード：{e.status}")
        raise e 
    
    gz_files = glob(os.path.join(gz_file_path,'*.gz'))
    limit_row = execute_info.limit_row
    
    # データを追記していく用にheaderのみのcsvファイルを作成
    with open('output.csv','w',newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["id","userName","ppids","optoutDeny","created","deleted"])

    #  zipファイルを展開、必要なカラムを取り出しcsvファイルとして保存する、アドレスのデコードもここで行う
    try:
        generate_csv(secret_info,limit_row,gz_files,csv_file_path)
    except DecodingError as e:
        print(f"エラーメッセージ：{e.msg}")
        print(f"エラーステータスコード：{e.status}")  
        raise e    
    except GenerateCsvError as e:
        print(f"エラーメッセージ：{e.msg}")
        print(f"エラーステータスコード：{e.status}")
        raise e       
    